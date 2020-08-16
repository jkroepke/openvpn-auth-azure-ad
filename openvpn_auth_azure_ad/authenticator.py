import json
import logging
import time
import uuid
from typing import Dict, Optional

from cacheout import CacheManager
from msal import PublicClientApplication
from prometheus_client import Counter

from openvpn_auth_azure_ad import util
from openvpn_auth_azure_ad._version import __version__
from openvpn_auth_azure_ad.openvpn import OpenVPNManagementInterface
from openvpn_auth_azure_ad.util import errors
from openvpn_auth_azure_ad.util.thread_pool import ThreadPoolExecutorStackTraced

openvpn_auth_azure_ad_events = Counter(
    "openvpn_auth_azure_ad_events", "track events", ["event"]
)
openvpn_auth_azure_ad_auth_total = Counter(
    "openvpn_auth_azure_ad_auth_total", "auth total", ["flow"]
)
openvpn_auth_azure_ad_auth_succeeded = Counter(
    "openvpn_auth_azure_ad_auth_succeeded", "auth succeeded", ["flow"]
)
openvpn_auth_azure_ad_auth_failures = Counter(
    "openvpn_auth_azure_ad_auth_failures", "auth failures", ["flow"]
)

logger = logging.getLogger(__name__)


class AADAuthenticatorFlows:
    USER_PASSWORD = "username_password"
    DEVICE_TOKEN = "device_token"
    AUTH_TOKEN = "auth_token"


class AADAuthenticator(object):
    token_scopes = ["User.ReadBasic.All"]

    def __init__(
        self,
        app: PublicClientApplication,
        graph_endpoint: str,
        authenticators: str,
        verify_common_name: bool,
        auth_token: bool,
        threads: int,
        host: str = None,
        port: int = None,
        socket: str = None,
        password: str = None,
    ):
        self._app = app
        self._graph_endpoint = graph_endpoint
        self._authenticators = [s.strip() for s in authenticators.split(",")]
        self._openvpn = OpenVPNManagementInterface(host, port, socket, password)
        self._openvpn.connect()
        self._states = CacheManager(
            {
                "challenge": {"maxsize": 256, "ttl": 600},
                "authenticated": {"maxsize": 256, "ttl": 0},
                "auth_token": {"maxsize": 256, "ttl": 86400},
            }
        )

        self._verify_common_name_enabled = verify_common_name
        self._auth_token_enabled = auth_token
        self._thread_pool = ThreadPoolExecutorStackTraced(max_workers=threads)

    def run(self) -> None:
        logger.info("Running openvpn-auth-azure-ad %s" % __version__)
        try:
            while True:
                message = self._openvpn.receive()
                if not message:
                    logger.error("Connection to OpenVPN closed.")
                    break

                if message.startswith(">INFO"):
                    continue

                if message.startswith(">CLIENT:DISCONNECT"):
                    self._thread_pool.submit(self.client_disconnect, message)

                elif message.startswith(">CLIENT:CONNECT"):
                    self._thread_pool.submit(self.client_connect, message)

                elif message.startswith(">CLIENT:REAUTH"):
                    self._thread_pool.submit(self.client_reauth, message)

                self._states["challenge"].delete_expired()
                self._states["auth_token"].delete_expired()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.error(str(e), exc_info=e)

    def send_authentication_success(self, client: dict) -> None:
        self.log_info(client, "authentication succeeded")
        if self._auth_token_enabled:
            auth_token = str(uuid.uuid1())
            self._states["auth_token"].set(auth_token, client["state_id"])
            self._openvpn.send_command(
                'client-auth %s %s\npush "auth-token %s"\nEND'
                % (client["cid"], client["kid"], auth_token)
            )
        else:
            self._openvpn.send_command(
                "client-auth-nt %s %s" % (client["cid"], client["kid"])
            )

    def send_authentication_challenge(self, client: Dict, client_message: str) -> None:
        self.log_debug(client, "authentication challenge: %s" % client_message)

        client_challenge = util.format_client_challenge(client, client_message)
        self._openvpn.send_command(
            'client-deny %s %s "%s" "%s"'
            % (client["cid"], client["kid"], "client_challenge", client_challenge)
        )

    def send_authentication_error(
        self, client: dict, message: str, client_message: Optional[str]
    ) -> None:
        if client_message is None:
            self._openvpn.send_command(
                'client-deny %s %s "%s"' % (client["cid"], client["kid"], message)
            )
        else:
            client_challenge = util.format_client_challenge(client, client_message)
            self._openvpn.send_command(
                'client-deny %s %s "%s" "%s"'
                % (client["cid"], client["kid"], message, client_challenge)
            )

    def verify_common_name(self, client, result) -> bool:
        if (
            "common_name" not in client["env"]
            or "id_token_claims" not in result
            or "preferred_username" not in result["id_token_claims"]
        ):
            return False

        return (
            client["env"]["common_name"]
            == result["id_token_claims"]["preferred_username"]
        )

    def handle_reauth(self, client: Dict) -> Optional[dict]:
        if not self._auth_token_enabled:
            return None

        openvpn_auth_azure_ad_auth_total.labels(AADAuthenticatorFlows.AUTH_TOKEN).inc()

        # Get Auth-Token from Request
        auth_token = util.get_auth_token(client)
        if auth_token is None:
            return None

        # Receive state_id by auth-token
        state_id = self._states["auth_token"].get(auth_token)
        if state_id is None:
            return None

        # Inject state_id into client
        client["state_id"] = state_id

        # Delete auth-token from auth-token state
        self._states["auth_token"].delete(auth_token)

        # Get authenticated state
        authenticated_state = self._states["authenticated"].get(state_id)
        if authenticated_state is None:
            return None

        # check is authenticated state has required objects
        if "result" not in authenticated_state or "client" not in authenticated_state:
            return None

        self.log_info(client, "Authenticate using auth-token flow")

        # recheck if connected client is the same as inside the state.
        if (
            client["env"]["common_name"]
            != authenticated_state["client"]["env"]["common_name"]
            or client["env"]["username"]
            != authenticated_state["client"]["env"]["username"]
        ):
            return None

        # check if user is active inside azure ad by using a refresh token
        result = self._app.acquire_token_by_refresh_token(
            authenticated_state["result"]["refresh_token"], scopes=self.token_scopes
        )

        return result

    def handle_response_challenge(self, client: Dict) -> Optional[dict]:
        if not client["env"]["password"].startswith("CRV1::"):
            return None

        # get state id from client
        state_id = util.get_state_id(client)
        if state_id is None:
            return None

        # get state from challenge state and check if exists
        state = self._states["challenge"].get(state_id)
        if state is None:
            return None

        # delete used challenge state
        self._states["challenge"].delete(state_id)

        # Check if required properties exist in state
        if "flow" not in state:
            return None

        self.log_info(client, "Continue to authenticate using device token flow")
        result = self.device_token_finish(state)

        return result

    def client_connect(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, "Received client connect")
        openvpn_auth_azure_ad_events.labels("connect").inc()
        self.authenticate_client(client)

    def client_disconnect(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, "Received client disconnect event")
        openvpn_auth_azure_ad_events.labels("disconnect").inc()

    def client_reauth(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, "Received client re auth event")
        openvpn_auth_azure_ad_events.labels("reauth").inc()
        self.authenticate_client(client)

    def authenticate_client(self, client: dict) -> None:
        result = {}

        if client["reason"] == "reauth":
            # allow clients to bypass azure ad authentication by reauthenticate via auth-token
            result = self.handle_reauth(client)
            if result is not None:
                if util.is_authenticated(result):
                    if (
                        self._verify_common_name_enabled
                        and not self.verify_common_name(client, result)
                    ):
                        self.log_info(
                            client, "common_name does not match Azure AD username."
                        )
                        self.send_authentication_error(
                            client, "common_name_not_matched", None
                        )
                        return None

                    openvpn_auth_azure_ad_auth_succeeded.labels(
                        AADAuthenticatorFlows.AUTH_TOKEN
                    ).inc()
                    self.log_info(client, "auth-token flow succeeded")
                    self.send_authentication_success(client)
                    return

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            result = self.handle_response_challenge(client)
            if result is not None:
                client["state_id"] = util.get_state_id(client)
                if util.is_authenticated(result):
                    if (
                        self._verify_common_name_enabled
                        and not self.verify_common_name(client, result)
                    ):
                        self.log_info(
                            client, "common_name does not match Azure AD username."
                        )
                        self.send_authentication_error(
                            client, "common_name_not_matched", None
                        )
                        return None

                    self._states["authenticated"].set(
                        client["state_id"], {"client": client, "result": result}
                    )
                    openvpn_auth_azure_ad_auth_succeeded.labels(
                        AADAuthenticatorFlows.DEVICE_TOKEN
                    ).inc()
                    self.log_info(client, "device token flow succeeded")
                    self.send_authentication_success(client)
                    return
                else:
                    openvpn_auth_azure_ad_auth_failures.labels(
                        AADAuthenticatorFlows.DEVICE_TOKEN
                    ).inc()
                    if 70016 in result.get("error_codes", []):
                        error = "device token flow errored: no user action"
                        self.log_info(client, error)
                        self.send_authentication_error(client, error, None)
                    else:
                        self.log_info(
                            client,
                            "device token flow errored: %s "
                            % util.format_error(result),
                        )
                        self.send_authentication_error(
                            client, util.format_error(result), None
                        )
                    return

        client["state_id"] = str(uuid.uuid1())
        if AADAuthenticatorFlows.USER_PASSWORD in self._authenticators:
            self.log_debug(client, "Authenticate using username/password flow")
            openvpn_auth_azure_ad_auth_total.labels(
                AADAuthenticatorFlows.USER_PASSWORD
            ).inc()
            result = self._app.acquire_token_by_username_password(
                client["env"]["username"],
                client["env"]["password"],
                scopes=self.token_scopes,
            )

            if util.is_authenticated(result):
                if self._verify_common_name_enabled and not self.verify_common_name(
                    client, result
                ):
                    self.log_info(
                        client, "common_name does not match Azure AD username."
                    )
                    self.send_authentication_error(
                        client, "common_name_not_matched", None
                    )
                    return None
            else:
                openvpn_auth_azure_ad_auth_failures.labels(
                    AADAuthenticatorFlows.USER_PASSWORD
                ).inc()
                if 65001 in result.get("error_codes", []):
                    # AAD requires user consent for U/P flow
                    error = (
                        "Get consent first: %s"
                        % self._app.get_authorization_request_url(self.token_scopes)
                    )
                    self.send_authentication_error(client, "consent_needed", error)
                else:
                    error = util.format_error(result)
                    self.send_authentication_error(client, error, None)

                self.log_info(client, "password flow errored: %s" % (error,))
                return

            openvpn_auth_azure_ad_auth_succeeded.labels(
                AADAuthenticatorFlows.USER_PASSWORD
            ).inc()
            self.log_info(client, "password flow succeeded")
            # Do not send successful auth command, because device token can be enabled.

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            self.log_info(client, "Start to authenticate using device token flow")
            flow = self.device_auth_start()
            message = flow["message"] + " Then press OK here. No input required here."

            self.log_debug(client, "Save state as %s" % client["state_id"])
            self._states["challenge"].set(client["state_id"], {"flow": flow})

            openvpn_auth_azure_ad_auth_total.labels(
                AADAuthenticatorFlows.DEVICE_TOKEN
            ).inc()
            self.send_authentication_challenge(client, message)
            return

        self._states["authenticated"].set(
            client["state_id"], {"client": client, "result": result}
        )
        self.send_authentication_success(client)
        return

    def device_auth_start(self) -> dict:
        flow = self._app.initiate_device_flow(scopes=self.token_scopes)

        if "user_code" not in flow:
            raise ValueError(
                "Fail to create device flow. Err: %s" % json.dumps(flow, indent=4)
            )

        return flow

    def device_token_finish(self, state: dict) -> dict:
        # Block authentication at least for 30 seconds
        state["flow"]["expires_in"] = 30
        state["flow"]["expires_at"] = time.time() + state["flow"]["expires_in"]

        return self._app.acquire_token_by_device_flow(state["flow"])

    @staticmethod
    def parse_client_data(data: str) -> dict:
        client = {
            "env": {},
            "reason": None,
            "cid": None,
            "kid": None,
            "state_id": None,
        }

        for line in data.splitlines():
            try:
                if line.startswith(">CLIENT:CONNECT") or line.startswith(
                    ">CLIENT:REAUTH"
                ):
                    client_info = line.split(",")
                    client["reason"] = client_info[0].replace(">CLIENT:", "").lower()
                    client["cid"] = client_info[1]
                    client["kid"] = client_info[2]
                elif line.startswith(">CLIENT:DISCONNECT"):
                    client_info = line.split(",")
                    client["reason"] = client_info[0].replace(">CLIENT:", "").lower()
                    client["cid"] = client_info[1]
                elif line.startswith(">CLIENT:ENV,"):
                    client_env = line.split(",")[1].split("=")
                    client["env"][client_env[0]] = (
                        client_env[1] if len(client_env) == 2 else ""
                    )
                else:
                    raise errors.ParseError("Can't parse line: %s" % (line,))
            except Exception:
                raise errors.ParseError("Can't parse line: %s" % (line,))

        return client

    def log_info(self, client: dict, message: str) -> None:
        prefix = self.format_log_prefix(client)

        logger.info("[%s]: %s" % (prefix, message))

    def log_debug(self, client: dict, message: str) -> None:
        prefix = self.format_log_prefix(client)

        logger.debug("[%s]: %s" % (prefix, message))

    def format_log_prefix(self, client: dict) -> str:
        prefix = "cid: %s" % (client["cid"],)
        if "common_name" in client["env"]:
            prefix += " | %s" % client["env"]["common_name"]

        return prefix
