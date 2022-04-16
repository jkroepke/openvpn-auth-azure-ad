import json
import logging
import time
from typing import Dict, Optional

from cacheout import CacheManager
from msal import PublicClientApplication
from prometheus_client import Counter

from . import util
from ._version import __version__
from .openvpn import OpenVPNManagementInterface
from .util import errors
from .util.thread_pool import ThreadPoolExecutorStackTraced

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


def format_log_prefix(client: dict) -> str:
    prefix = "cid: %s" % (client["cid"],)
    if "common_name" in client["env"]:
        prefix += " | %s" % client["env"]["common_name"]

    if "state_id" in client and client["state_id"] is not None:
        prefix += " | %s" % client["state_id"]

    return prefix


def log_debug(client: dict, message: str) -> None:
    prefix = format_log_prefix(client)

    logger.debug("[%s]: %s" % (prefix, message))


def log_info(client: dict, message: str) -> None:
    prefix = format_log_prefix(client)

    logger.info("[%s]: %s" % (prefix, message))


def log_warn(client: dict, message: str) -> None:
    prefix = format_log_prefix(client)

    logger.warning("[%s]: %s" % (prefix, message))


class AADAuthenticator(object):
    token_scopes = ["User.ReadBasic.All"]

    def __init__(
        self,
        app: PublicClientApplication,
        graph_endpoint: str,
        authenticators: str,
        verify_openvpn_client: bool,
        verify_openvpn_client_id_token_claim: bool,
        auth_token: bool,
        auth_token_lifetime: int,
        remember_user: bool,
        threads: int,
        host: str = None,
        port: int = None,
        socket: str = None,
        password: str = None,
        release_hold: bool = None,
    ):
        self._app = app
        self._graph_endpoint = graph_endpoint
        self._authenticators = [s.strip() for s in authenticators.split(",")]
        self._openvpn = OpenVPNManagementInterface(
            release_hold, host, port, socket, password
        )
        self._openvpn.connect()
        self._states = CacheManager(
            {
                "challenge": {"maxsize": 256, "ttl": 600},
                "authenticated": {"maxsize": 256, "ttl": 0},
                "auth_token": {"maxsize": 256, "ttl": 86400},
            }
        )

        self._verify_openvpn_client = verify_openvpn_client
        self._verify_openvpn_client_id_token_claim = (
            verify_openvpn_client_id_token_claim
        )
        self._auth_token_enabled = auth_token
        self._auth_token_lifetime = auth_token_lifetime
        self._remember_user_enabled = remember_user
        self._thread_pool = ThreadPoolExecutorStackTraced(max_workers=threads)

    def run(self) -> None:
        logger.info("Running openvpn-auth-azure-ad %s" % __version__)
        try:
            while True:
                message = self._openvpn.receive()
                if not message:
                    logger.error("Connection to OpenVPN closed. Reconnecting...")
                    self._openvpn.disconnect(False)
                    self._openvpn.connect(True)
                    continue

                if message.startswith("ERROR:"):
                    logger.error(message)
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
        log_info(client, "authentication succeeded")
        if self._auth_token_enabled:
            self._openvpn.send_command(
                "\n".join(("client-auth %s %s", 'push "auth-token %s"', "END"))
                % (client["cid"], client["kid"], client["auth_token"])
            )
        else:
            self._openvpn.send_command(
                "client-auth-nt %s %s" % (client["cid"], client["kid"])
            )

    def send_authentication_challenge(self, client: Dict, client_message: str) -> None:
        log_debug(client, "authentication challenge: %s" % client_message)

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

    def send_authentication_pending(self, client: dict, timeout: int) -> None:
        self._openvpn.send_command(
            "client-pending-auth %s %s %d" % (client["cid"], client["kid"], timeout)
        )

    def setup_auth_token(self, client) -> None:
        if self._auth_token_enabled:
            client["auth_token"] = util.generated_id()
            self._states["auth_token"].set(
                client["auth_token"], client["state_id"], self._auth_token_lifetime
            )

    def verify_client_certificate(self, client, result) -> bool:
        if not self._verify_openvpn_client:
            return True

        if "common_name" not in client["env"]:
            log_warn(client, "Missing common_name in client env")
            return False

        if "id_token_claims" not in result:
            log_warn(client, "Could not get id_token_claims")
            return False

        if self._verify_openvpn_client_id_token_claim not in result["id_token_claims"]:
            log_warn(
                client,
                "claim %s does not exist in id_token"
                % (self._verify_openvpn_client_id_token_claim,),
            )
            return False

        verify_result = (
            client["env"]["common_name"]
            == result["id_token_claims"][self._verify_openvpn_client_id_token_claim]
        )

        if not verify_result:
            log_info(
                client,
                (
                    "client certificate common name does not match Azure AD user (claim: %s). "
                    + "Client certificate: '%s' - Azure AD: '%s'"
                )
                % (
                    self._verify_openvpn_client_id_token_claim,
                    client["env"]["common_name"],
                    result["id_token_claims"][
                        self._verify_openvpn_client_id_token_claim
                    ],
                ),
            )

        return verify_result

    def handle_reauth(self, client: Dict) -> Optional[dict]:
        if not self._auth_token_enabled:
            return None

        openvpn_auth_azure_ad_auth_total.labels(AADAuthenticatorFlows.AUTH_TOKEN).inc()

        # Get Auth-Token from Request
        client["auth_token"] = util.get_auth_token(client)
        if client["auth_token"] is None:
            return None

        # Receive state_id by auth-token
        client["state_id"] = self._states["auth_token"].get(client["auth_token"])
        if client["state_id"] is None:
            return None

        # Get authenticated state
        authenticated_state = self._states["authenticated"].get(client["state_id"])
        if authenticated_state is None:
            return None

        # check is authenticated state has required objects
        if "result" not in authenticated_state or "client" not in authenticated_state:
            return None

        log_info(client, "Authenticate using auth-token flow")

        # recheck if connected client is the same as inside the state.
        if (
            client["auth_token"] != authenticated_state["client"]["auth_token"]
            or client["env"]["common_name"]
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

        client["state_id"] = state_id

        # delete used challenge state
        self._states["challenge"].delete(state_id)

        # Check if required properties exist in state
        if "flow" not in state:
            return None

        log_info(client, "Continue to authenticate using device token flow")
        result = self.device_token_finish(state)

        return result

    def client_connect(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        log_info(client, "Received client connect")
        openvpn_auth_azure_ad_events.labels("connect").inc()
        self.authenticate_client(client)

    @staticmethod
    def client_disconnect(data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        log_info(client, "Received client disconnect event")
        openvpn_auth_azure_ad_events.labels("disconnect").inc()

    def client_reauth(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        log_info(client, "Received client re auth event")
        openvpn_auth_azure_ad_events.labels("reauth").inc()
        self.authenticate_client(client)

    def authenticate_client(self, client: dict) -> None:
        result = {}
        if client["reason"] == "reauth":
            # allow clients to bypass azure ad authentication by reauthenticate via auth-token
            result = self.handle_reauth(client)
            if result is not None:
                if util.is_authenticated(result):
                    if not self.verify_client_certificate(client, result):
                        self.send_authentication_error(
                            client, "client_certificate_not_matched", None
                        )
                        return None

                    openvpn_auth_azure_ad_auth_succeeded.labels(
                        AADAuthenticatorFlows.AUTH_TOKEN
                    ).inc()
                    log_info(client, "auth-token flow succeeded")
                    self.send_authentication_success(client)
                    return

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            result = self.handle_response_challenge(client)
            if result is not None:
                client["state_id"] = util.get_state_id(client)
                if util.is_authenticated(result):
                    if not self.verify_client_certificate(client, result):
                        self.send_authentication_error(
                            client, "client_certificate_not_matched", None
                        )
                        return None

                    self.setup_auth_token(client)
                    self._states["authenticated"].set(
                        client["state_id"], {"client": client, "result": result}
                    )
                    openvpn_auth_azure_ad_auth_succeeded.labels(
                        AADAuthenticatorFlows.DEVICE_TOKEN
                    ).inc()
                    log_info(client, "device token flow succeeded")
                    self.send_authentication_success(client)
                    return
                else:
                    openvpn_auth_azure_ad_auth_failures.labels(
                        AADAuthenticatorFlows.DEVICE_TOKEN
                    ).inc()

                    if 70016 in result.get("error_codes", []):
                        error = "device token flow errored: no user action"
                        log_info(client, error)
                        self.send_authentication_error(client, error, None)
                    else:
                        log_info(
                            client,
                            "device token flow errored: %s "
                            % util.format_error(result),
                        )
                        self.send_authentication_error(
                            client, util.format_error(result), None
                        )
                    return

        client["state_id"] = util.generated_id()
        if self._remember_user_enabled:
            accounts = self._app.get_accounts()
            if "common_name" not in client["env"] and accounts:
                result = self._app.acquire_token_silent(
                    self.token_scopes, account=client["env"]["common_name"]
                )

            if util.is_authenticated(result):
                self.setup_auth_token(client)
                self._states["authenticated"].set(
                    client["state_id"], {"client": client, "result": result}
                )
                self.send_authentication_success(client)
                return

        if AADAuthenticatorFlows.USER_PASSWORD in self._authenticators:
            log_debug(client, "Authenticate using username/password flow")
            openvpn_auth_azure_ad_auth_total.labels(
                AADAuthenticatorFlows.USER_PASSWORD
            ).inc()
            result = self._app.acquire_token_by_username_password(
                client["env"]["username"],
                client["env"]["password"],
                scopes=self.token_scopes,
            )

            if util.is_authenticated(result):
                if not self.verify_client_certificate(client, result):
                    self.send_authentication_error(
                        client, "client_certificate_not_matched", None
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
                        % self._app.initiate_auth_code_flow(self.token_scopes)[
                            "auth_uri"
                        ]
                    )
                    self.send_authentication_error(client, "consent_needed", error)
                else:
                    error = util.format_error(result)
                    self.send_authentication_error(client, error, None)

                log_info(client, "password flow errored: %s" % (error,))
                return

            openvpn_auth_azure_ad_auth_succeeded.labels(
                AADAuthenticatorFlows.USER_PASSWORD
            ).inc()
            log_info(client, "password flow succeeded")
            # Do not send successful auth command, because device token can be enabled.

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            log_info(client, "Start to authenticate using device token flow")
            flow = self.device_auth_start()
            message = flow["message"] + " Then press OK here."

            self._states["challenge"].set(client["state_id"], {"flow": flow})

            openvpn_auth_azure_ad_auth_total.labels(
                AADAuthenticatorFlows.DEVICE_TOKEN
            ).inc()
            self.send_authentication_challenge(client, message)
            return

        self.setup_auth_token(client)
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
        # Block authentication at least for 120 seconds
        state["flow"]["expires_in"] = 60
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
