from typing import Optional, Dict
from openvpn import OpenVPNManagementInterface
from msal import PublicClientApplication
from cacheout import Cache
from util import errors
from prometheus_client import Counter
from version import __version__

import util
import uuid
import logging
import json
import time

openvpn_aad_authenticator_events = Counter('openvpn_aad_authenticator_events', 'track events', ['event'])
openvpn_aad_authenticator_auth_total = Counter('openvpn_aad_authenticator_auth_total', 'auth total', ['flow'])
openvpn_aad_authenticator_auth_succeeded = Counter('openvpn_aad_authenticator_auth_succeeded', 'auth succeeded',
                                                   ['flow'])
openvpn_aad_authenticator_auth_failures = Counter('openvpn_aad_authenticator_auth_failures', 'auth failures', ['flow'])

logger = logging.getLogger(__name__)


class AADAuthenticatorFlows:
    USER_PASSWORD = 'username_password'
    DEVICE_TOKEN = 'device_token'
    AUTH_TOKEN = 'auth_token'


class AADAuthenticator(object):
    token_scopes = ["User.ReadBasic.All"]

    def __init__(self, app: PublicClientApplication, graph_endpoint: str, authenticators: str, auth_token: bool,
                 host: Optional[str] = None, port: Optional[int] = None,
                 socket: Optional[str] = None, password: Optional[str] = None):
        self._app = app
        self._graph_endpoint = graph_endpoint
        self._authenticators = [s.strip() for s in authenticators.split(',')]
        self._openvpn = OpenVPNManagementInterface(host, port, socket, password)
        self._openvpn.connect()
        self._states = Cache(maxsize=256, ttl=600)
        self._auth_token_enabled = auth_token

        if self._auth_token_enabled:
            self._auth_token_state = Cache(maxsize=256, ttl=0)

    def run(self) -> None:
        logger.info('Running openvpn_aad_authenticator %s' % __version__)
        try:
            while True:
                data = self._openvpn.wait_for_data()
                messages = data.split('>CLIENT:ENV,END')

                for message in messages:
                    if message.startswith(">INFO"):
                        continue

                    if message.startswith(">CLIENT:DISCONNECT"):
                        self.client_disconnect(message)

                    if message.startswith(">CLIENT:CONNECT"):
                        self.client_connect(message)

                    if message.startswith(">CLIENT:REAUTH"):
                        self.client_reauth(message)

                self._states.delete_expired()
        except Exception as e:
            logger.error(str(e), exc_info=e)

    def send_authentication_success(self, client: dict, result: dict) -> None:
        self.log_info(client, 'authentication succeeded')
        if self._auth_token_enabled:
            auth_token = str(uuid.uuid1())
            self._auth_token_state.set(auth_token, {'client': client, 'result': result})
            self._openvpn.send_command(
                "client-auth %s %s\npush \"auth-token %s\"\nEND" % (client['cid'], client['kid'], auth_token))
        else:
            self._openvpn.send_command('client-auth-nt %s %s' % (client['cid'], client['kid']))

    def send_authentication_challenge(self, client: Dict, state_id, message: str) -> None:
        self.log_debug(client, 'authentication challenge: %s' % message)
        client_challenge = 'CRV1:E,R:%s:%s:%s' % (state_id, util.b64encode_string(client['env']['username']), message)

        self._openvpn.send_command('client-deny %s %s "%s" "%s"'
                                   % (client['cid'], client['kid'], 'client_challenge', client_challenge))

    def send_authentication_error(self, client: Dict, message: str) -> None:
        self._openvpn.send_command('client-deny %s %s "%s" "%s"'
                                   % (client['cid'], client['kid'], message, message))

    def handle_reauth(self, client: Dict) -> Optional[dict]:
        if not self._auth_token_enabled:
            return None

        openvpn_aad_authenticator_auth_total.labels(AADAuthenticatorFlows.AUTH_TOKEN).inc()

        auth_token = util.get_auth_token(client)
        if auth_token is None:
            return None

        state = self._auth_token_state.get(auth_token)
        if state is None:
            return None

        if 'result' not in state or 'client' not in state:
            return None

        self.log_info(client, 'Authenticate using auth-token flow')

        if client['env']['common_name'] != state['client']['env']['common_name'] \
                or client['env']['username'] != state['client']['env']['username']:
            return None

        result = self._app.acquire_token_by_refresh_token(state['result']['refresh_token'], scopes=self.token_scopes)

        return result

    def handle_response_challenge(self, client: Dict) -> Optional[dict]:
        if not client['env']['password'].startswith("CRV1::"):
            return None

        state_id = util.get_state_id(client)
        if state_id is None:
            return None

        state = self._states.get(state_id)
        self._states.delete(state_id)
        if state is None:
            return None

        if 'flow' not in state:
            return None

        self.log_info(client, 'Continue to authenticate using device token flow')
        result = self.device_token_finish(state)

        return result

    def client_connect(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, 'Received client connect')
        openvpn_aad_authenticator_events.labels('connect').inc()
        self.authenticate_client(client)

    def client_disconnect(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, 'Received client disconnect event')
        openvpn_aad_authenticator_events.labels('disconnect').inc()

    def client_reauth(self, data: str) -> None:
        client = AADAuthenticator.parse_client_data(data)
        self.log_info(client, 'Received client re auth event')
        openvpn_aad_authenticator_events.labels('reauth').inc()
        self.authenticate_client(client)

    def authenticate_client(self, client: dict) -> None:
        result = {}

        if client['reason'] == 'reauth':
            result = self.handle_reauth(client)
            if result is not None:
                if util.is_authenticated(result):
                    openvpn_aad_authenticator_auth_succeeded.labels(AADAuthenticatorFlows.AUTH_TOKEN).inc()
                    self.log_info(client, 'auth-token flow succeeded')
                    self.send_authentication_success(client, result)
                    return

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            result = self.handle_response_challenge(client)
            if result is not None:
                self._states.expired(util.get_state_id(client))

                if util.is_authenticated(result):
                    openvpn_aad_authenticator_auth_succeeded.labels(AADAuthenticatorFlows.DEVICE_TOKEN).inc()
                    self.log_info(client, 'device token flow succeeded')
                    self.send_authentication_success(client, result)
                    return
                else:
                    openvpn_aad_authenticator_auth_failures.labels(AADAuthenticatorFlows.DEVICE_TOKEN).inc()
                    if 70016 in result.get("error_codes", []):
                        error = 'device token flow errored: no user action'
                        self.log_info(client, error)
                        self.send_authentication_error(client, error)
                    else:
                        self.log_info(client, 'device token flow errored: %s ' % util.format_error(result))
                        self.send_authentication_error(client, util.format_error(result))
                    return

        if AADAuthenticatorFlows.USER_PASSWORD in self._authenticators:
            self.log_debug(client, 'Authenticate using username/password flow')
            openvpn_aad_authenticator_auth_total.labels(AADAuthenticatorFlows.USER_PASSWORD).inc()
            result = self._app.acquire_token_by_username_password(client['env']['username'], client['env']['password'],
                                                                  scopes=self.token_scopes)

            if not util.is_authenticated(result):
                openvpn_aad_authenticator_auth_failures.labels(AADAuthenticatorFlows.USER_PASSWORD).inc()
                if 65001 in result.get("error_codes", []):
                    # AAD requires user consent for U/P flow
                    error = "Get consent first:", self._app.get_authorization_request_url(self.token_scopes)
                else:
                    error = util.format_error(result)

                self.log_info(client, 'password flow errored: %s' % (error,))
                self.send_authentication_error(client, error)
                return

            openvpn_aad_authenticator_auth_succeeded.labels(AADAuthenticatorFlows.USER_PASSWORD).inc()
            self.log_info(client, 'password flow succeeded')

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            self.log_info(client, 'Start to authenticate using device token flow')
            state_id = str(uuid.uuid1())
            flow = self.device_auth_start()
            message = flow['message'] + ". Then press OK."

            self.log_debug(client, 'Save state as %s' % state_id)
            self._states.set(state_id, {'client': client, 'flow': flow})

            openvpn_aad_authenticator_auth_total.labels(AADAuthenticatorFlows.DEVICE_TOKEN).inc()
            self.send_authentication_challenge(client, state_id, message)
            return

        self.send_authentication_success(client, result)
        return

    def device_auth_start(self) -> dict:
        flow = self._app.initiate_device_flow(scopes=self.token_scopes)
        flow["expires_in"] = 30
        flow["expires_at"] = time.time() + flow["expires_in"]

        if "user_code" not in flow:
            raise ValueError("Fail to create device flow. Err: %s" % json.dumps(flow, indent=4))

        return flow

    def device_token_finish(self, state: dict) -> dict:
        return self._app.acquire_token_by_device_flow(state['flow'])

    @staticmethod
    def parse_client_data(data: str) -> dict:
        client = {
            'env': {},
            'reason': None,
            'cid': None,
            'kid': None,
        }

        for line in data.splitlines():
            try:
                if line.startswith(">CLIENT:CONNECT") or line.startswith(">CLIENT:REAUTH"):
                    client_info = line.split(',')
                    client['reason'] = client_info[0].replace('>CLIENT:', '').lower()
                    client['cid'] = client_info[1]
                    client['kid'] = client_info[2]
                elif line.startswith(">CLIENT:DISCONNECT"):
                    client_info = line.split(',')
                    client['reason'] = client_info[0].replace('>CLIENT:', '').lower()
                    client['cid'] = client_info[1]
                elif line.startswith(">CLIENT:ENV,"):
                    client_env = line.split(',')[1].split('=')
                    client['env'][client_env[0]] = client_env[1] if len(client_env) == 2 else ''
                else:
                    raise errors.ParseError("Can't parse line: %s" % (line,))
            except Exception as e:
                raise errors.ParseError("Can't parse line: %s" % (line,))

        return client

    def log_info(self, client: dict, message: str) -> None:
        prefix = self.format_log_prefix(client)

        logger.info('[%s]: %s' % (prefix, message))

    def log_debug(self, client: dict, message: str) -> None:
        prefix = self.format_log_prefix(client)

        logger.debug('[%s]: %s' % (prefix, message))

    def format_log_prefix(self, client: dict) -> str:
        prefix = 'cid: %s' % (client['cid'],)
        if 'common_name' in client['env']:
            prefix += ' | %s' % client['env']['common_name']

        return prefix
