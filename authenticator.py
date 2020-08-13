from typing import Optional, List, Dict
from lib.openvpn import OpenVPNManagementInterface
from msal import PublicClientApplication
from cacheout import Cache

import util
import uuid
import json


class AADAuthenticatorFlows:
    USER_PASSWORD = 'username_password'
    DEVICE_TOKEN = 'device_token'


class AADAuthenticator(object):
    token_scopes = ["User.ReadBasic.All"]

    def __init__(self, app: PublicClientApplication, graph_endpoint: str, authenticators: List[str],
                 host: Optional[str] = None, port: Optional[int] = None,
                 socket: Optional[str] = None, password: Optional[str] = None):
        self._app = app
        self._graph_endpoint = graph_endpoint
        self._authenticators = authenticators
        self._openvpn = OpenVPNManagementInterface(host, port, socket, password)
        self._openvpn.connect()
        self._states = Cache(maxsize=256, ttl=600)

    def run(self) -> None:
        while True:
            data = self._openvpn.wait_for_data()
            if data.startswith(">INFO"):
                continue

            if data.startswith(">CLIENT:DISCONNECT"):
                self.client_disconnect(data)

            if data.startswith(">CLIENT:CONNECT"):
                self.client_connect(data)

    def send_authentication_success(self, client: Dict) -> None:
        self._openvpn.send_command('client-auth-nt %s %s' % (client['cid'], client['kid']))

    def send_authentication_challenge(self, client: Dict, state_id, message: str) -> None:
        client_challenge = 'CRV1:E,R:%s:%s:%s' % (state_id, util.b64encode_string(client['env']['username']), message)

        self._openvpn.send_command('client-deny %s %s "%s" "%s"'
                                   % (client['cid'], client['kid'], 'client_challenge', client_challenge))

    def send_authentication_error(self, client: Dict, message: str) -> None:
        self._openvpn.send_command('client-deny %s %s "%s" "%s"'
                                   % (client['cid'], client['kid'], message, message))

    def handle_response_challenge(self, client: Dict) -> Optional[dict]:
        if not client['env']['password'].startswith("CRV1::"):
            return None

        password = client['env']['password'].split("::")
        if len(password) < 2:
            return None

        state_id = password[1]
        state = self._states.get(state_id)

        if state is None:
            return None

        if 'flow' not in state:
            return None

        result = self.device_token_finish(state)

        return result

    def client_connect(self, data: str) -> None:
        client = util.parse_client_data(data)

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            result = self.handle_response_challenge(client)
            if result is not None:
                if util.is_authenticated(result):
                    self.send_authentication_success(client)
                    return
                else:
                    self.send_authentication_error(client, util.format_error(result))
                    return

        if AADAuthenticatorFlows.USER_PASSWORD in self._authenticators:
            result = self._app.acquire_token_by_username_password(client['env']['username'], client['env']['password'],
                                                                  scopes=self.token_scopes)

            if not util.is_authenticated(result):
                if 65001 in result.get("error_codes", []):
                    # AAD requires user consent for U/P flow
                    error = "Get consent first:", self._app.get_authorization_request_url(self.token_scopes)
                else:
                    error = result.get("error") + ': ' + result.get("error_description")

                self.send_authentication_error(client, error)
                return

        if AADAuthenticatorFlows.DEVICE_TOKEN in self._authenticators:
            state_id = str(uuid.uuid1())
            flow = self.device_auth_start()
            message = flow['message'] + ". Then press OK."
            self._states.set(state_id, {'client': client, 'flow': flow})

            self.send_authentication_challenge(client, state_id, message)
            return

        self.send_authentication_success(client)
        return

    def client_disconnect(self, data: str) -> None:
        pass

    def device_auth_start(self) -> dict:
        flow = self._app.initiate_device_flow(scopes=self.token_scopes)
        if "user_code" not in flow:
            raise ValueError("Fail to create device flow. Err: %s" % json.dumps(flow, indent=4))

        return flow

    def device_token_finish(self, state: dict) -> dict:
        return self._app.acquire_token_by_device_flow(state['flow'])
