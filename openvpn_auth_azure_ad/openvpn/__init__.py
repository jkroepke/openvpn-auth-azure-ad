import contextlib
import logging
import select
import socket
from typing import Generator, Optional

import openvpn_auth_azure_ad.util.errors as errors

logger = logging.getLogger(__name__)


class SocketType:
    IP = "ip"
    UNIX_SOCKET = "socket"


class OpenVPNManagementInterface(object):
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None,
                 socket_path: Optional[str] = None, password: Optional[str] = None):
        if (socket_path and host) or (socket_path and port) or (not socket_path and not host and not port):
            raise errors.AuthenticatorError("Must specify either socket or host and port")
        if socket_path:
            self._mgmt_socket = socket_path
            self._type = SocketType.UNIX_SOCKET
        else:
            self._mgmt_host = host
            self._mgmt_port = port
            self._type = SocketType.IP
        self._mgmt_password = password
        self._socket = None
        self._release = None

    @property
    def type(self) -> Optional[str]:
        """Get SocketType object for this VPN.
        """
        return self._type

    @property
    def mgmt_address(self) -> str:
        """Get address of management interface.
        """
        if self.type == SocketType.IP:
            return f"{self._mgmt_host}:{self._mgmt_port}"
        else:
            return str(self._mgmt_socket)

    def connect(self) -> Optional[bool]:
        """Connect to management interface socket.
        """
        try:
            if self.type == SocketType.IP:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._socket.settimeout(5)
                self._socket.connect(('{}'.format(self._mgmt_host), int(self._mgmt_port)))
            else:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.connect(self._mgmt_socket)

            resp = self._socket_recv()

            if resp.startswith("ENTER PASSWORD"):
                resp = self.send_command(self._mgmt_password)
                if not resp.startswith("SUCCESS: password is correct"):
                    logger.critical("Wrong management interface password.")

                assert resp.startswith("SUCCESS: password is correct"), "Wrong management interface password."
            else:
                print(resp)
                assert resp.startswith(">INFO"), "Did not get expected response from interface when opening socket."

            logger.info("Connection to OpenVPN management interfaced established.")
            self._get_version()

            return True
        except (socket.timeout, socket.error) as e:
            raise errors.ConnectError(str(e)) from None

    def disconnect(self, _quit=True) -> None:
        """Disconnect from management interface socket.
        """
        if self._socket is not None:
            if _quit:
                self._socket_send("quit\n")
            self._socket.close()
            self._socket = None

    @property
    def is_connected(self) -> bool:
        """Determine if management interface socket is connected or not.
        """
        return self._socket is not None

    @property
    def release(self) -> str:
        """OpenVPN release string.
        """
        if self._release is None:
            self._release = self._get_version()
        return self._release

    @contextlib.contextmanager
    def connection(self) -> Generator:
        """Create context where management interface socket is open and close when done.
        """
        self.connect()
        try:
            yield
        finally:
            self.disconnect()

    def _socket_send(self, data) -> None:
        """Convert data to bytes and send to socket.
        """
        self._socket.send(bytes(data, "utf-8"))

    def _socket_recv(self) -> str:
        """Receive bytes from socket and convert to string.
        """
        buffer_size = 4096  # 4 KiB
        data = b''
        while True:
            part = self._socket.recv(buffer_size)
            data += part
            if len(part) < buffer_size:
                # either 0 or end of data
                break

        return data.decode("utf-8")

    def send_command(self, cmd) -> Optional[str]:
        """Send command to management interface and fetch response.
        """
        if not self.is_connected:
            raise errors.NotConnectedError("You must be connected to the management interface to issue commands.")
        logger.debug("Sending cmd: %r", cmd.strip())
        self._socket_send(cmd + "\n")
        if cmd.startswith("kill") or cmd.startswith("client-kill"):
            return
        resp = self._socket_recv()
        logger.debug("Cmd response: %r", resp)
        return resp

    def _get_version(self) -> str:
        """Get OpenVPN version from socket.
        """
        raw = self.send_command("version")
        for line in raw.splitlines():
            if line.startswith("OpenVPN Version"):
                return line.replace("OpenVPN Version: ", "")
        raise errors.ParseError("Unable to get OpenVPN version, no matches found in socket response.")

    def wait_for_data(self) -> str:
        """Poll for incoming data
        """
        if not self.is_connected:
            raise errors.NotConnectedError("You must be connected to the management interface to issue commands.")
        logger.debug("Waiting for incoming data")

        _ = select.select([self._socket], [], [])[0]

        return self._socket_recv()

    @staticmethod
    def has_prefix(line) -> bool:
        return line.startswith(">INFO") or line.startswith(">CLIENT") or line.startswith(">STATE")

    @property
    def socket(self):
        return self._socket
