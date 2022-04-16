import contextlib
import logging
import queue
import re
import socket
import sys
import threading
import time
from typing import Generator, Optional
from ..util import errors

logger = logging.getLogger(__name__)

FIRST_LINE_REGEX = re.compile(r"^>CLIENT:(?P<event>([^,]+))(.*)$")
LAST_LINE_REGEX = re.compile(r"^(?:>CLIENT:ENV,)?END$")


class SocketType:
    IP = "ip"
    UNIX_SOCKET = "socket"


class OpenVPNManagementInterface(object):
    def __init__(
        self,
        release_hold: bool,
        host: Optional[str] = None,
        port: Optional[int] = None,
        socket_path: Optional[str] = None,
        password: Optional[str] = None,
    ):
        if (
            (socket_path and host)
            or (socket_path and port)
            or (not socket_path and not host and not port)
        ):
            raise errors.AuthenticatorError(
                "Must specify either socket or host and port"
            )
        if socket_path:
            self._mgmt_socket = socket_path
            self._type = SocketType.UNIX_SOCKET
        else:
            self._mgmt_host = host
            self._mgmt_port = port
            self._type = SocketType.IP

        self._mgmt_password = password
        self._mgmt_release_hold = release_hold

        self._socket = None
        self._release = None

        self._socket_file = None
        self._socket_io_lock = threading.Lock()

        self._listener_thread = None
        self._writer_thread = None

        self._reset_queues()

    @property
    def type(self) -> Optional[str]:
        """Get SocketType object for this VPN."""
        return self._type

    @property
    def mgmt_address(self) -> str:
        """Get address of management interface."""
        if self.type == SocketType.IP:
            return f"{self._mgmt_host}:{self._mgmt_port}"
        else:
            return str(self._mgmt_socket)

    def connect(self, retry: bool = False) -> Optional[bool]:
        """Connect to management interface socket."""
        while True:
            logger.info(
                "Connecting to OpenVPN management %s:%d.",
                self._mgmt_host,
                int(self._mgmt_port),
            )

            try:
                if self.type == SocketType.IP:
                    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    self._socket.connect(
                        ("{}".format(self._mgmt_host), int(self._mgmt_port))
                    )
                else:
                    self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self._socket.connect(self._mgmt_socket)

                resp = self._socket.recv(1024).decode("utf-8")

                self._socket_file = self._socket.makefile("r")
                self._listener_thread = threading.Thread(
                    target=self._socket_read_thread,
                    daemon=True,
                    name="socket-read-thread",
                )
                self._writer_thread = threading.Thread(
                    target=self._socket_write_thread,
                    daemon=True,
                    name="socket-write-thread",
                )

                self._reset_queues()
                self._listener_thread.start()
                self._writer_thread.start()

                if resp.startswith("ENTER PASSWORD"):
                    resp = self.send_command(self._mgmt_password)
                    if not resp.startswith("SUCCESS: password is correct"):
                        logger.critical("Wrong management interface password.")

                    assert resp.startswith(
                        "SUCCESS: password is correct"
                    ), "Wrong management interface password."

                    resp = self._socket_recv("INFO")
                    assert resp.startswith(
                        ">INFO"
                    ), "Did not get expected response from interface when opening socket."
                else:
                    assert resp.startswith(
                        ">INFO"
                    ), "Did not get expected response from interface when opening socket."

                self._get_version()
                logger.info("Connection to OpenVPN management interfaced established.")

                if self._mgmt_release_hold:
                    self._release_hold()

                return True
            except AssertionError as e:
                if not retry:
                    raise e
            except (socket.timeout, socket.error) as e:
                if retry:
                    logger.error(str(e))
                    time.sleep(2)
                else:
                    logger.error(errors.ConnectError(str(e)))
                    sys.exit(1)

    def disconnect(self, _quit=True) -> None:
        """Disconnect from management interface socket."""
        if self._socket is not None:
            if _quit:
                self._socket_send("quit\n")

            self._socket.close()
            self._socket = None

    @property
    def is_connected(self) -> bool:
        """Determine if management interface socket is connected or not."""
        return self._socket is not None

    @property
    def release(self) -> str:
        """OpenVPN release string."""
        if self._release is None:
            self._release = self._get_version()
        return self._release

    @contextlib.contextmanager
    def connection(self) -> Generator:
        """Create context where management interface socket is open and close when done."""
        self.connect()
        try:
            yield
        finally:
            self.disconnect()

    def _socket_read_thread(self):
        """
        This thread handles the socket's output and handles any events before adding the output to the reception queue.
        """
        recv_lines = []
        while True:
            if not self.is_connected:
                break

            line = self._socket_file.readline().strip()

            if not line:
                self._recv_queue["CLIENT"].put(None)
                break

            if line.startswith(">INFO:"):
                self._recv_queue["INFO"].put(line + "\n")
                continue

            if line.startswith(">HOLD:"):
                continue

            if (
                line.startswith("SUCCESS:")
                or line.startswith("ERROR:")
                or line.startswith("ENTER PASSWORD")
            ):
                self._recv_queue["COMMAND"].put(line + "\n")
                continue

            if len(recv_lines) == 0:
                self._socket_io_lock.acquire()

            recv_lines.append(line)

            if LAST_LINE_REGEX.match(line):
                self._socket_io_lock.release()
                queue_name = "CLIENT" if line.startswith(">CLIENT") else "COMMAND"
                self._recv_queue[queue_name].put("\n".join(recv_lines))
                recv_lines = []

    def _socket_write_thread(self):
        while True:
            if not self.is_connected:
                break

            try:
                data = self._send_queue.get()
                self._socket_io_lock.acquire()
                self._socket.send(bytes(data, "utf-8"))
            finally:
                self._socket_io_lock.release()

    def _socket_send(self, data) -> None:
        """Convert data to bytes and send to socket."""
        if self._socket is None:
            raise errors.NotConnectedError(
                "You must be connected to the management interface to issue commands."
            )
        self._send_queue.put(data)

    def _socket_recv(self, queue_name: str) -> str:
        """Receive bytes from socket and convert to string."""
        if self._socket is None:
            raise errors.NotConnectedError(
                "You must be connected to the management interface to issue commands."
            )

        return self._recv_queue[queue_name].get()

    def send_command(self, cmd) -> Optional[str]:
        """Send command to management interface and fetch response."""
        if not self.is_connected:
            raise errors.NotConnectedError(
                "You must be connected to the management interface to issue commands."
            )

        logger.debug("Sending cmd: %r", cmd.strip())
        self._socket_send(cmd + "\n")
        if cmd.startswith("kill") or cmd.startswith("client-kill"):
            return
        resp = self._socket_recv("COMMAND")
        logger.debug("Cmd response: %r", resp)

        if resp.startswith("ERROR: "):
            logger.error(resp)

        return resp

    def _reset_queues(self) -> None:
        self._recv_queue = {
            "COMMAND": queue.Queue(),
            "CLIENT": queue.Queue(),
            "INFO": queue.Queue(),
        }
        self._send_queue = queue.Queue()

    def _get_version(self) -> str:
        """Get OpenVPN version from socket."""
        raw = self.send_command("version")
        for line in raw.splitlines():
            if line.startswith("OpenVPN Version"):
                return line.replace("OpenVPN Version: ", "")
        raise errors.ParseError(
            "Unable to get OpenVPN version, no matches found in socket response. (Got: %s)",
            (raw,),
        )

    def _release_hold(self) -> None:
        logger.info("Releasing management hold on OpenVPN Server.")
        raw = self.send_command("hold release")
        for line in raw.splitlines():
            if line.startswith("SUCCESS: hold release succeeded"):
                return

        raise errors.ParseError(
            "Unable to release hold on server, no matches found in socket response. (Got: %s)",
            (raw,),
        )

    def receive(self) -> str:
        """Poll for incoming data"""
        if not self.is_connected:
            raise errors.NotConnectedError(
                "You must be connected to the management interface to issue commands."
            )
        logger.debug("Waiting for incoming data")

        recv = self._socket_recv("CLIENT")
        logger.debug("Got data: '%s'", recv)
        return recv

    @staticmethod
    def has_prefix(line) -> bool:
        return (
            line.startswith(">INFO")
            or line.startswith(">CLIENT")
            or line.startswith(">STATE")
        )

    @property
    def socket(self):
        return self._socket
