"""PULSE/1 reference TCP client implementation."""

from __future__ import annotations

import socket
from typing import Any

from parallax.pulse.constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_PORT,
    MessageType,
)
from parallax.pulse.exceptions import (
    ConnectionClosedError,
    PulseError,
)
from parallax.pulse.frame import PulseFrame, read_frame, write_frame


class PulseClient:
    """Client for connecting to and interacting with a PULSE/1 daemon."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        timeout: float = 5.0,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_payload_size = max_payload_size
        self._socket: socket.socket | None = None

    @property
    def is_connected(self) -> bool:
        """Check if socket is currently active."""
        return self._socket is not None

    def connect(self) -> None:
        """Establish TCP connection to the PULSE/1 service."""
        if self._socket is not None:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError as err:
            sock.close()
            raise ConnectionClosedError(f"Failed to connect to {self.host}:{self.port}: {err}") from err

        self._socket = sock

    def close(self) -> None:
        """Close the underlying TCP socket."""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def __enter__(self) -> PulseClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def send_frame(self, frame: PulseFrame) -> None:
        """Send a frame over the socket connection."""
        if self._socket is None:
            raise ConnectionClosedError("Client is not connected to a server")
        write_frame(self._socket, frame, max_payload_size=self.max_payload_size)

    def receive_frame(self) -> PulseFrame | None:
        """Receive a frame from the socket connection."""
        if self._socket is None:
            raise ConnectionClosedError("Client is not connected to a server")
        return read_frame(self._socket, max_payload_size=self.max_payload_size)

    def send_and_receive(self, frame: PulseFrame) -> PulseFrame:
        """Send a frame and await a single response frame."""
        self.send_frame(frame)
        response = self.receive_frame()
        if response is None:
            raise ConnectionClosedError("Server closed connection without responding")
        return response

    def hello(self, payload: dict[str, Any] | None = None) -> PulseFrame:
        """Initiate session handshake."""
        frame = PulseFrame(
            msg_type=MessageType.HELLO,
            payload=payload if payload is not None else {"client": "pulse-python-client", "version": "0.1.0"},
        )
        return self.send_and_receive(frame)

    def auth(self, username: str = "", password: str = "") -> PulseFrame:
        """Submit authentication credentials."""
        frame = PulseFrame(
            msg_type=MessageType.AUTH,
            payload={"username": username, "password": password},
        )
        return self.send_and_receive(frame)

    def status(self) -> PulseFrame:
        """Request operational status telemetry."""
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={})
        return self.send_and_receive(frame)

    def read_diag(self, section: str = "system_config") -> PulseFrame:
        """Request diagnostic telemetry for the specified section."""
        frame = PulseFrame(
            msg_type=MessageType.READ_DIAG,
            payload={"section": section},
        )
        return self.send_and_receive(frame)

    def close_session(self) -> PulseFrame:
        """Send CLOSE message to terminate the session gracefully."""
        frame = PulseFrame(msg_type=MessageType.CLOSE, payload={"reason": "normal_shutdown"})
        resp = self.send_and_receive(frame)
        self.close()
        return resp
