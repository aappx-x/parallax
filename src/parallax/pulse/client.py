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


def main() -> int:
    """CLI entrypoint for interactive PULSE/1 client."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="PULSE/1 protocol CLI client.")
    parser.add_argument("--host", default="127.0.0.1", help="PULSE/1 daemon host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"PULSE/1 daemon port (default: {DEFAULT_PORT})")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    subparsers.add_parser("hello", help="Send HELLO handshake")
    subparsers.add_parser("status", help="Query service STATUS telemetry")

    auth_parser = subparsers.add_parser("auth", help="Authenticate with service")
    auth_parser.add_argument("--username", "-u", default="", help="Username")
    auth_parser.add_argument("--password", "-p", default="", help="Password")

    diag_parser = subparsers.add_parser("read-diag", help="Read diagnostic telemetry")
    diag_parser.add_argument("--section", "-s", default="system_config", help="Diagnostic section (default: system_config)")

    subparsers.add_parser("close", help="Send CLOSE frame to terminate session")
    subparsers.add_parser("demo", help="Run authentication flaw demonstration")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "demo":
        from parallax.pulse.demo import run_demo_suite
        return run_demo_suite(host=args.host, port=args.port)

    try:
        with PulseClient(host=args.host, port=args.port) as client:
            if args.command == "hello":
                resp = client.hello()
            elif args.command == "status":
                resp = client.status()
            elif args.command == "auth":
                resp = client.auth(username=args.username, password=args.password)
            elif args.command == "read-diag":
                resp = client.read_diag(section=args.section)
            elif args.command == "close":
                resp = client.close_session()
            else:
                parser.print_help()
                return 1

            print(f"[{resp.msg_type.name}] {json.dumps(resp.payload, indent=2)}")
    except ConnectionClosedError as err:
        print(f"[!] Connection error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
