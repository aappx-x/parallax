"""PULSE/1 reference TCP server implementation."""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any

from parallax.pulse.constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_PORT,
    MessageType,
)
from parallax.pulse.exceptions import (
    ConnectionClosedError,
    FrameError,
    IncompleteFrameError,
    InvalidMagicError,
    InvalidMessageTypeError,
    InvalidPayloadError,
    InvalidVersionError,
    PayloadTooLargeError,
)
from parallax.pulse.frame import PulseFrame, read_frame, write_frame
from parallax.pulse.session import PulseSession

logger = logging.getLogger(__name__)

# Default synthetic credentials for the daemon
DEFAULT_CREDENTIALS = {
    "svc-pulse": "Meridian#PulseKey2024",
    "pulse_admin": "Puls3Admin!Pass",
}

# Default synthetic diagnostics strictly isolated to simulation
DEFAULT_DIAGNOSTICS: dict[str, dict[str, Any]] = {
    "system_config": {
        "section": "system_config",
        "service": "PULSE/1",
        "version": "0.1.0",
        "daemon_user": "svc-pulse",
        "helper_path": "/usr/local/bin/pulse-helper",
        "config_path": "/etc/pulse/pulse.conf",
        "archive_directory": "/var/archive/meridian",
        "diagnostic_ticket": "DIAG-TKT-7741-ALPHA",
        "encryption_passphrase_fragment": "meridian-vault-2024-fragA",
    },
    "telemetry": {
        "section": "telemetry",
        "service": "PULSE/1",
        "cpu_usage_pct": 2.4,
        "memory_rss_bytes": 14285700,
        "active_threads": 4,
    },
}


class PulseServer:
    """Reference TCP server implementation for the PULSE/1 protocol."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_PORT,
        vulnerable: bool = False,
        credentials: dict[str, str] | None = None,
        diagnostics: dict[str, dict[str, Any]] | None = None,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        client_timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port_requested = port
        self.vulnerable = vulnerable
        self.credentials = credentials if credentials is not None else dict(DEFAULT_CREDENTIALS)
        self.diagnostics = diagnostics if diagnostics is not None else dict(DEFAULT_DIAGNOSTICS)
        self.max_payload_size = max_payload_size
        self.client_timeout = client_timeout

        self._server_socket: socket.socket | None = None
        self._bound_port: int | None = None
        self._is_running = threading.Event()
        self._listen_thread: threading.Thread | None = None
        self._client_threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._start_time: float = 0.0

    @property
    def port(self) -> int:
        """Return the actual bound port of the server."""
        if self._bound_port is not None:
            return self._bound_port
        return self.port_requested

    @property
    def uptime(self) -> float:
        """Return daemon uptime in seconds."""
        if self._start_time == 0.0:
            return 0.0
        return max(0.0, time.time() - self._start_time)

    def start(self) -> None:
        """Bind socket, begin listening, and start background worker thread."""
        if self._is_running.is_set():
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port_requested))
        sock.listen(128)
        sock.settimeout(0.5)

        self._server_socket = sock
        self._bound_port = sock.getsockname()[1]
        self._start_time = time.time()
        self._is_running.set()

        thread = threading.Thread(target=self._listen_loop, daemon=True, name="PulseServer-Listener")
        self._listen_thread = thread
        thread.start()
        logger.info("PulseServer started on %s:%d (vulnerable=%s)", self.host, self.port, self.vulnerable)

    def stop(self) -> None:
        """Stop listening and cleanly shutdown active client connections."""
        if not self._is_running.is_set():
            return

        self._is_running.clear()

        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

        if self._listen_thread is not None:
            self._listen_thread.join(timeout=2.0)
            self._listen_thread = None

        with self._lock:
            threads = list(self._client_threads)
        for t in threads:
            t.join(timeout=2.0)
        with self._lock:
            self._client_threads.clear()

        logger.info("PulseServer stopped.")

    def __enter__(self) -> PulseServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def _listen_loop(self) -> None:
        while self._is_running.is_set():
            if self._server_socket is None:
                break
            try:
                client_sock, client_addr = self._server_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            client_sock.settimeout(self.client_timeout)
            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, client_addr),
                daemon=True,
                name=f"PulseServer-Client-{client_addr[0]}:{client_addr[1]}",
            )
            with self._lock:
                self._client_threads.append(client_thread)
            client_thread.start()

    def _handle_client(self, conn: socket.socket, client_addr: tuple[str, int]) -> None:
        session = PulseSession(client_address=client_addr)
        try:
            while self._is_running.is_set() and not session.closed:
                try:
                    frame = read_frame(conn, max_payload_size=self.max_payload_size)
                    if frame is None:
                        # Clean peer disconnect
                        break
                except (
                    InvalidMagicError,
                    InvalidVersionError,
                    InvalidMessageTypeError,
                    InvalidPayloadError,
                    PayloadTooLargeError,
                ) as err:
                    status_code = 413 if isinstance(err, PayloadTooLargeError) else 400
                    try:
                        err_frame = PulseFrame(
                            msg_type=MessageType.ERROR,
                            payload={"error": str(err), "code": status_code},
                        )
                        write_frame(conn, err_frame, max_payload_size=self.max_payload_size)
                        conn.shutdown(socket.SHUT_WR)
                        conn.settimeout(0.2)
                        while conn.recv(4096):
                            pass
                    except Exception:
                        pass
                    break
                except (IncompleteFrameError, ConnectionClosedError, TimeoutError, OSError):
                    break

                response = self.handle_message(session, frame)
                if response is not None:
                    try:
                        write_frame(conn, response, max_payload_size=self.max_payload_size)
                    except (ConnectionClosedError, OSError):
                        break

                if frame.msg_type == MessageType.CLOSE or session.closed:
                    break
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._lock:
                cur_thread = threading.current_thread()
                if cur_thread in self._client_threads:
                    self._client_threads.remove(cur_thread)

    def handle_message(self, session: PulseSession, frame: PulseFrame) -> PulseFrame | None:
        """Process an incoming frame and produce an appropriate protocol response."""
        session.request_count += 1
        session.last_activity = time.time()
        payload = frame.payload if isinstance(frame.payload, dict) else {}

        if frame.msg_type == MessageType.HELLO:
            session.hello_received = True
            return PulseFrame(
                msg_type=MessageType.STATUS,
                payload={
                    "status": "ready",
                    "service": "PULSE/1",
                    "version": "0.1.0",
                    "vulnerable_mode": self.vulnerable,
                },
            )

        if frame.msg_type == MessageType.STATUS:
            return PulseFrame(
                msg_type=MessageType.STATUS,
                payload={
                    "status": "ok",
                    "service": "PULSE/1",
                    "authenticated": session.authenticated,
                    "uptime_seconds": round(self.uptime, 2),
                },
            )

        if frame.msg_type == MessageType.AUTH:
            session.auth_attempted = True
            username = str(payload.get("username", ""))
            password = str(payload.get("password", ""))

            if self._verify_credentials(username, password):
                session.authenticated = True
                session.auth_failed = False
                session.username = username
                return PulseFrame(
                    msg_type=MessageType.STATUS,
                    payload={"status": "authenticated", "message": "Authentication successful"},
                )
            else:
                session.authenticated = False
                session.auth_failed = True
                return PulseFrame(
                    msg_type=MessageType.ERROR,
                    payload={"error": "Authentication Failed", "code": 401},
                )

        if frame.msg_type == MessageType.READ_DIAG:
            return self._handle_read_diag(session, payload)

        if frame.msg_type == MessageType.CLOSE:
            session.closed = True
            return PulseFrame(
                msg_type=MessageType.CLOSE,
                payload={"status": "closed", "message": "Session terminated"},
            )

        if frame.msg_type == MessageType.ERROR:
            # Client emitted an ERROR notification
            return None

        return PulseFrame(
            msg_type=MessageType.ERROR,
            payload={"error": f"Unhandled message type: {frame.msg_type}", "code": 400},
        )

    def _verify_credentials(self, username: str, password: str) -> bool:
        """Verify given credentials against configured dictionary."""
        if username in self.credentials and self.credentials[username] == password:
            return True
        return False

    def _handle_read_diag(self, session: PulseSession, payload: dict[str, Any]) -> PulseFrame:
        """Handle READ_DIAG request with state-machine authorization enforcement."""
        if self.vulnerable:
            # Flaw: When the attacker submits invalid credentials via AUTH, the server
            # emits ERROR ("Authentication Failed"), but the state machine fails to set
            # an authorization guard flag. READ_DIAG succeeds after failed authentication!
            if not (session.authenticated or session.auth_failed):
                return PulseFrame(
                    msg_type=MessageType.ERROR,
                    payload={"error": "Authentication required", "code": 403},
                )
        else:
            # Corrected mode: READ_DIAG is strictly rejected unless authentication succeeded
            if not session.authenticated:
                return PulseFrame(
                    msg_type=MessageType.ERROR,
                    payload={"error": "Authentication required", "code": 403},
                )

        section = payload.get("section", "system_config")
        diag_section = self.diagnostics.get(
            section,
            {
                "section": section,
                "status": "not_found",
                "message": f"Section '{section}' not found",
            },
        )
        return PulseFrame(msg_type=MessageType.READ_DIAG, payload=diag_section)
