"""Integration tests for PULSE/1 TCP client and server communication."""

import socket
import threading
import time
import pytest

from parallax.pulse.constants import MessageType
from parallax.pulse.exceptions import (
    ConnectionClosedError,
    InvalidMagicError,
    InvalidPayloadError,
)
from parallax.pulse.frame import PulseFrame, read_frame, write_frame, write_raw
from parallax.pulse.client import PulseClient
from parallax.pulse.server import PulseServer


@pytest.fixture
def running_server():
    """Provides a running PulseServer on an ephemeral port in corrected mode."""
    server = PulseServer(host="127.0.0.1", port=0, vulnerable=False)
    server.start()
    yield server
    server.stop()


class TestClientServerCommunication:
    """Tests basic client and server TCP interactions."""

    def test_hello_and_status_exchange(self, running_server: PulseServer) -> None:
        with PulseClient(host="127.0.0.1", port=running_server.port) as client:
            resp = client.hello()
            assert resp.msg_type == MessageType.STATUS
            assert resp.payload.get("status") == "ready"
            assert resp.payload.get("service") == "PULSE/1"

            status_resp = client.status()
            assert status_resp.msg_type == MessageType.STATUS
            assert status_resp.payload.get("status") == "ok"
            assert status_resp.payload.get("authenticated") is False

    def test_close_terminates_session(self, running_server: PulseServer) -> None:
        with PulseClient(host="127.0.0.1", port=running_server.port) as client:
            resp = client.close_session()
            assert resp.msg_type == MessageType.CLOSE
            assert resp.payload.get("status") == "closed"

    def test_multiple_sequential_requests(self, running_server: PulseServer) -> None:
        with PulseClient(host="127.0.0.1", port=running_server.port) as client:
            client.hello()
            for _ in range(5):
                resp = client.status()
                assert resp.msg_type == MessageType.STATUS
                assert resp.payload.get("status") == "ok"
            close_resp = client.close_session()
            assert close_resp.msg_type == MessageType.CLOSE

    def test_multiple_concurrent_clients(self, running_server: PulseServer) -> None:
        num_clients = 10
        barrier = threading.Barrier(num_clients)
        results = [False] * num_clients

        def client_worker(idx: int) -> None:
            barrier.wait()
            try:
                with PulseClient(host="127.0.0.1", port=running_server.port) as cl:
                    h = cl.hello()
                    s = cl.status()
                    c = cl.close_session()
                    if (
                        h.msg_type == MessageType.STATUS
                        and s.msg_type == MessageType.STATUS
                        and c.msg_type == MessageType.CLOSE
                    ):
                        results[idx] = True
            except Exception:
                results[idx] = False

        threads = [
            threading.Thread(target=client_worker, args=(i,))
            for i in range(num_clients)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert all(results)


class TestServerRobustnessAndMalformedInputs:
    """Tests server behavior against malformed, oversized, or disconnected clients."""

    def test_server_rejects_invalid_magic_with_error_frame(
        self, running_server: PulseServer
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        try:
            raw_bad_magic = PulseFrame.build_raw(int(MessageType.HELLO), b"{}", magic=b"BAD!")
            write_raw(sock, raw_bad_magic)

            # Server should respond with ERROR frame
            resp = read_frame(sock)
            assert resp is not None
            assert resp.msg_type == MessageType.ERROR
            assert "Invalid magic" in resp.payload.get("error", "")
            assert resp.payload.get("code") == 400
        finally:
            sock.close()

    def test_server_rejects_invalid_version_with_error_frame(
        self, running_server: PulseServer
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        try:
            raw_bad_ver = PulseFrame.build_raw(int(MessageType.HELLO), b"{}", version=0x99)
            write_raw(sock, raw_bad_ver)

            resp = read_frame(sock)
            assert resp is not None
            assert resp.msg_type == MessageType.ERROR
            assert "version" in resp.payload.get("error", "").lower()
            assert resp.payload.get("code") == 400
        finally:
            sock.close()

    def test_server_rejects_unknown_message_type_with_error_frame(
        self, running_server: PulseServer
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        try:
            raw_bad_type = PulseFrame.build_raw(0xFE, b"{}")
            write_raw(sock, raw_bad_type)

            resp = read_frame(sock)
            assert resp is not None
            assert resp.msg_type == MessageType.ERROR
            assert "message type" in resp.payload.get("error", "").lower()
            assert resp.payload.get("code") == 400
        finally:
            sock.close()

    def test_server_rejects_invalid_json_with_error_frame(
        self, running_server: PulseServer
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        try:
            raw_bad_json = PulseFrame.build_raw(
                int(MessageType.STATUS), b"{this is not json at all"
            )
            write_raw(sock, raw_bad_json)

            resp = read_frame(sock)
            assert resp is not None
            assert resp.msg_type == MessageType.ERROR
            assert "JSON" in resp.payload.get("error", "")
            assert resp.payload.get("code") == 400
        finally:
            sock.close()

    def test_server_rejects_oversized_payload_with_error_frame(self) -> None:
        # Create server with small 100-byte limit
        with PulseServer(host="127.0.0.1", port=0, max_payload_size=100) as server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", server.port))
            try:
                big_payload = b'{"msg":"' + (b"A" * 200) + b'"}'
                raw_oversized = PulseFrame.build_raw(int(MessageType.STATUS), big_payload)
                write_raw(sock, raw_oversized)

                resp = read_frame(sock, max_payload_size=1000)
                assert resp is not None
                assert resp.msg_type == MessageType.ERROR
                assert resp.payload.get("code") == 413
            finally:
                sock.close()

    def test_abrupt_client_disconnect(self, running_server: PulseServer) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        # Send 2 bytes of header and immediately terminate socket
        sock.sendall(b"PU")
        sock.close()

        # Ensure server survives and handles next connection cleanly
        time.sleep(0.1)
        with PulseClient(host="127.0.0.1", port=running_server.port) as client:
            resp = client.hello()
            assert resp.msg_type == MessageType.STATUS

    def test_fragmented_delivery_across_network(
        self, running_server: PulseServer
    ) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", running_server.port))
        try:
            frame = PulseFrame(msg_type=MessageType.STATUS, payload={"query": "test"})
            data = frame.serialize()

            # Drip feed 1 byte at a time with tiny sleeps
            for b in data:
                sock.sendall(bytes([b]))
                time.sleep(0.001)

            resp = read_frame(sock)
            assert resp is not None
            assert resp.msg_type == MessageType.STATUS
            assert resp.payload.get("status") == "ok"
        finally:
            sock.close()
