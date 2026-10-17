"""Comprehensive tests for PULSE/1 binary framing, serialization, and stream I/O."""

import json
import socket
import struct
import pytest

from parallax.pulse.constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    MessageType,
)
from parallax.pulse.exceptions import (
    ConnectionClosedError,
    IncompleteFrameError,
    InvalidMagicError,
    InvalidMessageTypeError,
    InvalidPayloadError,
    InvalidVersionError,
    PayloadTooLargeError,
)
from parallax.pulse.frame import (
    PulseFrame,
    read_frame,
    write_frame,
    write_raw,
)


class TestPulseFrameRoundTrip:
    """Tests round-trip serialization and deserialization across all message types."""

    @pytest.mark.parametrize(
        "msg_type",
        [
            MessageType.HELLO,
            MessageType.AUTH,
            MessageType.STATUS,
            MessageType.READ_DIAG,
            MessageType.CLOSE,
            MessageType.ERROR,
        ],
    )
    def test_all_message_types_round_trip(self, msg_type: MessageType) -> None:
        payload = {"type_name": msg_type.name, "code": int(msg_type), "active": True}
        frame = PulseFrame(msg_type=msg_type, payload=payload)
        serialized = frame.serialize()

        # Check binary layout
        assert serialized[:4] == MAGIC
        assert serialized[4] == VERSION
        assert serialized[5] == int(msg_type)
        payload_len = struct.unpack("!H", serialized[6:8])[0]
        assert payload_len == len(serialized) - 8

        # Deserialization check
        decoded, remainder = PulseFrame.deserialize(serialized)
        assert remainder == b""
        assert decoded.msg_type == msg_type
        assert decoded.version == VERSION
        assert decoded.payload == payload

    def test_empty_dict_payload(self) -> None:
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={})
        serialized = frame.serialize()
        decoded, remainder = PulseFrame.deserialize(serialized)
        assert remainder == b""
        assert decoded.payload == {}

    def test_none_payload_serializes_to_empty_dict(self) -> None:
        frame = PulseFrame(msg_type=MessageType.CLOSE, payload=None)
        serialized = frame.serialize()
        decoded, remainder = PulseFrame.deserialize(serialized)
        assert remainder == b""
        assert decoded.payload == {}

    def test_zero_length_payload_deserializes_to_empty_dict(self) -> None:
        raw = PulseFrame.build_raw(int(MessageType.STATUS), b"")
        decoded, remainder = PulseFrame.deserialize(raw)
        assert remainder == b""
        assert decoded.payload == {}

    def test_complex_and_unicode_payloads(self) -> None:
        payload = {
            "unicode_text": "Meridian 🛰️ Computation Lab / 東京",
            "numbers": [0, -42, 3.14159, 100000],
            "nested": {
                "flag": False,
                "null_val": None,
                "sub_list": ["alpha", "beta", "gamma"],
            },
        }
        frame = PulseFrame(msg_type=MessageType.READ_DIAG, payload=payload)
        serialized = frame.serialize()
        decoded, remainder = PulseFrame.deserialize(serialized)
        assert remainder == b""
        assert decoded.payload == payload

    def test_stream_of_multiple_concatenated_frames(self) -> None:
        f1 = PulseFrame(msg_type=MessageType.HELLO, payload={"client": "pulse-cli"})
        f2 = PulseFrame(msg_type=MessageType.AUTH, payload={"username": "svc-pulse"})
        f3 = PulseFrame(msg_type=MessageType.CLOSE, payload={})

        stream = f1.serialize() + f2.serialize() + f3.serialize()

        d1, rem1 = PulseFrame.deserialize(stream)
        assert d1.msg_type == MessageType.HELLO
        assert d1.payload == {"client": "pulse-cli"}

        d2, rem2 = PulseFrame.deserialize(rem1)
        assert d2.msg_type == MessageType.AUTH
        assert d2.payload == {"username": "svc-pulse"}

        d3, rem3 = PulseFrame.deserialize(rem2)
        assert d3.msg_type == MessageType.CLOSE
        assert d3.payload == {}
        assert rem3 == b""

    def test_from_bytes_exact_flag(self) -> None:
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={"status": "ok"})
        data = frame.serialize()

        # exact=True on clean data succeeds
        parsed = PulseFrame.from_bytes(data, exact=True)
        assert parsed.payload == {"status": "ok"}

        # exact=True on data with trailing noise fails
        with pytest.raises(InvalidPayloadError, match="Extraneous"):
            PulseFrame.from_bytes(data + b"trailing_noise", exact=True)

        # exact=False allows trailing noise
        parsed_non_exact = PulseFrame.from_bytes(data + b"trailing_noise", exact=False)
        assert parsed_non_exact.payload == {"status": "ok"}


class TestPulseFrameValidationAndRejection:
    """Tests wire boundary enforcement and rejection of malformed frames."""

    def test_reject_invalid_magic(self) -> None:
        bad_magics = [b"FAIL", b"puls", b"PUL\x00", b"\x00\x00\x00\x00"]
        for magic in bad_magics:
            raw = PulseFrame.build_raw(int(MessageType.HELLO), b"{}", magic=magic)
            with pytest.raises(InvalidMagicError, match="Invalid magic identifier"):
                PulseFrame.deserialize(raw)

    def test_reject_invalid_version(self) -> None:
        bad_versions = [0x00, 0x02, 0x05, 0xFF]
        for ver in bad_versions:
            raw = PulseFrame.build_raw(int(MessageType.HELLO), b"{}", version=ver)
            with pytest.raises(InvalidVersionError, match="Unsupported protocol version"):
                PulseFrame.deserialize(raw)

    def test_reject_unknown_message_types(self) -> None:
        bad_types = [0x00, 0x07, 0x10, 0xFF]
        for t in bad_types:
            raw = PulseFrame.build_raw(t, b"{}")
            with pytest.raises(InvalidMessageTypeError, match="Unknown message type"):
                PulseFrame.deserialize(raw)

    def test_reject_invalid_json_syntax(self) -> None:
        bad_payloads = [
            b"{not valid json",
            b'{"key": }',
            b"hello world",
            b"{'single_quotes': 1}",
        ]
        for p in bad_payloads:
            raw = PulseFrame.build_raw(int(MessageType.STATUS), p)
            with pytest.raises(InvalidPayloadError, match="Payload is not valid JSON"):
                PulseFrame.deserialize(raw)

    def test_reject_invalid_utf8_payload(self) -> None:
        # Non-UTF8 byte sequence
        bad_bytes = b"\x80\x81\xff\xfe"
        raw = PulseFrame.build_raw(int(MessageType.STATUS), bad_bytes)
        with pytest.raises(InvalidPayloadError, match="Payload is not valid UTF-8"):
            PulseFrame.deserialize(raw)

    def test_enforce_payload_length_limit_on_serialize(self) -> None:
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={"data": "A" * 100})
        # Serialized payload will be ~115 bytes; limit to 50 bytes
        with pytest.raises(PayloadTooLargeError, match="exceeds maximum allowed limit"):
            frame.serialize(max_payload_size=50)

    def test_enforce_payload_length_limit_on_deserialize(self) -> None:
        # Craft frame claiming payload_length of 1000 when limit is 500
        header = struct.pack(HEADER_SIZE and "!4sBBH", MAGIC, VERSION, int(MessageType.STATUS), 1000)
        data = header + (b" " * 1000)
        with pytest.raises(PayloadTooLargeError, match="exceeds maximum limit"):
            PulseFrame.deserialize(data, max_payload_size=500)

    def test_incomplete_header(self) -> None:
        raw = PulseFrame(msg_type=MessageType.STATUS, payload={}).serialize()
        for length in range(HEADER_SIZE):
            with pytest.raises(IncompleteFrameError, match="Buffer has .* need at least 8"):
                PulseFrame.deserialize(raw[:length])

    def test_incomplete_payload(self) -> None:
        raw = PulseFrame(msg_type=MessageType.STATUS, payload={"status": "running"}).serialize()
        # Truncate by 3 bytes
        with pytest.raises(IncompleteFrameError, match="payload bytes, need"):
            PulseFrame.deserialize(raw[:-3])

    def test_boundary_max_16bit_payload(self) -> None:
        # 65535 payload size
        # Check that serialize rejects > 65535 even if max_payload_size is large
        oversized_str = "x" * 70000
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={"big": oversized_str})
        with pytest.raises(PayloadTooLargeError):
            frame.serialize(max_payload_size=100000)


class TestSocketStreamIO:
    """Tests read_frame, write_frame, and partial reads/writes over sockets."""

    @pytest.fixture
    def socket_pair(self) -> tuple[socket.socket, socket.socket]:
        """Provides a connected pair of local sockets."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        addr = server_sock.getsockname()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(addr)
        conn, _ = server_sock.accept()
        server_sock.close()

        yield client_sock, conn

        client_sock.close()
        conn.close()

    def test_socket_write_and_read_round_trip(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        frame = PulseFrame(
            msg_type=MessageType.READ_DIAG,
            payload={"section": "system_config"},
        )
        write_frame(client, frame)
        received = read_frame(server)
        assert received is not None
        assert received.msg_type == MessageType.READ_DIAG
        assert received.payload == {"section": "system_config"}

    def test_socket_clean_disconnect_returns_none(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        client.close()
        received = read_frame(server)
        assert received is None

    def test_socket_partial_reads_byte_by_byte(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        frame = PulseFrame(msg_type=MessageType.HELLO, payload={"client": "test"})
        data = frame.serialize()

        # Send data 1 byte at a time to test partial read buffering
        for byte in data:
            client.send(bytes([byte]))

        received = read_frame(server)
        assert received is not None
        assert received.msg_type == MessageType.HELLO
        assert received.payload == {"client": "test"}

    def test_socket_truncated_header_raises_incomplete(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={})
        data = frame.serialize()

        # Send only 4 bytes of header, then close
        client.sendall(data[:4])
        client.close()

        with pytest.raises(IncompleteFrameError, match="Connection closed after 4 bytes of header"):
            read_frame(server)

    def test_socket_truncated_payload_raises_incomplete(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={"key": "value"})
        data = frame.serialize()

        # Send full header (8 bytes) + only 2 bytes of payload, then close
        client.sendall(data[:10])
        client.close()

        with pytest.raises(IncompleteFrameError, match="Connection closed after 2 bytes of payload"):
            read_frame(server)

    def test_socket_oversized_payload_raises_error(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        frame = PulseFrame(msg_type=MessageType.STATUS, payload={"data": "x" * 200})
        write_frame(client, frame)

        with pytest.raises(PayloadTooLargeError, match="exceeds maximum limit"):
            read_frame(server, max_payload_size=50)

    def test_socket_invalid_magic_raises_error(
        self, socket_pair: tuple[socket.socket, socket.socket]
    ) -> None:
        client, server = socket_pair
        raw = PulseFrame.build_raw(int(MessageType.STATUS), b"{}", magic=b"BADM")
        write_raw(client, raw)

        with pytest.raises(InvalidMagicError, match="Invalid magic identifier"):
            read_frame(server)
