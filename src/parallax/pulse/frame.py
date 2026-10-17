"""Binary framing, serialization, and deserialization for PULSE/1."""

from __future__ import annotations

from dataclasses import dataclass
import json
import socket
import struct
from typing import Any

from parallax.pulse.constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    VERSION,
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


@dataclass(frozen=True)
class PulseFrame:
    """Represents a single PULSE/1 protocol frame."""

    msg_type: MessageType
    payload: Any = None
    version: int = VERSION

    def serialize(self, max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE) -> bytes:
        """Encode this frame into wire format bytes.

        Raises:
            InvalidPayloadError: If the payload cannot be serialized to JSON.
            PayloadTooLargeError: If the serialized payload exceeds max_payload_size or 65535 bytes.
        """
        if self.payload is None:
            raw_payload = b"{}"
        elif isinstance(self.payload, (dict, list, str, int, float, bool)):
            try:
                raw_payload = json.dumps(self.payload, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError) as err:
                raise InvalidPayloadError(f"Failed to serialize payload to JSON: {err}") from err
        else:
            raise InvalidPayloadError(f"Unsupported payload type: {type(self.payload)}")

        payload_len = len(raw_payload)
        if payload_len > max_payload_size or payload_len > 0xFFFF:
            raise PayloadTooLargeError(
                f"Payload size {payload_len} exceeds maximum allowed limit {min(max_payload_size, 0xFFFF)}"
            )

        header = struct.pack(HEADER_FORMAT, MAGIC, self.version, int(self.msg_type), payload_len)
        return header + raw_payload

    @classmethod
    def build_raw(
        cls,
        msg_type: int,
        raw_payload: bytes,
        version: int = VERSION,
        magic: bytes = MAGIC,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
    ) -> bytes:
        """Construct raw wire frame bytes without JSON validation.

        Useful for synthetic protocol fuzzing, packet capture generation, and negative testing.
        """
        payload_len = len(raw_payload)
        if payload_len > max_payload_size or payload_len > 0xFFFF:
            raise PayloadTooLargeError(f"Payload size {payload_len} exceeds maximum allowed limit")
        header = struct.pack(HEADER_FORMAT, magic, version, msg_type, payload_len)
        return header + raw_payload

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
    ) -> tuple[PulseFrame, bytes]:
        """Deserialize the first frame from the given byte buffer.

        Returns:
            Tuple of (parsed_frame, remaining_unparsed_bytes).

        Raises:
            IncompleteFrameError: If data has fewer bytes than required for header or payload.
            InvalidMagicError: If magic identifier is not 'PULS'.
            InvalidVersionError: If protocol version is unsupported.
            InvalidMessageTypeError: If message type is unrecognized.
            PayloadTooLargeError: If payload length exceeds max_payload_size.
            InvalidPayloadError: If payload is not valid UTF-8 JSON.
        """
        if len(data) < HEADER_SIZE:
            raise IncompleteFrameError(
                f"Buffer has {len(data)} bytes, need at least {HEADER_SIZE} for frame header"
            )

        magic, version, msg_type_raw, payload_len = struct.unpack(
            HEADER_FORMAT, data[:HEADER_SIZE]
        )

        if magic != MAGIC:
            raise InvalidMagicError(f"Invalid magic identifier: {magic!r}, expected {MAGIC!r}")

        if version != VERSION:
            raise InvalidVersionError(
                f"Unsupported protocol version: {version:#04x}, expected {VERSION:#04x}"
            )

        try:
            msg_type = MessageType(msg_type_raw)
        except ValueError as err:
            raise InvalidMessageTypeError(f"Unknown message type: {msg_type_raw:#04x}") from err

        if payload_len > max_payload_size:
            raise PayloadTooLargeError(
                f"Payload length {payload_len} exceeds maximum limit of {max_payload_size}"
            )

        total_frame_len = HEADER_SIZE + payload_len
        if len(data) < total_frame_len:
            raise IncompleteFrameError(
                f"Buffer has {len(data) - HEADER_SIZE} payload bytes, need {payload_len}"
            )

        raw_payload = data[HEADER_SIZE:total_frame_len]
        remaining = data[total_frame_len:]

        if payload_len == 0:
            payload = {}
        else:
            try:
                decoded_str = raw_payload.decode("utf-8")
            except UnicodeDecodeError as err:
                raise InvalidPayloadError(f"Payload is not valid UTF-8: {err}") from err

            try:
                payload = json.loads(decoded_str)
            except json.JSONDecodeError as err:
                raise InvalidPayloadError(f"Payload is not valid JSON: {err}") from err

        return cls(msg_type=msg_type, payload=payload, version=version), remaining

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
        exact: bool = True,
    ) -> PulseFrame:
        """Parse a frame from bytes.

        If exact is True, raises InvalidPayloadError if extra trailing bytes are present.
        """
        frame, remaining = cls.deserialize(data, max_payload_size=max_payload_size)
        if exact and remaining:
            raise InvalidPayloadError(f"Extraneous {len(remaining)} bytes after complete frame")
        return frame


def read_frame(
    sock: socket.socket,
    max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
) -> PulseFrame | None:
    """Read and decode a single PulseFrame from a stream socket.

    Handles partial socket reads across both header and payload.

    Returns:
        PulseFrame if successfully read, or None if peer cleanly disconnected
        before any frame bytes were received.

    Raises:
        IncompleteFrameError: If the socket closes mid-header or mid-payload.
        InvalidMagicError: If magic is not 'PULS'.
        InvalidVersionError: If version is unsupported.
        InvalidMessageTypeError: If message type is unrecognized.
        PayloadTooLargeError: If payload length exceeds max_payload_size.
        InvalidPayloadError: If payload is not valid UTF-8 JSON.
        ConnectionClosedError: If an underlying socket error occurs.
    """
    header_bytes = bytearray()
    while len(header_bytes) < HEADER_SIZE:
        try:
            chunk = sock.recv(HEADER_SIZE - len(header_bytes))
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as err:
            if len(header_bytes) == 0:
                return None
            raise ConnectionClosedError(f"Socket error reading frame header: {err}") from err

        if not chunk:
            if len(header_bytes) == 0:
                return None
            raise IncompleteFrameError(
                f"Connection closed after {len(header_bytes)} bytes of header (expected {HEADER_SIZE})"
            )
        header_bytes.extend(chunk)

    magic, version, msg_type_raw, payload_len = struct.unpack(
        HEADER_FORMAT, bytes(header_bytes)
    )

    if magic != MAGIC:
        raise InvalidMagicError(f"Invalid magic identifier: {magic!r}, expected {MAGIC!r}")

    if version != VERSION:
        raise InvalidVersionError(
            f"Unsupported protocol version: {version:#04x}, expected {VERSION:#04x}"
        )

    try:
        msg_type = MessageType(msg_type_raw)
    except ValueError as err:
        raise InvalidMessageTypeError(f"Unknown message type: {msg_type_raw:#04x}") from err

    if payload_len > max_payload_size:
        raise PayloadTooLargeError(
            f"Payload length {payload_len} exceeds maximum limit of {max_payload_size}"
        )

    payload_bytes = bytearray()
    while len(payload_bytes) < payload_len:
        try:
            chunk = sock.recv(payload_len - len(payload_bytes))
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError) as err:
            raise ConnectionClosedError(f"Socket error reading frame payload: {err}") from err

        if not chunk:
            raise IncompleteFrameError(
                f"Connection closed after {len(payload_bytes)} bytes of payload (expected {payload_len})"
            )
        payload_bytes.extend(chunk)

    if payload_len == 0:
        payload = {}
    else:
        try:
            decoded_text = payload_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise InvalidPayloadError(f"Payload is not valid UTF-8: {err}") from err

        try:
            payload = json.loads(decoded_text)
        except json.JSONDecodeError as err:
            raise InvalidPayloadError(f"Payload is not valid JSON: {err}") from err

    return PulseFrame(msg_type=msg_type, payload=payload, version=version)


def write_frame(
    sock: socket.socket,
    frame: PulseFrame,
    max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
) -> None:
    """Serialize and write a PulseFrame to a stream socket, handling partial socket writes.

    Raises:
        ConnectionClosedError: If socket closes before the entire frame is sent.
        FrameError: If frame serialization fails.
    """
    data = frame.serialize(max_payload_size=max_payload_size)
    write_raw(sock, data)


def write_raw(sock: socket.socket, data: bytes) -> None:
    """Write raw bytes to a stream socket, looping to handle partial writes."""
    total_sent = 0
    total_len = len(data)
    while total_sent < total_len:
        try:
            sent = sock.send(data[total_sent:])
        except (ConnectionResetError, BrokenPipeError, OSError) as err:
            raise ConnectionClosedError(f"Socket error writing to peer: {err}") from err

        if sent == 0:
            raise ConnectionClosedError("Socket closed by peer during write")
        total_sent += sent
