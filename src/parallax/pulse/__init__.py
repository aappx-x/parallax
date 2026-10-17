"""PULSE/1 protocol implementation module."""

from parallax.pulse.constants import (
    DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_PORT,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    MessageType,
)
from parallax.pulse.exceptions import (
    AuthenticationError,
    ConnectionClosedError,
    FrameError,
    IncompleteFrameError,
    InvalidMagicError,
    InvalidMessageTypeError,
    InvalidPayloadError,
    InvalidVersionError,
    PayloadTooLargeError,
    ProtocolStateError,
    PulseError,
)
from parallax.pulse.frame import (
    PulseFrame,
    read_frame,
    write_frame,
    write_raw,
)

__all__ = [
    "DEFAULT_MAX_PAYLOAD_SIZE",
    "DEFAULT_PORT",
    "HEADER_FORMAT",
    "HEADER_SIZE",
    "MAGIC",
    "VERSION",
    "MessageType",
    "AuthenticationError",
    "ConnectionClosedError",
    "FrameError",
    "IncompleteFrameError",
    "InvalidMagicError",
    "InvalidMessageTypeError",
    "InvalidPayloadError",
    "InvalidVersionError",
    "PayloadTooLargeError",
    "ProtocolStateError",
    "PulseError",
    "PulseFrame",
    "read_frame",
    "write_frame",
    "write_raw",
]
