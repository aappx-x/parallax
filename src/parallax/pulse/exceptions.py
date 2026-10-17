"""Exception hierarchy for the PULSE/1 protocol."""


class PulseError(Exception):
    """Base exception for all PULSE/1 protocol errors."""


class FrameError(PulseError):
    """Base exception for binary framing errors."""


class InvalidMagicError(FrameError):
    """Raised when the 4-byte magic identifier does not match 'PULS'."""


class InvalidVersionError(FrameError):
    """Raised when the protocol version byte is unsupported."""


class InvalidMessageTypeError(FrameError):
    """Raised when the message type byte is unrecognized."""


class PayloadTooLargeError(FrameError):
    """Raised when a frame payload length exceeds the allowed limit."""


class IncompleteFrameError(FrameError):
    """Raised when a frame buffer or stream has fewer bytes than required."""


class InvalidPayloadError(FrameError):
    """Raised when a frame payload is not valid UTF-8 JSON."""


class ConnectionClosedError(PulseError):
    """Raised when a socket connection closes unexpectedly during I/O."""


class ProtocolStateError(PulseError):
    """Raised when a message is received in an incompatible session state."""


class AuthenticationError(PulseError):
    """Raised when an operation is rejected due to authentication requirements."""
