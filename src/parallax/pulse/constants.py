"""PULSE/1 protocol constants and enumeration definitions."""

from enum import IntEnum
import struct

# 4-byte magic identifier: ASCII 'PULS' (0x50 0x55 0x4c 0x53)
MAGIC: bytes = b"PULS"

# 1-byte protocol version: 0x01
VERSION: int = 0x01

# Binary header format:
# - 4 bytes magic (!4s)
# - 1 byte version (B)
# - 1 byte message type (B)
# - 2 bytes unsigned big-endian payload length (H)
HEADER_FORMAT: str = "!4sBBH"
HEADER_SIZE: int = struct.calcsize(HEADER_FORMAT)  # 8 bytes

# Default network settings
DEFAULT_PORT: int = 7741
DEFAULT_MAX_PAYLOAD_SIZE: int = 65535  # Max representable in 16-bit unsigned integer


class MessageType(IntEnum):
    """Agreed PULSE/1 protocol message types."""

    HELLO = 0x01      # Client initiates session handshake
    AUTH = 0x02       # Client submits credentials
    STATUS = 0x03     # Operational telemetry query / status response
    READ_DIAG = 0x04  # Diagnostic query request / response
    CLOSE = 0x05      # Graceful connection termination
    ERROR = 0x06      # Error condition notification
