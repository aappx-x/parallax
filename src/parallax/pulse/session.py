"""Session state tracking for PULSE/1 daemon connections."""

from dataclasses import dataclass, field
import time


@dataclass
class PulseSession:
    """Tracks state and authorization status for an active client connection."""

    client_address: tuple[str, int]
    authenticated: bool = False
    auth_attempted: bool = False
    auth_failed: bool = False
    username: str | None = None
    hello_received: bool = False
    closed: bool = False
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    request_count: int = 0
