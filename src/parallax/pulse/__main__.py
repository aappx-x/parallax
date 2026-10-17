"""CLI entrypoint for running the PULSE/1 daemon standalone."""

import argparse
import logging
import sys
import time

from parallax.pulse.constants import DEFAULT_PORT
from parallax.pulse.server import PulseServer


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PULSE/1 reference telemetry daemon."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--vulnerable",
        action="store_true",
        help="Enable vulnerable authentication state machine mode for scenario training",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    mode_str = "VULNERABLE (scenario flaw active)" if args.vulnerable else "CORRECTED (secure)"
    print(f"[*] Starting PULSE/1 daemon on {args.host}:{args.port} [{mode_str}]")

    server = PulseServer(host=args.host, port=args.port, vulnerable=args.vulnerable)
    server.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down PULSE/1 daemon...")
    finally:
        server.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
