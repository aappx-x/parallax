"""Unified CLI entrypoint for running the PULSE/1 daemon, client, or vulnerability demo."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time

from parallax.pulse.constants import DEFAULT_PORT
from parallax.pulse.client import PulseClient
from parallax.pulse.demo import run_demo_suite
from parallax.pulse.exceptions import ConnectionClosedError
from parallax.pulse.server import PulseServer


def _run_server(args: argparse.Namespace) -> int:
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


def _run_client(args: argparse.Namespace) -> int:
    if not getattr(args, "action", None):
        print("Usage: python -m parallax.pulse client {hello,status,auth,read-diag,close} ...")
        return 1

    try:
        with PulseClient(host=args.host, port=args.port) as client:
            if args.action == "hello":
                resp = client.hello()
            elif args.action == "status":
                resp = client.status()
            elif args.action == "auth":
                resp = client.auth(username=args.username, password=args.password)
            elif args.action == "read-diag":
                resp = client.read_diag(section=args.section)
            elif args.action == "close":
                resp = client.close_session()
            else:
                print(f"Unknown action: {args.action}")
                return 1
            print(f"[{resp.msg_type.name}] {json.dumps(resp.payload, indent=2)}")
    except ConnectionClosedError as err:
        print(f"[!] Connection error: {err}", file=sys.stderr)
        return 1
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    return run_demo_suite(host=args.host, port=args.port, mode=args.mode)


def _run_verify(args: argparse.Namespace) -> int:
    from parallax.verify import run_verification

    return run_verification(host=args.host, verbose=args.verbose)


def main() -> int:
    parser = argparse.ArgumentParser(description="PULSE/1 protocol CLI suite.")
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # server subcommand
    server_parser = subparsers.add_parser("server", help="Run PULSE/1 TCP daemon")
    server_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    server_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port (default: {DEFAULT_PORT})")
    server_parser.add_argument("--vulnerable", action="store_true", help="Enable vulnerable authentication mode")
    server_parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # client subcommand
    client_parser = subparsers.add_parser("client", help="Run interactive client command")
    client_parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    client_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Target port (default: {DEFAULT_PORT})")
    client_sub = client_parser.add_subparsers(dest="action", help="Client action")
    client_sub.add_parser("hello", help="Send HELLO handshake")
    client_sub.add_parser("status", help="Query service STATUS")
    auth_p = client_sub.add_parser("auth", help="Authenticate with credentials")
    auth_p.add_argument("--username", "-u", default="", help="Username")
    auth_p.add_argument("--password", "-p", default="", help="Password")
    diag_p = client_sub.add_parser("read-diag", help="Read diagnostic telemetry")
    diag_p.add_argument("--section", "-s", default="system_config", help="Section name")
    client_sub.add_parser("close", help="Gracefully terminate session")

    # demo subcommand
    demo_parser = subparsers.add_parser("demo", help="Run authentication flaw demonstration")
    demo_parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    demo_parser.add_argument("--port", type=int, default=None, help="Port of running service (default: spawns local)")
    demo_parser.add_argument("--mode", choices=["both", "vulnerable", "corrected"], default="both", help="Demo mode")

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Run lab environment and protocol verification")
    verify_parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    verify_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Fallback compatibility flags if invoked directly without subcommand:
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--vulnerable", action="store_true")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    args = parser.parse_args()

    if args.subcommand == "server":
        return _run_server(args)
    elif args.subcommand == "client":
        return _run_client(args)
    elif args.subcommand == "demo":
        return _run_demo(args)
    elif args.subcommand == "verify":
        return _run_verify(args)
    else:
        # Default behavior: run server
        return _run_server(args)


if __name__ == "__main__":
    sys.exit(main())
