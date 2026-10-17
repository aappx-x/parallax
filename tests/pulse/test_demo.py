"""Tests for the command-line demo and CLI entry points."""

import sys
from unittest.mock import patch
import pytest

from parallax.pulse.client import main as client_cli_main
from parallax.pulse.demo import main as demo_cli_main, run_demo_suite
from parallax.pulse.server import PulseServer


class TestDemoSuite:
    """Verifies that the command-line flaw demonstration executes cleanly."""

    def test_demo_suite_self_contained_both_modes(self) -> None:
        exit_code = run_demo_suite(mode="both")
        assert exit_code == 0

    def test_demo_suite_vulnerable_mode_only(self) -> None:
        exit_code = run_demo_suite(mode="vulnerable")
        assert exit_code == 0

    def test_demo_suite_corrected_mode_only(self) -> None:
        exit_code = run_demo_suite(mode="corrected")
        assert exit_code == 0

    def test_demo_suite_against_existing_vulnerable_server(self) -> None:
        with PulseServer(host="127.0.0.1", port=0, vulnerable=True) as server:
            exit_code = run_demo_suite(host="127.0.0.1", port=server.port)
            assert exit_code == 0

    def test_demo_suite_against_existing_corrected_server(self) -> None:
        with PulseServer(host="127.0.0.1", port=0, vulnerable=False) as server:
            exit_code = run_demo_suite(host="127.0.0.1", port=server.port)
            assert exit_code == 0


class TestClientCLI:
    """Tests command-line client invocation."""

    @pytest.fixture
    def active_server(self):
        server = PulseServer(host="127.0.0.1", port=0, vulnerable=True)
        server.start()
        yield server
        server.stop()

    def test_client_cli_hello_and_status(
        self, active_server: PulseServer, capsys: pytest.CaptureFixture
    ) -> None:
        test_args = ["client.py", "--port", str(active_server.port), "hello"]
        with patch.object(sys, "argv", test_args):
            ret = client_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "STATUS" in captured.out
        assert "ready" in captured.out

        test_args = ["client.py", "--port", str(active_server.port), "status"]
        with patch.object(sys, "argv", test_args):
            ret = client_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "STATUS" in captured.out
        assert "ok" in captured.out

    def test_client_cli_auth_and_diag(
        self, active_server: PulseServer, capsys: pytest.CaptureFixture
    ) -> None:
        # Invalid auth
        test_args = [
            "client.py",
            "--port",
            str(active_server.port),
            "auth",
            "--username",
            "svc-pulse",
            "--password",
            "wrongpass",
        ]
        with patch.object(sys, "argv", test_args):
            ret = client_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Authentication Failed" in captured.out

        # On a new standalone connection without prior auth, read-diag is rejected with 403
        test_args = [
            "client.py",
            "--port",
            str(active_server.port),
            "read-diag",
            "--section",
            "system_config",
        ]
        with patch.object(sys, "argv", test_args):
            ret = client_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Authentication required" in captured.out
        assert "403" in captured.out

    def test_client_cli_demo_subcommand(
        self, active_server: PulseServer, capsys: pytest.CaptureFixture
    ) -> None:
        test_args = ["client.py", "--port", str(active_server.port), "demo"]
        with patch.object(sys, "argv", test_args):
            ret = client_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "VULNERABILITY CONFIRMED" in captured.out

    def test_demo_cli_entrypoint(self, capsys: pytest.CaptureFixture) -> None:
        test_args = ["demo.py", "--mode", "vulnerable"]
        with patch.object(sys, "argv", test_args):
            ret = demo_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "State machine flaw confirmed" in captured.out


class TestUnifiedCLI:
    """Tests python -m parallax.pulse unified CLI dispatch."""

    def test_unified_cli_demo(self, capsys: pytest.CaptureFixture) -> None:
        from parallax.pulse.__main__ import main as unified_cli_main

        test_args = ["pulse", "demo", "--mode", "both"]
        with patch.object(sys, "argv", test_args):
            ret = unified_cli_main()
            assert ret == 0
        captured = capsys.readouterr()
        assert "Demonstration completed successfully" in captured.out

    def test_unified_cli_client_hello(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from parallax.pulse.__main__ import main as unified_cli_main

        with PulseServer(host="127.0.0.1", port=0) as server:
            test_args = ["pulse", "client", "--port", str(server.port), "hello"]
            with patch.object(sys, "argv", test_args):
                ret = unified_cli_main()
                assert ret == 0
            captured = capsys.readouterr()
            assert "STATUS" in captured.out
            assert "ready" in captured.out
