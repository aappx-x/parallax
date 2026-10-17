"""Tests for authentication state machine transitions in corrected and vulnerable modes."""

import pytest

from parallax.pulse.constants import MessageType
from parallax.pulse.client import PulseClient
from parallax.pulse.server import PulseServer


class TestCorrectedModeAuth:
    """Verifies that corrected mode strictly enforces authentication for diagnostics."""

    @pytest.fixture
    def corrected_server(self):
        server = PulseServer(
            host="127.0.0.1",
            port=0,
            vulnerable=False,
            credentials={"analyst": "GoodPass123!"},
        )
        server.start()
        yield server
        server.stop()

    def test_unauthenticated_read_diag_rejected(
        self, corrected_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=corrected_server.port) as client:
            resp = client.read_diag("system_config")
            assert resp.msg_type == MessageType.ERROR
            assert resp.payload.get("code") == 403
            assert "Authentication required" in resp.payload.get("error", "")

    def test_failed_auth_emits_error_and_rejects_subsequent_read_diag(
        self, corrected_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=corrected_server.port) as client:
            # Step 1: Submit invalid credentials
            auth_resp = client.auth(username="attacker", password="WrongPassword!")
            assert auth_resp.msg_type == MessageType.ERROR
            assert auth_resp.payload.get("code") == 401
            assert auth_resp.payload.get("error") == "Authentication Failed"

            # Step 2: Attempt READ_DIAG - must still be rejected in corrected mode
            diag_resp = client.read_diag("system_config")
            assert diag_resp.msg_type == MessageType.ERROR
            assert diag_resp.payload.get("code") == 403
            assert "Authentication required" in diag_resp.payload.get("error", "")

    def test_successful_auth_permits_read_diag(
        self, corrected_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=corrected_server.port) as client:
            auth_resp = client.auth(username="analyst", password="GoodPass123!")
            assert auth_resp.msg_type == MessageType.STATUS
            assert auth_resp.payload.get("status") == "authenticated"

            diag_resp = client.read_diag("system_config")
            assert diag_resp.msg_type == MessageType.READ_DIAG
            assert diag_resp.payload.get("section") == "system_config"
            assert diag_resp.payload.get("helper_path") == "/usr/local/bin/pulse-helper"

    def test_failed_auth_then_successful_auth(
        self, corrected_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=corrected_server.port) as client:
            # 1. Bad auth fails
            bad_auth = client.auth(username="analyst", password="WrongPassword")
            assert bad_auth.msg_type == MessageType.ERROR

            # 2. READ_DIAG fails
            denied = client.read_diag("system_config")
            assert denied.msg_type == MessageType.ERROR

            # 3. Good auth succeeds
            good_auth = client.auth(username="analyst", password="GoodPass123!")
            assert good_auth.msg_type == MessageType.STATUS

            # 4. READ_DIAG succeeds
            allowed = client.read_diag("system_config")
            assert allowed.msg_type == MessageType.READ_DIAG


class TestVulnerableModeAuth:
    """Verifies that vulnerable mode reproduces the scenario flaw.

    Flaw: When the attacker submits invalid credentials via AUTH, the server emits
    an ERROR frame ('Authentication Failed'). However, the state machine fails to set
    an authorization guard flag and fails to disconnect the session. The attacker
    immediately issues READ_DIAG, and the daemon erroneously processes the query.
    """

    @pytest.fixture
    def vulnerable_server(self):
        server = PulseServer(
            host="127.0.0.1",
            port=0,
            vulnerable=True,
            credentials={"pulse_admin": "ValidPass123!"},
        )
        server.start()
        yield server
        server.stop()

    def test_unauthenticated_read_diag_without_auth_attempt_is_rejected(
        self, vulnerable_server: PulseServer
    ) -> None:
        # Before any AUTH attempt, READ_DIAG is still rejected
        with PulseClient(host="127.0.0.1", port=vulnerable_server.port) as client:
            resp = client.read_diag("system_config")
            assert resp.msg_type == MessageType.ERROR
            assert resp.payload.get("code") == 403

    def test_vulnerability_flaw_read_diag_succeeds_after_failed_auth(
        self, vulnerable_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=vulnerable_server.port) as client:
            # Step 1: Attacker sends invalid credentials
            auth_resp = client.auth(username="svc-pulse", password="invalid_password")
            assert auth_resp.msg_type == MessageType.ERROR
            assert auth_resp.payload.get("code") == 401
            assert auth_resp.payload.get("error") == "Authentication Failed"

            # Step 2: Attacker immediately requests READ_DIAG
            diag_resp = client.read_diag("system_config")

            # Flaw verification: READ_DIAG succeeds!
            assert diag_resp.msg_type == MessageType.READ_DIAG
            payload = diag_resp.payload
            assert payload.get("section") == "system_config"
            assert payload.get("helper_path") == "/usr/local/bin/pulse-helper"
            assert payload.get("encryption_passphrase_fragment") == "meridian-vault-2024-fragA"
            assert payload.get("diagnostic_ticket") == "DIAG-TKT-7741-ALPHA"

    def test_full_scenario_breach_session_sequence(
        self, vulnerable_server: PulseServer
    ) -> None:
        """Simulates the exact 4-step sequence from SCENARIO_DESIGN.md:

        1. TCP connect
        2. AUTH (failed)
        3. READ_DIAG (leaked configuration)
        4. CLOSE (session teardown)
        """
        with PulseClient(host="127.0.0.1", port=vulnerable_server.port) as client:
            # Step 2: AUTH frame with invalid credentials
            auth_frame = client.auth(username="198.51.100.24-user", password="bad")
            assert auth_frame.msg_type == MessageType.ERROR
            assert auth_frame.payload.get("error") == "Authentication Failed"

            # Step 3: READ_DIAG query frame
            diag_frame = client.read_diag("system_config")
            assert diag_frame.msg_type == MessageType.READ_DIAG
            assert diag_frame.payload["helper_path"] == "/usr/local/bin/pulse-helper"

            # Step 4: CLOSE frame
            close_frame = client.close_session()
            assert close_frame.msg_type == MessageType.CLOSE

    def test_successful_auth_in_vulnerable_mode_also_succeeds(
        self, vulnerable_server: PulseServer
    ) -> None:
        with PulseClient(host="127.0.0.1", port=vulnerable_server.port) as client:
            auth_resp = client.auth(username="pulse_admin", password="ValidPass123!")
            assert auth_resp.msg_type == MessageType.STATUS
            assert auth_resp.payload.get("status") == "authenticated"

            diag_resp = client.read_diag("system_config")
            assert diag_resp.msg_type == MessageType.READ_DIAG
            assert diag_resp.payload.get("section") == "system_config"
