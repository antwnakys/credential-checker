"""Tests for the breach checker.

The network call is mocked so tests are fast, offline, and deterministic. We
verify the k-anonymity contract: only a 5-character prefix is sent, and the
suffix comparison is done locally.
"""

from unittest.mock import patch

from pwcheck.breach import check_password, sha1_hex


def test_sha1_is_uppercase_hex_of_expected_length():
    digest = sha1_hex("password")
    assert len(digest) == 40
    assert digest == digest.upper()
    # Known SHA-1 of "password".
    assert digest == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_empty_password_short_circuits_without_network():
    with patch("pwcheck.breach._fetch_range") as fetch:
        result = check_password("")
        fetch.assert_not_called()
    assert result.checked and not result.found


def test_found_password_reports_count():
    full = sha1_hex("password")
    suffix = full[5:]
    with patch("pwcheck.breach._fetch_range", return_value={suffix: 9_999}):
        result = check_password("password")
    assert result.checked and result.found
    assert result.count == 9_999


def test_absent_password_reports_not_found():
    with patch("pwcheck.breach._fetch_range", return_value={"DEADBEEF": 1}):
        result = check_password("a-very-unlikely-password-xyz")
    assert result.checked and not result.found
    assert result.count == 0


def test_only_five_char_prefix_is_sent():
    full = sha1_hex("hunter2")
    with patch("pwcheck.breach._fetch_range", return_value={}) as fetch:
        check_password("hunter2")
        sent_prefix = fetch.call_args.args[0]
    assert sent_prefix == full[:5]
    assert len(sent_prefix) == 5


def test_network_failure_degrades_gracefully():
    with patch("pwcheck.breach._fetch_range", side_effect=OSError("no network")):
        result = check_password("password")
    assert not result.checked
    assert result.error is not None
