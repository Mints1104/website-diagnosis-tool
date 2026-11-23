"""Tests for friendly_error: each exception type maps to a plain-English message."""

import socket
import ssl

from diagnosis import friendly_error, raw_error


def cert_error(code: int) -> ssl.SSLCertVerificationError:
    exc = ssl.SSLCertVerificationError("certificate verify failed")
    exc.verify_code = code
    exc.verify_message = "some openssl message"
    return exc


def test_dns_not_found():
    exc = socket.gaierror(11001, "getaddrinfo failed")
    assert "Domain not found" in friendly_error(exc)


def test_dns_other_failure():
    exc = socket.gaierror(11002, "temporary failure")
    assert "DNS lookup failed" in friendly_error(exc)


def test_expired_certificate():
    assert "expired" in friendly_error(cert_error(10))


def test_self_signed_certificate():
    assert "self-signed" in friendly_error(cert_error(18))


def test_wrong_host_certificate():
    assert "different hostname" in friendly_error(cert_error(62))


def test_unknown_cert_code_includes_openssl_message():
    assert "some openssl message" in friendly_error(cert_error(999))


def test_timeout_mentions_duration():
    assert "after 5 s" in friendly_error(TimeoutError("timed out"), timeout=5.0)


def test_refused():
    assert "refused" in friendly_error(ConnectionRefusedError(10061, "refused"))


def test_unreachable():
    assert "unreachable" in friendly_error(OSError(10051, "unreachable"))


def test_unknown_exception_falls_back_to_raw_text():
    assert friendly_error(RuntimeError("boom")) == "RuntimeError: boom"


def test_raw_error():
    assert raw_error(ValueError("bad")) == "ValueError: bad"
