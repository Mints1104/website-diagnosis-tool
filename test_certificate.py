"""Tests for parse_certificate, using a dict shaped like SSLSocket.getpeercert()'s output."""

from datetime import datetime, timezone

from diagnosis import parse_certificate

CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": (
        (("countryName", "US"),),
        (("organizationName", "SSL Corporation"),),
        (("commonName", "Cloudflare TLS Issuing ECC CA 3"),),
    ),
    "notBefore": "Sep 26 22:49:11 2026 GMT",
    "notAfter": "Dec 25 22:56:35 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"), ("IP Address", "1.2.3.4")),
}


def test_names():
    info = parse_certificate(CERT, now=datetime(2026, 11, 23, tzinfo=timezone.utc))
    assert info.subject == "example.com"
    assert info.issuer == "Cloudflare TLS Issuing ECC CA 3 (SSL Corporation)"
    assert info.alt_names == ["example.com", "*.example.com"]  # IP entries are skipped


def test_dates_are_utc():
    info = parse_certificate(CERT, now=datetime(2026, 11, 23, tzinfo=timezone.utc))
    assert info.not_after == datetime(2026, 12, 25, 22, 56, 35, tzinfo=timezone.utc)
    assert info.not_before.tzinfo == timezone.utc


def test_days_remaining_and_not_expiring_soon():
    info = parse_certificate(CERT, now=datetime(2026, 11, 23, tzinfo=timezone.utc))
    assert info.days_remaining == 32
    assert not info.expires_soon


def test_expires_soon():
    info = parse_certificate(CERT, now=datetime(2026, 12, 20, tzinfo=timezone.utc))
    assert info.days_remaining == 5
    assert info.expires_soon


def test_issuer_without_organization():
    cert = dict(CERT, issuer=((("commonName", "My CA"),),))
    assert parse_certificate(cert).issuer == "My CA"
