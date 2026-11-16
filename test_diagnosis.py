"""Automated tests for parse_url. The network steps were tested manually (see RESEARCH.md)."""

import pytest

from diagnosis import parse_url


def test_full_url():
    parsed = parse_url("https://example.com/page?x=1")
    assert parsed.hostname == "example.com"
    assert parsed.path == "/page"


def test_adds_https_when_scheme_missing():
    parsed = parse_url("example.com")
    assert parsed.hostname == "example.com"
    assert parsed.path == "/"


def test_strips_whitespace():
    assert parse_url("  example.com  ").hostname == "example.com"


def test_lowercases_hostname():
    assert parse_url("EXAMPLE.COM").hostname == "example.com"


def test_port_is_not_part_of_hostname():
    parsed = parse_url("https://example.com:8443/x")
    assert parsed.hostname == "example.com"
    assert parsed.path == "/x"


def test_empty_url_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_url("")


def test_whitespace_only_url_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_url("   ")


def test_http_url_raises():
    with pytest.raises(ValueError, match="Only https"):
        parse_url("http://example.com")


def test_url_without_hostname_raises():
    with pytest.raises(ValueError, match="no hostname"):
        parse_url("https://")
