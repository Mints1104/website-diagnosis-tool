"""Automated tests for parse_url."""

import pytest

from diagnosis import parse_url


def test_full_url_keeps_query():
    parsed = parse_url("https://example.com/page?x=1&y=2#frag")
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.port == 443
    assert parsed.path == "/page?x=1&y=2"  # the fragment is never sent to the server


def test_adds_https_when_scheme_missing():
    parsed = parse_url("example.com")
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.path == "/"


def test_strips_whitespace():
    assert parse_url("  example.com  ").hostname == "example.com"


def test_lowercases_hostname():
    assert parse_url("EXAMPLE.COM").hostname == "example.com"


def test_custom_port():
    parsed = parse_url("https://example.com:8443/x")
    assert parsed.hostname == "example.com"
    assert parsed.port == 8443
    assert parsed.host_header == "example.com:8443"


def test_default_port_left_out_of_host_header():
    assert parse_url("https://example.com:443/").host_header == "example.com"


def test_http_url():
    parsed = parse_url("http://example.com")
    assert parsed.scheme == "http"
    assert parsed.port == 80


def test_ipv6_literal():
    parsed = parse_url("http://[::1]:8080/")
    assert parsed.hostname == "::1"
    assert parsed.port == 8080
    assert parsed.host_header == "[::1]:8080"
    assert str(parsed) == "http://[::1]:8080/"


def test_idna_hostname():
    assert parse_url("bücher.de").hostname == "xn--bcher-kva.de"


def test_non_ascii_path_is_percent_encoded():
    assert parse_url("example.com/café?q=ü").path == "/caf%C3%A9?q=%C3%BC"


def test_already_encoded_path_is_not_double_encoded():
    assert parse_url("example.com/a%20b").path == "/a%20b"


def test_space_in_path_is_encoded():
    assert parse_url("example.com/a b").path == "/a%20b"


def test_empty_url_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_url("")


def test_whitespace_only_url_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_url("   ")


def test_unsupported_scheme_raises():
    with pytest.raises(ValueError, match="Only http"):
        parse_url("ftp://example.com")


def test_url_without_hostname_raises():
    with pytest.raises(ValueError, match="no hostname"):
        parse_url("https://")


def test_port_out_of_range_raises():
    with pytest.raises(ValueError):
        parse_url("https://example.com:99999")
