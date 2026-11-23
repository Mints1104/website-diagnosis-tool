"""Tests for check_security_headers."""

from diagnosis import check_security_headers

GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def statuses(headers, scheme="https"):
    return {c.header: c.status for c in check_security_headers(headers, scheme)}


def test_all_good():
    assert set(statuses(GOOD).values()) == {"pass"}


def test_all_missing():
    result = statuses({})
    assert result["Strict-Transport-Security"] == "missing"
    assert result["Content-Security-Policy"] == "missing"
    assert result["X-Frame-Options"] == "missing"
    assert len(result) == 6


def test_hsts_not_applicable_over_http():
    assert statuses(GOOD, scheme="http")["Strict-Transport-Security"] == "n/a"


def test_short_hsts_warns():
    checks = check_security_headers({"strict-transport-security": "max-age=300"}, "https")
    hsts = checks[0]
    assert hsts.status == "warn"
    assert "300" in hsts.note


def test_quoted_hsts_max_age():
    assert statuses({"strict-transport-security": 'max-age="31536000"'})["Strict-Transport-Security"] == "pass"


def test_x_frame_options_without_csp():
    assert statuses({"x-frame-options": "SAMEORIGIN"})["X-Frame-Options"] == "pass"
    assert statuses({"x-frame-options": "ALLOW-FROM x"})["X-Frame-Options"] == "warn"


def test_wrong_x_content_type_options():
    assert statuses({"x-content-type-options": "yes"})["X-Content-Type-Options"] == "warn"


def test_unsafe_referrer_policy():
    assert statuses({"referrer-policy": "unsafe-url"})["Referrer-Policy"] == "warn"
