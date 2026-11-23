"""Tests for follow_redirects. diagnose() is replaced with a fake so no network is used."""

import pytest

import diagnosis
from diagnosis import DiagnosisResult, DnsResult, HttpResult, follow_redirects, parse_url


def fake_site(routes: dict[str, tuple[int, str | None]]):
    """Build a fake diagnose() that answers each URL with (status, Location) from `routes`."""
    calls = []

    def fake_diagnose(url: str) -> DiagnosisResult:
        parsed = parse_url(url)
        calls.append(str(parsed))
        status, location = routes[str(parsed)]
        return DiagnosisResult(
            url=parsed,
            dns=DnsResult(ip="192.0.2.1", duration_ms=1.0),
            http=HttpResult(status_code=status, duration_ms=10.0, location=location),
        )

    return fake_diagnose, calls


def test_no_redirect(monkeypatch):
    fake, calls = fake_site({"https://a.test/": (200, None)})
    monkeypatch.setattr(diagnosis, "diagnose", fake)
    chain = follow_redirects("a.test")
    assert len(chain.hops) == 1
    assert chain.warning is None
    assert chain.total_ms == 11.0


def test_follows_absolute_and_relative_redirects(monkeypatch):
    fake, calls = fake_site({
        "http://a.test/": (301, "https://a.test/"),
        "https://a.test/": (302, "/login?next=%2F"),  # relative Location
        "https://a.test/login?next=%2F": (200, None),
    })
    monkeypatch.setattr(diagnosis, "diagnose", fake)
    chain = follow_redirects("http://a.test")
    assert calls == ["http://a.test/", "https://a.test/", "https://a.test/login?next=%2F"]
    assert chain.final.http.status_code == 200
    assert chain.warning is None


def test_detects_loop_without_requesting_again(monkeypatch):
    fake, calls = fake_site({
        "https://a.test/": (301, "https://b.test/"),
        "https://b.test/": (301, "https://a.test/"),
    })
    monkeypatch.setattr(diagnosis, "diagnose", fake)
    chain = follow_redirects("a.test")
    assert len(chain.hops) == 2
    assert len(calls) == 2
    assert "loop" in chain.warning


def test_stops_after_max_redirects(monkeypatch):
    routes = {f"https://a.test/{i}": (302, f"/{i + 1}") for i in range(10)}
    fake, calls = fake_site(routes)
    monkeypatch.setattr(diagnosis, "diagnose", fake)
    chain = follow_redirects("a.test/0", max_redirects=3)
    assert len(chain.hops) == 4  # the original request plus 3 redirects
    assert "Stopped after 3" in chain.warning


def test_redirect_to_unsupported_scheme(monkeypatch):
    fake, calls = fake_site({"https://a.test/": (302, "ftp://files.test/")})
    monkeypatch.setattr(diagnosis, "diagnose", fake)
    chain = follow_redirects("a.test")
    assert len(chain.hops) == 1
    assert "Can't follow" in chain.warning


def test_invalid_first_url_raises():
    with pytest.raises(ValueError):
        follow_redirects("")
