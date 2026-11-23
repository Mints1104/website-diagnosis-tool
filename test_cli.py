"""Tests for cli.py. Network calls are replaced with fakes."""

import json
import socket
from datetime import datetime, timezone

import pytest

import cli
import monitor
from diagnosis import (
    CertInfo,
    DiagnosisResult,
    DnsResult,
    HttpResult,
    RedirectChain,
    TcpResult,
    TlsResult,
    parse_url,
)


def fake_result(status=200, dns_error=None) -> DiagnosisResult:
    url = parse_url("example.com")
    if dns_error:
        return DiagnosisResult(url=url, dns=DnsResult(ip=None, duration_ms=5.0, error=dns_error))
    cert = CertInfo(
        subject="example.com", issuer="Test CA",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        days_remaining=40, alt_names=["example.com"],
    )
    return DiagnosisResult(
        url=url,
        dns=DnsResult(ip="192.0.2.1", duration_ms=1.0, all_ips=["192.0.2.1"]),
        tcp=TcpResult(sock=socket.socket(), duration_ms=2.0),  # a real (unconnected) socket
        tls=TlsResult(sock=None, duration_ms=3.0, version="TLSv1.3", cipher="X", cert=cert),
        http=HttpResult(status_code=status, duration_ms=4.0, reason="OK",
                        headers={"x-content-type-options": "nosniff"}),
    )


@pytest.fixture
def fake_site(monkeypatch):
    def use(result):
        monkeypatch.setattr(cli, "follow_redirects", lambda url: RedirectChain(hops=[result]))
        monkeypatch.setattr(cli, "diagnose", lambda url: result)
        monkeypatch.setattr(monitor, "diagnose", lambda url: result)
    return use


def test_check_text_output_and_exit_code(fake_site, capsys):
    fake_site(fake_result())
    assert cli.main(["check", "example.com"]) == 0
    out = capsys.readouterr().out
    assert "TLSv1.3, cert expires 2027-01-01 (40 days)" in out
    assert "200 OK" in out
    assert "Security headers: 1/6 pass" in out


def test_check_down_exits_1(fake_site, capsys):
    fake_site(fake_result(dns_error="Domain not found"))
    assert cli.main(["check", "example.com"]) == 1
    assert "FAILED: Domain not found" in capsys.readouterr().out


def test_check_http_error_exits_1(fake_site, capsys):
    fake_site(fake_result(status=500))
    assert cli.main(["check", "example.com", "--no-follow"]) == 1


def test_check_json(fake_site, capsys):
    fake_site(fake_result())
    cli.main(["check", "example.com", "--json"])
    data = json.loads(capsys.readouterr().out)  # must be valid JSON despite the socket
    hop = data["hops"][0]
    assert data["up"] is True
    assert "sock" not in hop["tcp"]
    assert hop["url"]["href"] == "https://example.com/"
    assert hop["tls"]["cert"]["not_after"] == "2027-01-01T00:00:00+00:00"
    assert hop["total_ms"] == 10.0
    assert hop["dns"]["ip_version"] == "IPv4"
    assert len(data["security_headers"]) == 6


def test_invalid_url_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "ftp://example.com"])
    assert exc.value.code == 2


def test_monitor_and_history(fake_site, capsys, tmp_path, monkeypatch):
    fake_site(fake_result())
    monkeypatch.setattr(monitor.time, "sleep", lambda s: None)
    db = str(tmp_path / "h.db")
    assert cli.main(["monitor", "example.com", "--count", "2", "--interval", "0", "--db", db]) == 0
    assert "2 checks, 100.0% up" in capsys.readouterr().out

    cli.main(["history", "example.com", "--json", "--db", db])
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 2
    assert rows[0]["status_code"] == 200
