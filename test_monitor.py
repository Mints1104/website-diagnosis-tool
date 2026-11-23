"""Tests for monitor.py, using an in-memory database and a fake diagnose()."""

from datetime import datetime, timedelta, timezone

import pytest

import monitor
from diagnosis import DiagnosisResult, DnsResult, HttpResult, TcpResult, parse_url


def result(url="example.com", status=200, dns_error=None, total=100.0) -> DiagnosisResult:
    parsed = parse_url(url)
    if dns_error:
        return DiagnosisResult(url=parsed, dns=DnsResult(ip=None, duration_ms=total, error=dns_error))
    return DiagnosisResult(
        url=parsed,
        dns=DnsResult(ip="192.0.2.1", duration_ms=10.0),
        tcp=TcpResult(sock=None, duration_ms=20.0),
        http=HttpResult(status_code=status, duration_ms=total - 30.0, reason="X"),
    )


@pytest.fixture
def conn():
    return monitor.connect(":memory:")


def test_record_and_history(conn):
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monitor.record(conn, result(total=100), now=t0)
    monitor.record(conn, result(dns_error="Domain not found"), now=t0 + timedelta(minutes=1))
    monitor.record(conn, result(status=503), now=t0 + timedelta(minutes=2))

    rows = monitor.history(conn, "https://example.com")
    assert [r["ok"] for r in rows] == [1, 0, 0]  # oldest first
    assert rows[0]["total_ms"] == 100
    assert rows[0]["tls_ms"] is None  # step didn't run
    assert rows[1]["failed_step"] == "DNS"
    assert rows[1]["error"] == "Domain not found"
    assert rows[2]["failed_step"] == "HTTP"
    assert rows[2]["status_code"] == 503


def test_history_limit_keeps_most_recent(conn):
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(5):
        monitor.record(conn, result(total=100 + i), now=t0 + timedelta(minutes=i))
    rows = monitor.history(conn, "example.com", limit=2)
    assert [r["total_ms"] for r in rows] == [103, 104]


def test_monitored_urls(conn):
    monitor.record(conn, result("b.test"))
    monitor.record(conn, result("a.test"))
    monitor.record(conn, result("a.test"))
    assert monitor.monitored_urls(conn) == ["https://a.test/", "https://b.test/"]


def test_percentile():
    values = list(range(1, 101))  # 1..100
    assert monitor.percentile(values, 95) == 95
    assert monitor.percentile(values, 50) == 50
    assert monitor.percentile([7], 95) == 7


def test_summarize():
    rows = [{"ok": 1, "total_ms": t} for t in (100, 200, 300)] + [{"ok": 0, "total_ms": 5000}]
    s = monitor.summarize(rows)
    assert s.checks == 4
    assert s.failures == 1
    assert s.uptime_pct == 75
    assert s.median_ms == 200  # failed checks are left out of the timings
    assert s.p95_ms == 300


def test_summarize_empty_and_all_failed():
    assert monitor.summarize([]).checks == 0
    s = monitor.summarize([{"ok": 0, "total_ms": 1}])
    assert s.uptime_pct == 0
    assert s.median_ms is None


def test_run_checks(conn, monkeypatch):
    monkeypatch.setattr(monitor, "diagnose", lambda url: result(url))
    sleeps, seen = [], []
    monitor.run_checks(conn, "example.com", count=3, interval=60,
                       on_result=lambda i, r: seen.append(i), sleep=sleeps.append)
    assert seen == [1, 2, 3]
    assert sleeps == [60, 60]  # no sleep after the last check
    assert len(monitor.history(conn, "example.com")) == 3


def test_run_checks_invalid_url(conn):
    with pytest.raises(ValueError):
        monitor.run_checks(conn, "", count=1, interval=0)
