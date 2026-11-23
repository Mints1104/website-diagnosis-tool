"""Check a URL repeatedly and keep the results in SQLite, so slow or failing checks can be
told apart from one-off network hiccups."""

import math
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import median
from typing import Callable

from diagnosis import DiagnosisResult, diagnose, parse_url

DEFAULT_DB = "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id          INTEGER PRIMARY KEY,
    url         TEXT NOT NULL,     -- normalised, e.g. "https://example.com/"
    checked_at  TEXT NOT NULL,     -- ISO 8601 in UTC
    ok          INTEGER NOT NULL,  -- 1 if every step worked and the status was below 400
    failed_step TEXT,              -- "DNS", "TCP", "TLS", "HTTP" or NULL
    error       TEXT,
    status_code INTEGER,
    dns_ms REAL, tcp_ms REAL, tls_ms REAL, http_ms REAL,
    total_ms    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS checks_url_time ON checks (url, checked_at);
"""


def connect(path: str = DEFAULT_DB) -> sqlite3.Connection:
    """Open (or create) the history database."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row  # rows can be read by column name
    conn.executescript(_SCHEMA)
    return conn


def is_up(result: DiagnosisResult) -> bool:
    return result.http is not None and result.http.status_code is not None and result.http.status_code < 400


def record(conn: sqlite3.Connection, result: DiagnosisResult, now: datetime | None = None) -> None:
    """Save one diagnosis."""
    now = now or datetime.now(timezone.utc)
    failed_step, error = None, None
    steps = {"DNS": result.dns, "TCP": result.tcp, "TLS": result.tls, "HTTP": result.http}
    for name, step in steps.items():
        if step is not None and step.error:
            failed_step, error = name, step.error
            break
    if failed_step is None and not is_up(result):
        failed_step, error = "HTTP", f"HTTP {result.http.status_code} {result.http.reason}"

    def ms(step):
        return step.duration_ms if step is not None else None

    # "?" placeholders let sqlite3 insert the values safely (no SQL injection from URLs)
    conn.execute(
        "INSERT INTO checks (url, checked_at, ok, failed_step, error, status_code,"
        " dns_ms, tcp_ms, tls_ms, http_ms, total_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(result.url), now.isoformat(timespec="seconds"), int(is_up(result)), failed_step, error,
            result.http.status_code if result.http else None,
            ms(result.dns), ms(result.tcp), ms(result.tls), ms(result.http), result.total_ms,
        ),
    )
    conn.commit()


def monitored_urls(conn: sqlite3.Connection) -> list[str]:
    return [row["url"] for row in conn.execute("SELECT DISTINCT url FROM checks ORDER BY url")]


def history(conn: sqlite3.Connection, url: str, limit: int | None = None) -> list[dict]:
    """The most recent checks for a URL, oldest first. `url` may be in any form parse_url accepts."""
    url = str(parse_url(url))
    sql = "SELECT * FROM checks WHERE url = ? ORDER BY checked_at DESC, id DESC"
    params: tuple = (url,)
    if limit is not None:
        sql += " LIMIT ?"
        params += (limit,)
    rows = [dict(row) for row in conn.execute(sql, params)]
    rows.reverse()
    return rows


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile: the smallest value with at least `pct`% of values at or below it."""
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


@dataclass
class Summary:
    checks: int
    failures: int
    uptime_pct: float
    median_ms: float | None  # over successful checks only; None if there were none
    p95_ms: float | None


def summarize(rows: list[dict]) -> Summary:
    """Uptime and response-time statistics for rows from history()."""
    if not rows:
        return Summary(checks=0, failures=0, uptime_pct=0.0, median_ms=None, p95_ms=None)
    times = [row["total_ms"] for row in rows if row["ok"]]
    failures = len(rows) - len(times)
    return Summary(
        checks=len(rows),
        failures=failures,
        uptime_pct=100 * len(times) / len(rows),
        median_ms=median(times) if times else None,
        p95_ms=percentile(times, 95) if times else None,
    )


def run_checks(
    conn: sqlite3.Connection,
    url: str,
    count: int,
    interval: float,
    on_result: Callable[[int, DiagnosisResult], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Diagnose `url` `count` times, `interval` seconds apart, saving each result.

    `count` of 0 means run until interrupted (Ctrl+C).
    `on_result(i, result)` is called after each check, e.g. to print or show progress.
    Raises ValueError if the URL is invalid.
    """
    parse_url(url)  # fail fast on an invalid URL
    i = 0
    while count == 0 or i < count:
        result = diagnose(url)
        record(conn, result)
        i += 1
        if on_result:
            on_result(i, result)
        if count == 0 or i < count:
            sleep(interval)
