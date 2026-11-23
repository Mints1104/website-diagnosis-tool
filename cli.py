"""Command-line interface.

    python cli.py check example.com [--json] [--no-follow]
    python cli.py monitor example.com [--interval 60] [--count 0] [--db history.db]
    python cli.py history example.com [--limit 20] [--db history.db]

`check` exits with 0 if the site is up (final status below 400) and 1 if not, so it can be
used in scripts. Invalid arguments exit with 2.
"""

import argparse
import dataclasses
import json
import socket
import sys
from contextlib import closing
from datetime import datetime

import monitor
from diagnosis import (
    DiagnosisResult,
    RedirectChain,
    check_security_headers,
    diagnose,
    follow_redirects,
)


def to_jsonable(obj):
    """Convert results to plain dicts/lists for json.dumps, leaving out open sockets."""
    if dataclasses.is_dataclass(obj):
        data = {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj) if f.name != "sock"}
        # Include computed properties that are useful in the output
        for prop in ("total_ms", "ip_version", "expires_soon"):
            if hasattr(type(obj), prop):
                data[prop] = to_jsonable(getattr(obj, prop))
        if hasattr(obj, "scheme") and hasattr(obj, "host_header"):  # ParsedUrl
            data["href"] = str(obj)
        return data
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_jsonable(value) for key, value in obj.items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, socket.socket):
        return None
    return obj


def chain_to_json(chain: RedirectChain) -> dict:
    data = to_jsonable(chain)
    final = chain.final
    data["up"] = monitor.is_up(final)
    if final.http and final.http.status_code:
        data["security_headers"] = to_jsonable(check_security_headers(final.http.headers, final.url.scheme))
    return data


def format_result(result: DiagnosisResult) -> list[str]:
    lines = [f"{result.url}" + (f"  ({result.dns.ip}, {result.dns.ip_version})" if result.dns.ip else "")]
    for name, step in [("DNS", result.dns), ("TCP", result.tcp), ("TLS", result.tls), ("HTTP", result.http)]:
        if step is None:
            note = "skipped (http://)" if name == "TLS" and result.url.scheme == "http" else "not reached"
            lines.append(f"  {name:<5} {'':>9}  {note}")
            continue
        time_text = f"{step.duration_ms:7.1f} ms"
        if step.error:
            lines.append(f"  {name:<5} {time_text}  FAILED: {step.error}")
        elif name == "TLS":
            cert = step.cert
            extra = f", cert expires {cert.not_after:%Y-%m-%d} ({cert.days_remaining} days)" if cert else ""
            lines.append(f"  {name:<5} {time_text}  {step.version}{extra}")
        elif name == "HTTP":
            redirect = f" -> {step.location}" if step.location else ""
            lines.append(f"  {name:<5} {time_text}  {step.status_code} {step.reason}{redirect}")
        else:
            lines.append(f"  {name:<5} {time_text}  OK")
    lines.append(f"  Total {result.total_ms:7.1f} ms")
    return lines


def format_chain(chain: RedirectChain) -> str:
    lines = []
    for i, hop in enumerate(chain.hops):
        if i:
            lines.append("")
        lines.extend(format_result(hop))
    if len(chain.hops) > 1:
        lines.append(f"\n{len(chain.hops) - 1} redirect(s), {chain.total_ms:.1f} ms in total")
    if chain.warning:
        lines.append(f"Warning: {chain.warning}")
    final = chain.final
    if final.http and final.http.status_code and not final.http.location:
        checks = check_security_headers(final.http.headers, final.url.scheme)
        applicable = [c for c in checks if c.status != "n/a"]
        passed = [c for c in applicable if c.status == "pass"]
        lines.append(f"Security headers: {len(passed)}/{len(applicable)} pass")
        for c in applicable:
            if c.status != "pass":
                lines.append(f"  {c.status}: {c.header} - {c.note}")
    return "\n".join(lines)


def cmd_check(args) -> int:
    chain = follow_redirects(args.url) if args.follow else RedirectChain(hops=[diagnose(args.url)])
    print(json.dumps(chain_to_json(chain), indent=2) if args.json else format_chain(chain))
    return 0 if monitor.is_up(chain.final) else 1


def cmd_monitor(args) -> int:
    # closing() closes the database when the block ends, even after Ctrl+C
    with closing(monitor.connect(args.db)) as conn:
        return _monitor(conn, args)


def _monitor(conn, args) -> int:
    def on_result(i, result):
        stamp = datetime.now().strftime("%H:%M:%S")
        if monitor.is_up(result):
            print(f"{stamp}  #{i}  up    {result.total_ms:7.1f} ms  HTTP {result.http.status_code}", flush=True)
        else:
            failed = next((s for s in (result.dns, result.tcp, result.tls, result.http) if s and s.error), None)
            reason = failed.error if failed else f"HTTP {result.http.status_code} {result.http.reason}"
            print(f"{stamp}  #{i}  DOWN  {result.total_ms:7.1f} ms  {reason}", flush=True)

    forever = " (Ctrl+C to stop)" if args.count == 0 else ""
    print(f"Checking {args.url} every {args.interval:g} s, saving to {args.db}{forever}")
    try:
        monitor.run_checks(conn, args.url, count=args.count, interval=args.interval, on_result=on_result)
    except KeyboardInterrupt:
        print("Stopped.")
    print_summary(monitor.history(conn, args.url))
    return 0


def print_summary(rows: list[dict]) -> None:
    s = monitor.summarize(rows)
    if not s.checks:
        print("No checks recorded for this URL.")
        return
    timing = f", median {s.median_ms:.1f} ms, p95 {s.p95_ms:.1f} ms" if s.median_ms is not None else ""
    print(f"{s.checks} checks, {s.uptime_pct:.1f}% up ({s.failures} failed){timing}")


def cmd_history(args) -> int:
    with closing(monitor.connect(args.db)) as conn:
        rows = monitor.history(conn, args.url, limit=args.limit)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        state = "up  " if row["ok"] else "DOWN"
        detail = f"HTTP {row['status_code']}" if row["ok"] else f"{row['failed_step']}: {row['error']}"
        print(f"{row['checked_at']}  {state}  {row['total_ms']:7.1f} ms  {detail}")
    print_summary(rows)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Time each step of loading a website.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="diagnose a URL once")
    check.add_argument("url")
    check.add_argument("--json", action="store_true", help="print the full result as JSON")
    check.add_argument("--no-follow", dest="follow", action="store_false", help="don't follow redirects")
    check.set_defaults(func=cmd_check)

    mon = sub.add_parser("monitor", help="check a URL repeatedly and save the results")
    mon.add_argument("url")
    mon.add_argument("--interval", type=float, default=60, help="seconds between checks (default 60)")
    mon.add_argument("--count", type=int, default=0, help="number of checks; 0 runs until Ctrl+C (default)")
    mon.add_argument("--db", default=monitor.DEFAULT_DB, help=f"database file (default {monitor.DEFAULT_DB})")
    mon.set_defaults(func=cmd_monitor)

    hist = sub.add_parser("history", help="show saved checks for a URL")
    hist.add_argument("url")
    hist.add_argument("--limit", type=int, default=20, help="most recent checks to show (default 20)")
    hist.add_argument("--json", action="store_true")
    hist.add_argument("--db", default=monitor.DEFAULT_DB)
    hist.set_defaults(func=cmd_history)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ValueError as e:  # invalid URL
        parser.error(str(e))  # prints usage and exits with code 2


if __name__ == "__main__":
    sys.exit(main())
