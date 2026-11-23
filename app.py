"""Streamlit page for diagnosing a website: enter a URL, see how long each step takes."""

import pandas as pd
import streamlit as st

import monitor
from diagnosis import (
    DiagnosisResult,
    RedirectChain,
    check_security_headers,
    diagnose,
    follow_redirects,
    parse_url,
)


def step_rows(result: DiagnosisResult) -> list[dict]:
    rows = []
    for name, step in [("DNS", result.dns), ("TCP", result.tcp), ("TLS", result.tls), ("HTTP", result.http)]:
        if step is None and name == "TLS" and result.url.scheme == "http":
            rows.append({"Step": name, "Time (ms)": "", "Status": "➖ Skipped (http://)"})
        elif step is None:
            rows.append({"Step": name, "Time (ms)": "", "Status": "⏭️ Not reached"})
        elif step.error:
            rows.append({"Step": name, "Time (ms)": f"{step.duration_ms:.1f}", "Status": "❌ Failed"})
        else:
            rows.append({"Step": name, "Time (ms)": f"{step.duration_ms:.1f}", "Status": "✅ OK"})
    return rows


def first_failure(result: DiagnosisResult):
    """(step name, step result) of the step that failed, or None."""
    for name, step in [("DNS", result.dns), ("TCP", result.tcp), ("TLS", result.tls), ("HTTP", result.http)]:
        if step is not None and step.error:
            return name, step
    return None


def show_result(result: DiagnosisResult, key: str) -> None:
    """Show one diagnosis: outcome, step timings and certificate details."""
    if result.dns.ip:
        others = len(result.dns.all_ips) - 1
        extra = f" (+{others} more)" if others else ""
        st.caption(f"Connected to {result.dns.ip} ({result.dns.ip_version}){extra}")

    failure = first_failure(result)
    if failure:
        name, step = failure
        st.error(f"Failed at {name}: {step.error}")
        if step.error_detail:
            with st.expander("Technical details"):
                st.code(step.error_detail, language=None)
    else:
        status = f"HTTP {result.http.status_code} {result.http.reason}"
        if result.http.status_code >= 400:  # the connection worked, but the server reported an error
            st.warning(status)
        elif result.http.location:
            st.info(f"{status}, redirects to {result.http.location}")
        else:
            st.success(status)

    st.dataframe(step_rows(result), hide_index=True, key=f"steps-{key}")
    st.metric("Time", f"{result.total_ms:.1f} ms")

    if result.tls and result.tls.cert:
        cert = result.tls.cert
        st.markdown("**Certificate**")
        if cert.expires_soon:
            st.warning(f"The certificate expires in {cert.days_remaining} days")
        st.dataframe(
            [
                {"Field": "Issued to", "Value": cert.subject},
                {"Field": "Issued by", "Value": cert.issuer},
                {"Field": "Valid from", "Value": f"{cert.not_before:%Y-%m-%d}"},
                {"Field": "Expires", "Value": f"{cert.not_after:%Y-%m-%d} ({cert.days_remaining} days left)"},
                {"Field": "Covers", "Value": ", ".join(cert.alt_names)},
                {"Field": "Protocol", "Value": f"{result.tls.version}, {result.tls.cipher}"},
            ],
            hide_index=True,
            key=f"cert-{key}",
        )

    # Security headers matter on the page the browser ends up on, so skip them for redirects
    if result.http and result.http.status_code and not result.http.location:
        checks = check_security_headers(result.http.headers, result.url.scheme)
        passed = sum(c.status == "pass" for c in checks)
        applicable = sum(c.status != "n/a" for c in checks)
        st.markdown(f"**Security headers** ({passed}/{applicable} pass)")
        icons = {"pass": "✅", "warn": "⚠️", "missing": "❌", "n/a": "➖"}
        st.dataframe(
            [
                {"Header": c.header, "Status": f"{icons[c.status]} {c.status}", "Note": c.note, "Value": c.value or ""}
                for c in checks
            ],
            hide_index=True,
            key=f"headers-{key}",
        )
        with st.expander("All response headers"):
            st.code("\n".join(f"{name}: {value}" for name, value in result.http.headers.items()), language=None)


def show_chain(chain: RedirectChain) -> None:
    """Show a summary of every hop, then each hop's details (the last one expanded)."""
    if len(chain.hops) > 1:
        st.subheader("Redirect chain")
        st.dataframe(
            [
                {
                    "#": i + 1,
                    "URL": str(hop.url),
                    "Status": hop.http.status_code if hop.http and hop.http.status_code else "failed",
                    "Time (ms)": f"{hop.total_ms:.1f}",
                }
                for i, hop in enumerate(chain.hops)
            ],
            hide_index=True,
        )
        st.metric("Total time (all hops)", f"{chain.total_ms:.1f} ms")
    if chain.warning:
        st.warning(chain.warning)

    for i, hop in enumerate(chain.hops):
        is_last = i == len(chain.hops) - 1
        if len(chain.hops) == 1:
            st.caption(f"Diagnosing {hop.url}")
            show_result(hop, key=str(i))
        else:
            with st.expander(f"{i + 1}. {hop.url}", expanded=is_last):
                show_result(hop, key=str(i))


def diagnose_tab() -> None:
    url = st.text_input("URL", placeholder="example.com")
    follow = st.checkbox("Follow redirects", value=True)

    if st.button("Diagnose"):
        try:
            with st.spinner("Diagnosing..."):
                chain = follow_redirects(url) if follow else RedirectChain(hops=[diagnose(url)])
        except ValueError as e:
            st.error(f"Invalid URL: {e}")
            return
        show_chain(chain)


def monitor_tab() -> None:
    st.write(
        "Check a URL several times and keep the results, so a one-off slow check can be told apart "
        "from a real problem. For long-running monitoring use `python cli.py monitor URL`."
    )
    conn = monitor.connect()

    url = st.text_input("URL to monitor", placeholder="example.com", key="monitor-url")
    col1, col2 = st.columns(2)
    count = col1.number_input("Number of checks", min_value=1, max_value=100, value=5)
    interval = col2.number_input("Seconds between checks", min_value=0, max_value=300, value=5)

    if st.button("Run checks"):
        progress = st.progress(0.0, text="Starting...")

        def on_result(i, result):
            text = f"Check {i}/{count}: {'up' if monitor.is_up(result) else 'DOWN'}, {result.total_ms:.0f} ms"
            progress.progress(i / count, text=text)

        try:
            monitor.run_checks(conn, url, count=int(count), interval=interval, on_result=on_result)
        except ValueError as e:
            st.error(f"Invalid URL: {e}")
        else:
            # Select the URL just checked in the history below (set before the selectbox is created)
            st.session_state["history-url"] = str(parse_url(url))

    urls = monitor.monitored_urls(conn)
    if not urls:
        st.info("No checks recorded yet.")
        return

    st.subheader("History")
    selected = st.selectbox("URL", urls, key="history-url")
    rows = monitor.history(conn, selected, limit=500)
    summary = monitor.summarize(rows)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Checks", summary.checks)
    c2.metric("Uptime", f"{summary.uptime_pct:.1f}%")
    c3.metric("Median", f"{summary.median_ms:.0f} ms" if summary.median_ms is not None else "–")
    c4.metric("95th percentile", f"{summary.p95_ms:.0f} ms" if summary.p95_ms is not None else "–")

    df = pd.DataFrame(rows)
    df["checked_at"] = pd.to_datetime(df["checked_at"])
    ok = df[df["ok"] == 1].set_index("checked_at")
    if not ok.empty:
        st.markdown("**Time per step (successful checks)**")
        steps = ok[["dns_ms", "tcp_ms", "tls_ms", "http_ms"]].fillna(0)
        st.area_chart(steps.rename(columns={"dns_ms": "DNS", "tcp_ms": "TCP", "tls_ms": "TLS", "http_ms": "HTTP"}),
                      y_label="ms", stack=True)  # stacked, so the top edge is the total time

    failures = df[df["ok"] == 0]
    if not failures.empty:
        st.markdown("**Failed checks**")
        st.dataframe(failures[["checked_at", "failed_step", "error"]], hide_index=True)


st.title("Website diagnosis")
st.write("Times each step of loading a website: DNS lookup, TCP connect, TLS handshake and HTTP request.")

tab_diagnose, tab_monitor = st.tabs(["Diagnose", "Monitor"])
with tab_diagnose:
    diagnose_tab()
with tab_monitor:
    monitor_tab()
