"""Streamlit page for diagnosing a website: enter a URL, see how long each step takes."""

import streamlit as st

from diagnosis import DiagnosisResult, RedirectChain, diagnose, follow_redirects


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


st.title("Website diagnosis")
st.write("Times each step of loading a website: DNS lookup, TCP connect, TLS handshake and HTTP request.")

url = st.text_input("URL", placeholder="example.com")
follow = st.checkbox("Follow redirects", value=True)

if st.button("Diagnose"):
    try:
        with st.spinner("Diagnosing..."):
            chain = follow_redirects(url) if follow else RedirectChain(hops=[diagnose(url)])
    except ValueError as e:
        st.error(f"Invalid URL: {e}")
        st.stop()
    show_chain(chain)
