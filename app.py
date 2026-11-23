"""Streamlit page for diagnosing a website: enter a URL, see how long each step takes."""

import streamlit as st

from diagnosis import diagnose

st.title("Website diagnosis")
st.write("Times each step of loading a website: DNS lookup, TCP connect, TLS handshake and HTTP request.")

url = st.text_input("URL", placeholder="example.com")

if st.button("Diagnose"):
    try:
        with st.spinner("Diagnosing..."):
            result = diagnose(url)
    except ValueError as e:
        st.error(f"Invalid URL: {e}")
        st.stop()

    steps = [
        ("DNS", result.dns),
        ("TCP", result.tcp),
        ("TLS", result.tls),
        ("HTTP", result.http),
    ]

    rows = []
    failed = None  # (step name, error) of the first step that failed
    for name, step in steps:
        if step is None:
            rows.append({"Step": name, "Time (ms)": "", "Status": "⏭️ Not reached"})
        elif step.error:
            rows.append({"Step": name, "Time (ms)": f"{step.duration_ms:.1f}", "Status": "❌ Failed"})
            failed = (name, step.error, step.error_detail)
        else:
            rows.append({"Step": name, "Time (ms)": f"{step.duration_ms:.1f}", "Status": "✅ OK"})

    if failed:
        st.error(f"Failed at {failed[0]}: {failed[1]}")
        if failed[2]:
            with st.expander("Technical details"):
                st.code(failed[2], language=None)
    else:
        st.success(f"HTTP {result.http.status_code} {result.http.reason}")
        if result.http.location:
            st.info(f"Redirects to {result.http.location}")

    st.dataframe(rows, hide_index=True)
    st.metric("Total time", f"{result.total_ms:.1f} ms")

    if result.tls and result.tls.cert:
        cert = result.tls.cert
        st.subheader("Certificate")
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
        )
