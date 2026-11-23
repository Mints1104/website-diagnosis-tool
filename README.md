# Website Diagnosis Tool

A small tool that takes a URL and times each step of loading it: **DNS lookup → TCP connect → TLS handshake → HTTP request**. It shows how long each step took and, if the site is broken, which step failed and why.

## Why

I built this to learn what actually happens when a browser loads a website: how DNS turns a name into an IP address, how a TCP connection is set up, what a TLS handshake does and how certificates are checked, and what an HTTP request and response look like.

A diagnosis tool was a good fit for that, because to time each step separately I had to understand where one step ends and the next begins.

Each step uses Python's built-in `socket` and `ssl` modules directly, and I checked the results against tools like `nslookup`, `ping` and `curl`. My research for each step is in [RESEARCH.md](RESEARCH.md).

## How to run it

Requires Python 3.10 or newer (I used Python 3.13.1 on Windows 10).

```bash
pip install -r requirements.txt

# Web page
streamlit run app.py

# Automated tests
python -m pytest -v

# Manual check: runs diagnose() on a working URL, a redirect and one failure at each step
python diagnosis.py
```

As the tool makes real network requests, it requires an internet connection.

## How it works

The code is split into two files:

- **`diagnosis.py`** contains all the logic and has no UI code:
  - `parse_url` checks the input and extracts the hostname and path (adds `https://` if missing, rejects anything that isn't `https://`).
  - `resolve_dns` looks up the IPv4 address with `socket.getaddrinfo`.
  - `connect_tcp` opens a TCP connection to port 443 with a 5 second timeout.
  - `tls_handshake` does the TLS handshake and verifies the certificate against the hostname.
  - `http_get` sends an HTTP/1.1 `GET` request and times until the first byte of the response. It records the status code and the redirect target, but doesn't follow redirects.
  - `diagnose` runs the steps in order and stops at the first one that fails. It returns a `DiagnosisResult` with one field per step (`None` if the step was never reached) and a `total_ms` property.
- **`app.py`** is the Streamlit page. It calls `diagnose()` and shows a table of each step's time and status, the error if a step failed, and the total time.

Each step is timed with `time.perf_counter()`.

**Error handling:**

- **Invalid input** (e.g. an empty URL or `http://`) raises a `ValueError` and the page shows it as "Invalid URL".
- **Network failures** (DNS not found, connection timeout, bad certificate) are returned in the result with an `error` message instead of being raised.

## Testing

- `parse_url` has automated tests in `test_diagnosis.py` (valid inputs, and inputs that should be rejected).
- The network steps were tested manually against real sites, including sites built to fail: `doesnotexist.invalid` (DNS), an unreachable IP (TCP timeout) and badssl.com's expired, self-signed and wrong-host certificates (TLS). Where possible, I compared my timings and results against `curl`. The output from each test is in RESEARCH.md.

I didn't write automated tests for the network steps, because tests against real sites are slow and depend on the internet, and mocking sockets was more than I had time to learn properly.

## Known limitations

- Only `https://` URLs on port 443. A custom port in the URL is ignored.
- The query string (`?x=1`) is dropped from the request.
- IPv4 only.
- Redirects are reported, not followed.
- Certificate revocation isn't checked (Python's default `ssl` settings don't check revocation lists, see RESEARCH.md (11)).
- Error messages are the raw Python error text.
- Each diagnosis is a single run, so one slow result can be a one-off network hiccup.
- URLs with non-ASCII characters (e.g. `example.com/café`) are reported as an error instead of being encoded properly.
- The header read has no size limit, so a server that sends headers forever without finishing would only be stopped by the 5 second timeout between chunks.

## Roadmap

- **Monitoring:** check a URL repeatedly and show the history, so one-off slow results can be told apart from real problems.
- Friendlier error messages, e.g. "This site's certificate has expired".
- Support query strings, custom ports, `http://` and IPv6.
- Properly encode non-ASCII URLs (IDNA for hostnames, percent-encoding for paths).
- Show certificate details (issuer, expiry date).
- Automated tests for the network steps using mocked sockets.
- Use a virtual environment instead of installing packages globally.

## Other documents

- [RESEARCH.md](RESEARCH.md): what I needed to learn for each step, my sources, experiments and what didn't work.
