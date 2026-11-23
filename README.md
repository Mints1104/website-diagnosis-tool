# Website Diagnosis Tool

A small tool that takes a URL and times each step of loading it: **DNS lookup → TCP connect → TLS handshake → HTTP request**. It shows how long each step took and, if the site is broken, which step failed and why.

## Why

I built this to learn what actually happens when a browser loads a website: how DNS turns a name into an IP address, how a TCP connection is set up, what a TLS handshake does and how certificates are checked, and what an HTTP request and response look like.

A diagnosis tool was a good fit for that, because to time each step separately I had to understand where one step ends and the next begins.

Each step uses Python's built-in `socket` and `ssl` modules directly, and I checked the results against tools like `nslookup`, `ping` and `curl`. My research for each step is in [RESEARCH.md](RESEARCH.md).

## Features

- **Step-by-step timing** of DNS, TCP, TLS and HTTP (time to first byte), with plain-English explanations when a step fails (e.g. "The site's certificate has expired") and the raw error kept for debugging.
- **Redirects followed** hop by hop (each hop is a full new diagnosis), with loop detection and a 5-redirect limit.
- **Certificate details**: issuer, validity dates, days remaining (with a warning under 14 days), covered hostnames, TLS version and cipher.
- **Security headers check** on the final page: HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options / `frame-ancestors`, Referrer-Policy and Permissions-Policy.
- **Monitoring**: check a URL repeatedly, store results in SQLite (`history.db`), and see uptime, median and 95th-percentile response times and a per-step chart.
- **URLs**: `http://` and `https://`, custom ports, query strings, IPv4 and IPv6, and non-ASCII URLs (IDNA hostnames, percent-encoded paths).
- **Web page** (Streamlit) and **command line** (with JSON output and script-friendly exit codes).

## How to run it

Requires Python 3.10 or newer (I used Python 3.13.1 on Windows 10).

```bash
pip install -r requirements.txt

# Web page (Diagnose and Monitor tabs)
streamlit run app.py

# Command line
python cli.py check example.com                  # step-by-step report, follows redirects
python cli.py check example.com --json           # full result as JSON
python cli.py check example.com --no-follow      # stop at the first response
python cli.py monitor example.com --interval 60  # check every 60 s until Ctrl+C
python cli.py history example.com                # saved checks and uptime summary

# Automated tests (no internet needed)
python -m pytest -v
```

`python cli.py check` exits with `0` if the site is up (final status below 400), `1` if it is down, and `2` for invalid input, so it can be used in scripts and scheduled tasks.

Diagnosing real sites needs an internet connection; the automated tests don't.

## How it works

- **`diagnosis.py`** contains the diagnosis logic and has no UI code:
  - `parse_url` validates the input and returns the scheme, ASCII hostname, port and encoded path + query. `https://` is added if no scheme is given.
  - `resolve_dns` looks up IPv4 and IPv6 addresses with `socket.getaddrinfo` and uses the first one (the operating system's preferred order).
  - `connect_tcp` opens a TCP connection with a 5 second timeout.
  - `tls_handshake` does the TLS handshake (skipped for `http://`), verifies the certificate against the hostname and reads its details.
  - `http_get` sends an HTTP/1.1 `GET` request, times until the first byte of the response, and reads the status line and headers.
  - `diagnose` runs the steps in order and stops at the first one that fails. `follow_redirects` calls `diagnose` for each hop of a redirect chain.
  - `friendly_error` turns exceptions into short explanations, and `check_security_headers` grades the response headers.
- **`monitor.py`** stores each check in SQLite and calculates uptime and response-time statistics.
- **`app.py`** is the Streamlit page, and **`cli.py`** is the command-line interface. Both only call the functions above.

Each step is timed with `time.perf_counter()`.

**Error handling:**

- **Invalid input** (e.g. an empty URL or `ftp://`) raises a `ValueError`, shown as "Invalid URL" on the page and as a usage error (exit code 2) on the command line.
- **Network failures** (DNS not found, connection timeout, bad certificate) are returned in the result with a friendly `error` and the raw `error_detail`, instead of being raised.

## Testing

The automated tests run in about 2 seconds without the internet:

- `test_diagnosis.py`: URL parsing (ports, IPv6 literals, IDNA, percent-encoding, invalid input).
- `test_network.py`: the network steps. `http_get` runs over a real `socket.socketpair()` with canned responses; `diagnose` runs end to end against a local `http.server` on `127.0.0.1` and `::1`; DNS, timeout and certificate failures are simulated with `unittest.mock`.
- `test_errors.py`, `test_certificate.py`, `test_security_headers.py`, `test_redirects.py`, `test_monitor.py` and `test_cli.py` cover the other features.

Results were also checked by hand against real sites, including ones built to fail (`doesnotexist.invalid`, an unreachable IP, and badssl.com's expired, self-signed, wrong-host and untrusted-root certificates), and compared with `curl` (timings, status codes, redirect chains and headers). Earlier test output is in RESEARCH.md.

## Known limitations

- Only the first resolved address is tried; there is no fallback to the next address (as browsers do with "Happy Eyeballs") if it fails.
- Certificate revocation isn't checked (Python's default `ssl` settings don't check revocation lists, see RESEARCH.md (11)).
- Each redirect hop opens a new connection, even when it goes to the same host.
- The header read has no size limit, so a server that sends headers forever would only be stopped by the 5 second timeout between chunks.
- Monitoring from the web page runs while the page is open; for long-running monitoring use `python cli.py monitor`.

## Roadmap

- Try each resolved address in turn, and compare IPv4 and IPv6 timings.
- Alerts (e.g. email or a webhook) when a monitored site goes down or its certificate is close to expiry.
- Monitor several URLs at once.
- Use a virtual environment instead of installing packages globally.

## Other documents

- [RESEARCH.md](RESEARCH.md): what I needed to learn for each step, my sources, experiments and what didn't work.
