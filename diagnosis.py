"""Diagnose a website connection step by step: DNS, TCP, TLS, HTTP."""

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse


# OpenSSL verify codes for the certificate problems people most often hit.
# Full list: https://docs.openssl.org/master/man1/openssl-verification-options/#diagnostics
_CERT_ERRORS = {
    9: "The site's certificate is not valid yet (check your computer's clock)",
    10: "The site's certificate has expired",
    18: "The site uses a self-signed certificate, which browsers don't trust",
    19: "The site's certificate chain ends in a self-signed root that isn't trusted",
    20: "The site's certificate was issued by an authority this computer doesn't trust",
    21: "The site's certificate chain is incomplete (a missing intermediate certificate)",
    23: "The site's certificate has been revoked",
    62: "The site's certificate is for a different hostname",
}

# Windows (WSA*) and POSIX errno values for "no route to the host or network".
_UNREACHABLE_ERRNOS = {10051, 10065, 101, 113, 51, 65}


def friendly_error(exc: BaseException, timeout: float | None = None) -> str:
    """Turn a low-level exception into a short, plain-English explanation."""
    if isinstance(exc, socket.gaierror):
        # 11001 (WSAHOST_NOT_FOUND) / 11004 (WSANO_DATA) on Windows; EAI_NONAME elsewhere
        if exc.errno in (11001, 11004, socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)):
            return "Domain not found: there is no DNS record for this hostname"
        return "DNS lookup failed (your DNS server may be unreachable)"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return _CERT_ERRORS.get(exc.verify_code, f"The site's certificate failed verification ({exc.verify_message})")
    if isinstance(exc, ssl.SSLError):
        return "The TLS handshake failed (the server may not support a secure protocol version this client accepts)"
    # TimeoutError is checked before OSError, since it's a subclass of it
    if isinstance(exc, TimeoutError):
        after = f" after {timeout:g} s" if timeout else ""
        return f"Timed out{after}: the server didn't answer (it may be down, or a firewall is dropping traffic)"
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused: the host is up but nothing is listening on that port"
    if isinstance(exc, ConnectionResetError):
        return "The server reset the connection"
    if isinstance(exc, UnicodeError):
        return "The URL contains characters that can't be sent in a request"
    if isinstance(exc, OSError) and exc.errno in _UNREACHABLE_ERRNOS:
        return "Network unreachable: there is no route to this host"
    return f"{type(exc).__name__}: {exc}"


def raw_error(exc: BaseException) -> str:
    """The raw exception text, kept alongside the friendly message for debugging."""
    return f"{type(exc).__name__}: {exc}"


DEFAULT_PORTS = {"http": 80, "https": 443}

# Characters left unescaped in a path or query (RFC 3986 "pchar" plus "/" and "?").
# "%" is included so an already-encoded URL isn't encoded twice.
_URL_SAFE = "/?:@!$&'()*+,;=-._~%"


@dataclass
class ParsedUrl:
    scheme: str  # "http" or "https"
    hostname: str  # ASCII form: lowercased and IDNA-encoded ("bücher.de" -> "xn--bcher-kva.de")
    port: int  # from the URL, or 80 / 443 by default
    path: str  # percent-encoded path plus query string, e.g. "/caf%C3%A9?x=1"

    @property
    def host_header(self) -> str:
        """The Host header value: brackets around IPv6 literals, and the port only if non-default."""
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        if self.port != DEFAULT_PORTS[self.scheme]:
            host += f":{self.port}"
        return host

    def __str__(self) -> str:
        return f"{self.scheme}://{self.host_header}{self.path}"


def parse_url(url: str) -> ParsedUrl:
    """Check a user-entered URL and extract the parts the diagnosis needs.

    Raises ValueError if the URL can't be diagnosed.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL is empty")
    # Without a scheme, urlparse treats "example.com" as a path and finds no hostname
    if "://" not in url:
        url = "https://" + url

    # urlparse lowercases the scheme and hostname, and strips the brackets from IPv6 literals
    parts = urlparse(url)
    if parts.scheme not in DEFAULT_PORTS:
        raise ValueError(f"Only http:// and https:// URLs are supported, got {parts.scheme}://")
    if not parts.hostname:
        raise ValueError("URL has no hostname")
    try:
        port = parts.port or DEFAULT_PORTS[parts.scheme]  # .port raises ValueError if out of range
        # Non-ASCII hostnames are sent as punycode (IDNA); ASCII ones pass through unchanged
        hostname = parts.hostname.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError(f"Hostname can't be encoded: {e}") from None

    # quote() percent-encodes everything else, encoding non-ASCII characters as UTF-8 first
    path = quote(parts.path or "/", safe=_URL_SAFE)
    if parts.query:
        path += "?" + quote(parts.query, safe=_URL_SAFE)
    return ParsedUrl(scheme=parts.scheme, hostname=hostname, port=port, path=path)


@dataclass
class DnsResult:
    ip: str | None  # the address the next step connects to; None if the lookup failed
    duration_ms: float
    error: str | None = None  # None if the lookup succeeded
    error_detail: str | None = None  # raw exception text behind `error`
    all_ips: list[str] = field(default_factory=list)  # every address returned, in order

    @property
    def ip_version(self) -> str | None:
        return None if self.ip is None else ("IPv6" if ":" in self.ip else "IPv4")


def resolve_dns(hostname: str, port: int = 443) -> DnsResult:
    """Look up the IPv4 and IPv6 addresses of a hostname and time how long it takes.

    The first address is used. It follows the operating system's preference order
    (RFC 6724), and Windows leaves out IPv6 addresses when the machine has no IPv6 route.
    A failed lookup is returned as a result with `error` set, not raised.
    """
    start = time.perf_counter()
    try:
        # AF_UNSPEC returns both IPv4 and IPv6 results.
        # SOCK_STREAM avoids duplicate entries per socket type.
        results = socket.getaddrinfo(
            hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        duration_ms = (time.perf_counter() - start) * 1000
        return DnsResult(ip=None, duration_ms=duration_ms,
                         error=friendly_error(e), error_detail=raw_error(e))
    duration_ms = (time.perf_counter() - start) * 1000

    # Each result is (family, type, proto, canonname, sockaddr). sockaddr is (ip, port) for
    # IPv4 and (ip, port, flowinfo, scope_id) for IPv6, so the IP is first either way.
    ips = list(dict.fromkeys(r[4][0] for r in results))  # de-duplicate, keeping the order
    return DnsResult(ip=ips[0], duration_ms=duration_ms, all_ips=ips)


@dataclass
class TcpResult:
    sock: socket.socket | None  # the open connection; None if connecting failed
    duration_ms: float
    error: str | None = None  # None if the connection succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def connect_tcp(ip: str, port: int = 443, timeout: float = 5.0) -> TcpResult:
    """Open a TCP connection to an IP and port and time how long it takes.

    On success the socket is left open for the TLS step; the caller must close it.
    A failed connection is returned as a result with `error` set, not raised.
    """
    start = time.perf_counter()
    try:
        # Returns once the three-way handshake (SYN, SYN-ACK, ACK) is done.
        # The timeout stays set on the socket, so the TLS and HTTP steps use it too.
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:  # covers refused, timed out and unreachable
        duration_ms = (time.perf_counter() - start) * 1000
        return TcpResult(sock=None, duration_ms=duration_ms,
                         error=friendly_error(e, timeout), error_detail=raw_error(e))
    duration_ms = (time.perf_counter() - start) * 1000

    return TcpResult(sock=sock, duration_ms=duration_ms)


EXPIRY_WARNING_DAYS = 14  # warn when a certificate expires within this many days


@dataclass
class CertInfo:
    subject: str  # the certificate's common name, e.g. "example.com"
    issuer: str  # who signed it, e.g. "Cloudflare TLS Issuing ECC CA 3 (SSL Corporation)"
    not_before: datetime  # UTC
    not_after: datetime  # UTC
    days_remaining: int  # whole days until not_after; negative once expired
    alt_names: list[str] = field(default_factory=list)  # hostnames the certificate covers

    @property
    def expires_soon(self) -> bool:
        return self.days_remaining <= EXPIRY_WARNING_DAYS


def _cert_name(name: tuple) -> dict[str, str]:
    """getpeercert() stores names as ((("commonName", "x"),), ...); flatten to a dict."""
    return {key: value for rdn in name for key, value in rdn}


def parse_certificate(cert: dict, now: datetime | None = None) -> CertInfo:
    """Turn the dict from SSLSocket.getpeercert() into a CertInfo."""
    now = now or datetime.now(timezone.utc)
    subject = _cert_name(cert.get("subject", ()))
    issuer = _cert_name(cert.get("issuer", ()))
    issuer_text = issuer.get("commonName", "unknown")
    if "organizationName" in issuer:
        issuer_text += f" ({issuer['organizationName']})"
    # ssl.cert_time_to_seconds parses OpenSSL's "Dec 25 22:56:35 2026 GMT" format
    not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    return CertInfo(
        subject=subject.get("commonName", ""),
        issuer=issuer_text,
        not_before=not_before,
        not_after=not_after,
        days_remaining=(not_after - now).days,
        alt_names=[value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"],
    )


@dataclass
class TlsResult:
    sock: ssl.SSLSocket | None  # the encrypted connection; None if the handshake failed
    duration_ms: float
    version: str | None = None  # e.g. "TLSv1.3"; None if the handshake failed
    cipher: str | None = None  # e.g. "TLS_AES_256_GCM_SHA384"
    cert: CertInfo | None = None  # details of the server's certificate
    error: str | None = None  # None if the handshake succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def tls_handshake(sock: socket.socket, hostname: str) -> TlsResult:
    """Do a TLS handshake on an open TCP socket and time how long it takes.

    The server's certificate is verified against `hostname`.
    On success the TLS socket is left open for the HTTP step; the caller must close it.
    On failure the TCP socket is closed here and the error is returned, not raised.
    """
    # Loads the trusted root certificates from the Windows certificate store and turns on
    # certificate and hostname checking. It does not check revocation (see RESEARCH.md (11)).
    context = ssl.create_default_context()
    start = time.perf_counter()
    try:
        # The handshake happens here. server_hostname is sent to the server (SNI) so it knows
        # which site's certificate to send, and is what the certificate is checked against.
        tls_sock = context.wrap_socket(sock, server_hostname=hostname)
    except OSError as e:  # SSLCertVerificationError is a subclass of OSError
        duration_ms = (time.perf_counter() - start) * 1000
        sock.close()
        return TlsResult(sock=None, duration_ms=duration_ms,
                         error=friendly_error(e, sock.gettimeout()), error_detail=raw_error(e))
    duration_ms = (time.perf_counter() - start) * 1000

    return TlsResult(
        sock=tls_sock,
        duration_ms=duration_ms,
        version=tls_sock.version(),
        cipher=tls_sock.cipher()[0],
        # getpeercert() returns the parsed certificate only because it was verified
        cert=parse_certificate(tls_sock.getpeercert()),
    )


@dataclass
class HttpResult:
    status_code: int | None  # e.g. 200; None if the request failed
    duration_ms: float  # time from sending the request to the first byte of the response
    reason: str | None = None  # e.g. "OK"
    location: str | None = None  # where a redirect points to; None if not a redirect
    headers: dict[str, str] = field(default_factory=dict)  # response headers, lowercase names
    error: str | None = None  # None if the request succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def http_get(sock: socket.socket, host: str, path: str) -> HttpResult:
    """Send an HTTP/1.1 GET request and time how long until the first byte of the response.

    `sock` is a TLS socket for https:// or a plain TCP socket for http://.
    `host` is the Host header value (see ParsedUrl.host_header).
    Reads the status line and headers only, not the body.
    The socket is always closed here, since this is the last step.
    A failed request is returned as a result with `error` set, not raised.
    Relies on the socket's timeout (set by connect_tcp) so a silent server can't block forever.
    """
    # HTTP lines end with \r\n, and a blank line ends the headers.
    # Host says which site we want, since one IP can serve many sites.
    # Connection: close asks the server to close the connection after replying.
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: website-diagnosis/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    start = time.perf_counter()
    try:
        sock.sendall(request.encode("ascii"))  # sendall keeps sending until every byte is sent
        data = sock.recv(4096)  # waits for up to 4096 bytes; b"" means the server closed
        # Stop the clock at the first bytes back (time to first byte).
        # Reading the rest of the headers below is not counted.
        duration_ms = (time.perf_counter() - start) * 1000
        # Keep reading until the end of the headers (a blank line), in case they span several chunks
        while data and b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError as e:  # parse_url already encoded the URL, so the request is always ASCII
        duration_ms = (time.perf_counter() - start) * 1000
        return HttpResult(status_code=None, duration_ms=duration_ms,
                          error=friendly_error(e, sock.gettimeout()), error_detail=raw_error(e))
    finally:
        sock.close()

    if not data:
        return HttpResult(status_code=None, duration_ms=duration_ms,
                          error="Server closed the connection without responding")

    # Headers are latin-1 by convention, and this decoding can't fail.
    head = data.split(b"\r\n\r\n")[0].decode("iso-8859-1")
    lines = head.split("\r\n")
    # Split at most twice so a reason with spaces stays whole: ["HTTP/1.1", "301", "Moved Permanently"]
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return HttpResult(status_code=None, duration_ms=duration_ms,
                          error=f"Unexpected response: {lines[0]!r}")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")  # split at the first colon only (URLs contain colons)
        name = name.strip().lower()  # header names are case-insensitive
        # A header sent more than once is combined with ", " (RFC 9110 section 5.3)
        headers[name] = f"{headers[name]}, {value.strip()}" if name in headers else value.strip()

    return HttpResult(
        status_code=int(parts[1]),
        duration_ms=duration_ms,
        reason=parts[2] if len(parts) == 3 else "",
        location=headers.get("location"),  # where a redirect (3xx) points
        headers=headers,
    )


@dataclass
class HeaderCheck:
    header: str  # e.g. "Strict-Transport-Security"
    status: str  # "pass", "warn", "missing" or "n/a"
    value: str | None  # the header's value, if sent
    note: str  # what it does, or what's wrong


HSTS_MIN_SECONDS = 180 * 24 * 3600  # Mozilla's guidelines recommend at least 6 months


def check_security_headers(headers: dict[str, str], scheme: str) -> list[HeaderCheck]:
    """Grade the response headers that protect browsers against common attacks.

    `headers` uses lowercase names, as HttpResult.headers does.
    Guidance: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers and
    https://owasp.org/www-project-secure-headers/
    """
    checks = []

    hsts = headers.get("strict-transport-security")
    if scheme == "http":
        # Browsers ignore HSTS sent over plain HTTP (RFC 6797 section 7.2)
        checks.append(HeaderCheck("Strict-Transport-Security", "n/a", hsts, "Only applies to https://"))
    elif hsts is None:
        checks.append(HeaderCheck("Strict-Transport-Security", "missing", None,
                                  "Browsers may connect over plain HTTP first, which can be intercepted"))
    else:
        max_age = 0
        for directive in hsts.split(";"):
            key, _, val = directive.strip().partition("=")
            if key.lower() == "max-age" and val.strip('"').isdigit():
                max_age = int(val.strip('"'))
        if max_age >= HSTS_MIN_SECONDS:
            checks.append(HeaderCheck("Strict-Transport-Security", "pass", hsts,
                                      f"Browsers will use HTTPS only for {max_age // 86400} days"))
        else:
            checks.append(HeaderCheck("Strict-Transport-Security", "warn", hsts,
                                      f"max-age is {max_age} s; at least 6 months is recommended"))

    csp = headers.get("content-security-policy")
    checks.append(HeaderCheck("Content-Security-Policy", "pass" if csp else "missing", csp,
                              "Limits where scripts and other content can load from" if csp
                              else "No policy limiting scripts, which makes cross-site scripting easier"))

    xcto = headers.get("x-content-type-options")
    if xcto and xcto.lower() == "nosniff":
        checks.append(HeaderCheck("X-Content-Type-Options", "pass", xcto, "Stops browsers guessing file types"))
    else:
        checks.append(HeaderCheck("X-Content-Type-Options", "warn" if xcto else "missing", xcto,
                                  "Should be 'nosniff' so browsers don't guess file types"))

    # Clickjacking: either X-Frame-Options or the newer CSP frame-ancestors directive works
    xfo = headers.get("x-frame-options")
    if csp and "frame-ancestors" in csp.lower():
        checks.append(HeaderCheck("X-Frame-Options", "pass", xfo, "Framing is controlled by CSP frame-ancestors"))
    elif xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        checks.append(HeaderCheck("X-Frame-Options", "pass", xfo, "Other sites can't embed this page in a frame"))
    else:
        checks.append(HeaderCheck("X-Frame-Options", "warn" if xfo else "missing", xfo,
                                  "Other sites could embed this page in a frame (clickjacking)"))

    referrer = headers.get("referrer-policy")
    if referrer and "unsafe-url" in referrer.lower():
        checks.append(HeaderCheck("Referrer-Policy", "warn", referrer, "unsafe-url leaks full URLs to other sites"))
    else:
        checks.append(HeaderCheck("Referrer-Policy", "pass" if referrer else "missing", referrer,
                                  "Controls how much of the URL is shared with other sites" if referrer
                                  else "Browser default applies (usually strict-origin-when-cross-origin)"))

    permissions = headers.get("permissions-policy")
    checks.append(HeaderCheck("Permissions-Policy", "pass" if permissions else "missing", permissions,
                              "Restricts browser features like camera and location" if permissions
                              else "No restrictions on browser features like camera and location"))
    return checks


@dataclass
class DiagnosisResult:
    url: ParsedUrl
    dns: DnsResult  # always runs, so never None
    tcp: TcpResult | None = None  # None if an earlier step failed
    tls: TlsResult | None = None  # also None for http:// URLs, which have no TLS step
    http: HttpResult | None = None

    @property
    def total_ms(self) -> float:
        """Total time of the steps that ran (DNS + TCP + TLS + HTTP), like web.dev's TTFB."""
        steps = [self.dns, self.tcp, self.tls, self.http]
        return sum(step.duration_ms for step in steps if step is not None)


def diagnose(url: str) -> DiagnosisResult:
    """Run every step in order (DNS, TCP, TLS, HTTP) and stop at the first one that fails.

    Raises ValueError if the URL is invalid (from parse_url).
    Network failures are returned in the result, not raised.
    """
    parsed = parse_url(url)

    result = DiagnosisResult(url=parsed, dns=resolve_dns(parsed.hostname, parsed.port))
    if result.dns.error:
        return result

    result.tcp = connect_tcp(result.dns.ip, parsed.port)
    if result.tcp.error:
        return result

    # Each step hands its open socket to the next one: TCP socket -> TLS, TLS socket -> HTTP.
    # Plain http:// skips TLS and sends the request straight over the TCP socket.
    sock = result.tcp.sock
    if parsed.scheme == "https":
        result.tls = tls_handshake(sock, parsed.hostname)
        if result.tls.error:
            return result
        sock = result.tls.sock

    result.http = http_get(sock, parsed.host_header, parsed.path)
    return result


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class RedirectChain:
    hops: list[DiagnosisResult]  # one full diagnosis per URL visited, in order
    warning: str | None = None  # why following stopped early, e.g. a redirect loop

    @property
    def final(self) -> DiagnosisResult:
        return self.hops[-1]

    @property
    def total_ms(self) -> float:
        return sum(hop.total_ms for hop in self.hops)


def follow_redirects(url: str, max_redirects: int = 5) -> RedirectChain:
    """Diagnose a URL and then each URL it redirects to, up to `max_redirects` times.

    Every hop is a fresh diagnosis (new DNS, TCP, TLS and HTTP), like a browser opening
    a new connection to a different host. Raises ValueError only if the first URL is invalid.
    """
    chain = RedirectChain(hops=[diagnose(url)])
    seen = {str(chain.final.url)}
    while True:
        http = chain.final.http
        if http is None or http.status_code not in REDIRECT_STATUSES or not http.location:
            return chain
        if len(chain.hops) > max_redirects:
            chain.warning = f"Stopped after {max_redirects} redirects"
            return chain
        # Location may be relative ("/login"), so resolve it against the current URL
        next_url = urljoin(str(chain.final.url), http.location)
        try:
            normalised = str(parse_url(next_url))  # compare URLs in the same form
        except ValueError as e:
            chain.warning = f"Can't follow redirect to {next_url}: {e}"
            return chain
        if normalised in seen:
            chain.warning = f"Redirect loop: {normalised} was already visited"
            return chain
        seen.add(normalised)
        chain.hops.append(diagnose(next_url))


if __name__ == "__main__":
    # Manual check: one URL that works, one that redirects, then one failure at each step
    # (parse_url is covered by the automated tests in test_diagnosis.py)
    for url in [
        "example.com",  # all steps succeed
        "google.com",  # succeeds with a 301 redirect
        "doesnotexist.invalid",  # fails at DNS
        "https://10.255.255.1",  # fails at TCP (unreachable IP, takes ~5 s to time out)
        "expired.badssl.com",  # fails at TLS
    ]:
        result = diagnose(url)
        print(url, "->", result)
        print("total_ms:", result.total_ms)
        print()

    try:
        diagnose("ftp://example.com")  # invalid input: should raise
    except ValueError as e:
        print("ValueError:", e)
