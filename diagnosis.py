"""Diagnose a website connection step by step: DNS, TCP, TLS, HTTP."""

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse


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


@dataclass
class ParsedUrl:
    hostname: str
    path: str


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

    # urlparse also lowercases the hostname and strips the port (e.g. ":8443") out of it
    parts = urlparse(url)
    if parts.scheme != "https":
        raise ValueError(f"Only https:// URLs are supported, got {parts.scheme}://")
    if not parts.hostname:
        raise ValueError("URL has no hostname")

    return ParsedUrl(hostname=parts.hostname, path=parts.path or "/")


@dataclass
class DnsResult:
    ip: str | None  # None if the lookup failed
    duration_ms: float
    error: str | None = None  # None if the lookup succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def resolve_dns(hostname: str) -> DnsResult:
    """Look up the IPv4 address of a hostname and time how long it takes.

    A failed lookup is returned as a result with `error` set, not raised.
    """
    start = time.perf_counter()
    try:
        # AF_INET limits results to IPv4.
        # SOCK_STREAM avoids duplicate entries per socket type.
        results = socket.getaddrinfo(
            hostname, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        duration_ms = (time.perf_counter() - start) * 1000
        return DnsResult(ip=None, duration_ms=duration_ms,
                         error=friendly_error(e), error_detail=raw_error(e))
    duration_ms = (time.perf_counter() - start) * 1000

    # Each result is (family, type, proto, canonname, sockaddr), and for
    # IPv4 sockaddr is (ip,port). Take the IP from the first result.
    ip = results[0][4][0]
    return DnsResult(ip=ip, duration_ms=duration_ms)


@dataclass
class TcpResult:
    sock: socket.socket | None  # the open connection; None if connecting failed
    duration_ms: float
    error: str | None = None  # None if the connection succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def connect_tcp(ip: str, timeout: float = 5.0) -> TcpResult:
    """Open a TCP connection to an IP on port 443 and time how long it takes.

    On success the socket is left open for the TLS step; the caller must close it.
    A failed connection is returned as a result with `error` set, not raised.
    """
    start = time.perf_counter()
    try:
        # Returns once the three-way handshake (SYN, SYN-ACK, ACK) is done.
        # The timeout stays set on the socket, so the TLS and HTTP steps use it too.
        sock = socket.create_connection((ip, 443), timeout=timeout)
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
    error: str | None = None  # None if the request succeeded
    error_detail: str | None = None  # raw exception text behind `error`


def http_get(sock: ssl.SSLSocket, hostname: str, path: str) -> HttpResult:
    """Send an HTTP/1.1 GET request and time how long until the first byte of the response.

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
        f"Host: {hostname}\r\n"
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
    except (OSError, UnicodeError) as e:  # UnicodeError: non-ASCII characters in the URL
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

    # Pull out Location so the caller can see where a redirect (3xx) points. It isn't followed.
    location = None
    for line in lines[1:]:
        name, _, value = line.partition(":")  # split at the first colon only (URLs contain colons)
        if name.strip().lower() == "location":  # header names are case-insensitive
            location = value.strip()

    return HttpResult(
        status_code=int(parts[1]),
        duration_ms=duration_ms,
        reason=parts[2] if len(parts) == 3 else "",
        location=location,
    )


@dataclass
class DiagnosisResult:
    url: ParsedUrl
    dns: DnsResult  # always runs, so never None
    tcp: TcpResult | None = None  # None if an earlier step failed
    tls: TlsResult | None = None
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

    result = DiagnosisResult(url=parsed, dns=resolve_dns(parsed.hostname))
    if result.dns.error:
        return result

    result.tcp = connect_tcp(result.dns.ip)
    if result.tcp.error:
        return result

    # Each step hands its open socket to the next one: TCP socket -> TLS, TLS socket -> HTTP
    result.tls = tls_handshake(result.tcp.sock, parsed.hostname)
    if result.tls.error:
        return result

    result.http = http_get(result.tls.sock, parsed.hostname, parsed.path)
    return result


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
        diagnose("http://example.com")  # invalid input: should raise
    except ValueError as e:
        print("ValueError:", e)
