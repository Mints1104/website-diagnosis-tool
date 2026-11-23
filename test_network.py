"""Tests for the network steps, without using the internet.

- http_get runs on a real socket pair, with the "server" end sending canned responses.
- diagnose() runs end to end against a local http.server on 127.0.0.1 and ::1.
- Failures that are slow or impossible to trigger locally (DNS errors, timeouts,
  bad certificates) are simulated with unittest.mock.
"""

import http.server
import socket
import ssl
import threading
from unittest import mock

import pytest

from diagnosis import connect_tcp, diagnose, http_get, resolve_dns, tls_handshake

# ---------- DNS ----------


def addrinfo(ip: str):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


def test_dns_uses_first_address_and_keeps_all():
    results = [addrinfo("2001:db8::1"), addrinfo("192.0.2.1"), addrinfo("192.0.2.1")]
    with mock.patch("socket.getaddrinfo", return_value=results) as getaddrinfo:
        result = resolve_dns("example.test", 8443)
    assert result.ip == "2001:db8::1"
    assert result.ip_version == "IPv6"
    assert result.all_ips == ["2001:db8::1", "192.0.2.1"]  # duplicates removed
    assert getaddrinfo.call_args.args[1] == 8443


def test_dns_failure_is_returned_not_raised():
    with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(11001, "getaddrinfo failed")):
        result = resolve_dns("doesnotexist.invalid")
    assert result.ip is None
    assert "Domain not found" in result.error
    assert "gaierror" in result.error_detail


def test_dns_localhost_for_real():
    assert resolve_dns("localhost").ip in ("127.0.0.1", "::1")


# ---------- TCP ----------


def test_tcp_connects_to_a_local_listener():
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        result = connect_tcp("127.0.0.1", port, timeout=2)
        assert result.error is None
        assert result.sock.getpeername() == ("127.0.0.1", port)
        result.sock.close()


@pytest.mark.parametrize("exc, expected", [
    (ConnectionRefusedError(10061, "refused"), "refused"),
    (TimeoutError("timed out"), "Timed out after 5 s"),
])
def test_tcp_failures(exc, expected):
    with mock.patch("socket.create_connection", side_effect=exc):
        result = connect_tcp("192.0.2.1", 443, timeout=5)
    assert result.sock is None
    assert expected in result.error


# ---------- TLS ----------


def test_tls_failure_closes_the_socket():
    sock = mock.Mock(spec=socket.socket)
    sock.gettimeout.return_value = 5.0
    error = ssl.SSLCertVerificationError("certificate verify failed")
    error.verify_code, error.verify_message = 10, "certificate has expired"
    context = mock.Mock()
    context.wrap_socket.side_effect = error
    with mock.patch("ssl.create_default_context", return_value=context):
        result = tls_handshake(sock, "expired.example")
    assert result.error == "The site's certificate has expired"
    sock.close.assert_called_once()
    context.wrap_socket.assert_called_once_with(sock, server_hostname="expired.example")


def test_tls_success_reads_version_cipher_and_certificate():
    tls_sock = mock.Mock()
    tls_sock.version.return_value = "TLSv1.3"
    tls_sock.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    tls_sock.getpeercert.return_value = {
        "subject": ((("commonName", "a.test"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2030 GMT",
    }
    context = mock.Mock()
    context.wrap_socket.return_value = tls_sock
    with mock.patch("ssl.create_default_context", return_value=context):
        result = tls_handshake(mock.Mock(), "a.test")
    assert result.error is None
    assert (result.version, result.cipher) == ("TLSv1.3", "TLS_AES_128_GCM_SHA256")
    assert result.cert.subject == "a.test"


# ---------- HTTP ----------


def serve_canned(chunks: list[bytes]):
    """Return a client socket whose peer sends `chunks` and then closes."""
    client, server = socket.socketpair()
    client.settimeout(2)

    def run():
        server.recv(4096)  # wait for the request
        for chunk in chunks:
            server.sendall(chunk)
        server.close()

    threading.Thread(target=run, daemon=True).start()
    return client


def test_http_parses_status_and_headers():
    sock = serve_canned([
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Location: https://example.com/\r\n"
        b"Set-Cookie: a=1\r\n"
        b"set-cookie: b=2\r\n"
        b"\r\n<html>body is ignored</html>"
    ])
    result = http_get(sock, "example.com", "/")
    assert result.status_code == 301
    assert result.reason == "Moved Permanently"
    assert result.location == "https://example.com/"
    assert result.headers["set-cookie"] == "a=1, b=2"


def test_http_headers_split_across_chunks():
    sock = serve_canned([b"HTTP/1.1 200 OK\r\nX-A: 1\r\n", b"X-B: 2\r\n\r\n"])
    result = http_get(sock, "example.com", "/")
    assert result.status_code == 200
    assert result.headers == {"x-a": "1", "x-b": "2"}


def test_http_sends_host_header_and_path():
    client, server = socket.socketpair()
    client.settimeout(2)
    received = []

    def run():
        received.append(server.recv(4096))
        server.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        server.close()

    threading.Thread(target=run, daemon=True).start()
    http_get(client, "[::1]:8080", "/a%20b?x=1")
    request = received[0].decode("ascii")
    assert request.startswith("GET /a%20b?x=1 HTTP/1.1\r\n")
    assert "\r\nHost: [::1]:8080\r\n" in request


def test_http_server_closes_without_response():
    result = http_get(serve_canned([]), "example.com", "/")
    assert result.status_code is None
    assert "closed the connection" in result.error


def test_http_garbage_response():
    result = http_get(serve_canned([b"SSH-2.0-OpenSSH_9.6\r\n\r\n"]), "example.com", "/")
    assert result.status_code is None
    assert "Unexpected response" in result.error


def test_http_timeout():
    client, server = socket.socketpair()  # the server end never answers
    client.settimeout(0.2)
    result = http_get(client, "example.com", "/")
    server.close()
    assert result.status_code is None
    assert "Timed out after 0.2 s" in result.error


# ---------- End to end over http:// ----------


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Path", self.path)
        self.end_headers()

    def log_message(self, *args):
        pass  # keep test output clean


def run_local_server(host: str):
    server_class = http.server.ThreadingHTTPServer
    if ":" in host:
        server_class = type("V6Server", (server_class,), {"address_family": socket.AF_INET6})
    server = server_class((host, 0), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def ipv6_available() -> bool:
    try:
        with socket.create_server(("::1", 0), family=socket.AF_INET6):
            return True
    except OSError:
        return False


@pytest.mark.parametrize("host, url_host", [
    ("127.0.0.1", "127.0.0.1"),
    pytest.param("::1", "[::1]", marks=pytest.mark.skipif(not ipv6_available(), reason="no IPv6 loopback")),
])
def test_diagnose_end_to_end(host, url_host):
    server = run_local_server(host)
    port = server.server_address[1]
    try:
        result = diagnose(f"http://{url_host}:{port}/café?q=1")
    finally:
        server.shutdown()
        server.server_close()
    assert result.dns.ip == host
    assert result.tls is None  # http:// has no TLS step
    assert result.http.status_code == 200
    assert result.http.headers["x-path"] == "/caf%C3%A9?q=1"
    assert result.total_ms > 0
