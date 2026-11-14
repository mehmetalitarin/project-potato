"""Tests for the market data client (T-NET-1, T-NET-2, T-NET-4; R5).

A fake provider runs on loopback for each test. Most tests reach it over
plain HTTP through the one seam in the module, ``_open_connection``. The TLS
tests use the real connection class against a local TLS server, with
certificates made on the spot by the ``openssl`` command.
"""

import copy
import http.client
import json
import logging
import pickle
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import potato.integrations.market_data as market_data
from potato.integrations.market_data import (
    HOST,
    MAX_PRICE,
    MAX_RESPONSE_BYTES,
    PORT,
    SYMBOL_PATTERN,
    MarketDataClient,
    MarketDataError,
    MarketDataKeyRejectedError,
    MarketDataNoQuoteError,
    MarketDataRateLimitedError,
    MarketDataResponseError,
    MarketDataUnavailableError,
    Quote,
)
from potato.modules.portfolio import SYMBOL_FIELD
from potato.storage.database import SYMBOL_PATTERN as DATABASE_SYMBOL_PATTERN

# Built from pieces so that the secret scanner does not take it for a real key.
KEY = "_".join(("potato", "test", "value", "0000", "CANARY"))
CANARY = "server-said-canary-9917"
GOOD = {"c": 255.493, "d": 2.6, "dp": 1.03, "h": 255.5, "l": 248.07, "o": 253.9, "pc": 252.89,
        "t": 1774641600}  # fmt: skip
SOURCE = Path(market_data.__file__).read_text(encoding="utf-8")

Responder = Callable[[BaseHTTPRequestHandler], None]


def send_json(handler: BaseHTTPRequestHandler, body: object, status: int = 200) -> None:
    send_raw(handler, json.dumps(body).encode(), status)


def send_raw(handler: BaseHTTPRequestHandler, data: bytes, status: int = 200) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class FakeProvider:
    """A loopback HTTP or HTTPS server whose answers each test chooses."""

    def __init__(self, tls: ssl.SSLContext | None = None) -> None:
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.respond: Responder = lambda handler: send_json(handler, GOOD)
        self.release = threading.Event()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                headers = {name.lower(): value for name, value in self.headers.items()}
                fake.requests.append((self.command, self.path, headers))
                fake.respond(self)

            def log_message(self, *args: object) -> None:
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request: object, client_address: object) -> None:
                pass  # Clients hanging up mid-reply is what these tests do.

            def get_request(self) -> tuple[Any, Any]:
                connection, address = super().get_request()
                if tls is not None:
                    # Handshake in the handler's thread, not the accept loop.
                    connection = tls.wrap_socket(
                        connection, server_side=True, do_handshake_on_connect=False
                    )
                return connection, address

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port: int = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        self.thread.start()

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def provider() -> Iterator[FakeProvider]:
    fake = FakeProvider()
    yield fake
    fake.close()


class PlainConnection(http.client.HTTPConnection):
    """The real connection without TLS: same dialling, same watchdog handle."""

    guard: socket.socket | None = None

    def connect(self) -> None:
        self.sock, self.guard = market_data._dial(self.host, self.port, self.timeout)


def use_plain(
    monkeypatch: pytest.MonkeyPatch, port: int, socket_timeout: float | None = None
) -> None:
    """Point the client at a local plain-HTTP server through its one seam."""

    def open_connection(timeout: float) -> http.client.HTTPConnection:
        return PlainConnection("127.0.0.1", port, timeout=socket_timeout or timeout)

    monkeypatch.setattr(market_data, "_open_connection", open_connection)


@pytest.fixture
def client(provider: FakeProvider, monkeypatch: pytest.MonkeyPatch) -> MarketDataClient:
    use_plain(monkeypatch, provider.port)
    return MarketDataClient(KEY, timeout_seconds=5.0)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _assert_clean(error: BaseException) -> None:
    """An error says one fixed sentence and drags nothing else along."""
    assert error.__cause__ is None
    assert error.__context__ is None
    for text in (str(error), repr(error)):
        assert KEY not in text
        assert CANARY not in text
        assert not any(character.isdigit() for character in text)


# --- Where it connects (T-NET-1) ---------------------------------------------


def test_the_address_is_fixed_in_code() -> None:
    assert (HOST, PORT) == ("finnhub.io", 443)
    connection = market_data._open_connection(5.0)
    assert isinstance(connection, market_data._Connection)
    assert isinstance(connection, http.client.HTTPSConnection)
    assert (connection.host, connection.port) == ("finnhub.io", 443)
    assert connection.sock is None, "nothing is connected until a request is made"


def test_tls_settings_verify_the_certificate_and_the_name() -> None:
    context = market_data._tls_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_there_is_no_way_to_switch_verification_off() -> None:
    banned = ["CERT_NONE", "CERT_OPTIONAL", "_create_unverified_context", "check_hostname = False"]
    banned += ["verify=False", "set_tunnel", "getproxies"]
    for text in banned:
        assert text not in SOURCE
    # The client's constructor takes a key and a time limit, and nothing else.
    assert MarketDataClient.__slots__ == ("_key", "_timeout")
    with pytest.raises(TypeError):
        MarketDataClient(KEY, host="example.org")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        MarketDataClient(KEY, verify=False)  # type: ignore[call-arg]


# --- TLS for real, against a local server ------------------------------------


def _make_certificate(directory: Path, name: str, subject_alt_name: str) -> Path:
    """Make a self-signed certificate with ``openssl`` and return the combined file."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("the openssl command is not available")
    key, certificate = directory / f"{name}.key", directory / f"{name}.crt"
    command = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=potato-test",
        "-addext", f"subjectAltName={subject_alt_name}",
    ]  # fmt: skip
    done = subprocess.run(command, capture_output=True, timeout=120, check=False)  # noqa: S603
    if done.returncode != 0:
        pytest.skip("the openssl command could not make a test certificate")
    combined = directory / f"{name}.pem"
    combined.write_bytes(certificate.read_bytes() + key.read_bytes())
    return combined


@pytest.fixture(scope="module")
def certificates(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    directory = tmp_path_factory.mktemp("certificates")
    return {
        "loopback": _make_certificate(directory, "loopback", "IP:127.0.0.1"),
        "other_name": _make_certificate(directory, "other", "DNS:wrong.example"),
    }


def _server_context(certificate: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate)
    return context


def use_tls(
    monkeypatch: pytest.MonkeyPatch, port: int, trusted: Path | None, socket_timeout: float = 5.0
) -> None:
    """Point the real connection class at a local TLS server.

    The TLS settings are the real ones. A test may add one certificate to
    what they trust; nothing is taken away or switched off.
    """
    real_context = market_data._tls_context

    def context() -> ssl.SSLContext:
        made = real_context()
        if trusted is not None:
            made.load_verify_locations(trusted)
        return made

    def open_connection(timeout: float) -> http.client.HTTPConnection:
        return market_data._Connection("127.0.0.1", port, timeout=socket_timeout, context=context())

    monkeypatch.setattr(market_data, "_tls_context", context)
    monkeypatch.setattr(market_data, "_open_connection", open_connection)


def test_a_trusted_certificate_works_end_to_end(
    certificates: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(_server_context(certificates["loopback"]))
    proxy = FakeProvider()
    try:
        # Proxy settings in the environment must be ignored.
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        use_tls(monkeypatch, provider.port, trusted=certificates["loopback"])
        quote = MarketDataClient(KEY).quote("AAPL")
        assert quote == Quote("AAPL", Decimal("255.493"), 1774641600)
        assert provider.requests[0][2]["x-finnhub-token"] == KEY
        assert proxy.requests == []
    finally:
        provider.close()
        proxy.close()


def test_an_untrusted_certificate_is_refused_before_the_key_is_sent(
    certificates: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(_server_context(certificates["loopback"]))
    try:
        use_tls(monkeypatch, provider.port, trusted=None)
        with pytest.raises(MarketDataUnavailableError, match="could not be verified") as caught:
            MarketDataClient(KEY).quote("AAPL")
        _assert_clean(caught.value)
        assert provider.requests == []
    finally:
        provider.close()


def test_a_certificate_for_another_name_is_refused_before_the_key_is_sent(
    certificates: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(_server_context(certificates["other_name"]))
    try:
        # Trusted, but issued to a different name than the one connected to.
        use_tls(monkeypatch, provider.port, trusted=certificates["other_name"])
        with pytest.raises(MarketDataUnavailableError, match="could not be verified"):
            MarketDataClient(KEY).quote("AAPL")
        assert provider.requests == []
    finally:
        provider.close()


def test_a_slow_reply_over_tls_is_cut_off_too(
    certificates: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(_server_context(certificates["loopback"]))

    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            while not provider.release.wait(0.05):
                handler.wfile.write(b" ")
                handler.wfile.flush()
        except OSError:
            pass

    provider.respond = respond
    try:
        use_tls(monkeypatch, provider.port, trusted=certificates["loopback"], socket_timeout=30.0)
        started = time.monotonic()
        with pytest.raises(MarketDataUnavailableError, match="too long"):
            MarketDataClient(KEY, timeout_seconds=0.4).quote("AAPL")
        assert time.monotonic() - started < 5
    finally:
        provider.close()


class RawServer:
    """Accepts one connection at a time and keeps whatever bytes arrive."""

    def __init__(self, reply: bytes = b"") -> None:
        self.received = b""
        self._stop = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.05)
        self.port: int = self._listener.getsockname()[1]
        self._reply = reply
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except OSError:
                continue
            with connection:
                connection.settimeout(0.05)
                if self._reply:
                    connection.sendall(self._reply)
                while not self._stop.is_set():
                    try:
                        data = connection.recv(4096)
                    except TimeoutError:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    self.received += data

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._listener.close()


def test_a_server_that_does_not_speak_tls_never_sees_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = RawServer(reply=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    try:
        use_tls(monkeypatch, server.port, trusted=None)
        with pytest.raises(MarketDataUnavailableError) as caught:
            MarketDataClient(KEY).quote("AAPL")
        _assert_clean(caught.value)
    finally:
        server.close()
    assert KEY.encode() not in server.received
    assert b"quote" not in server.received


def test_a_stalled_handshake_is_cut_off_by_the_time_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = RawServer()
    try:
        # The socket's own timeout is far away, so only the watchdog can end this.
        use_tls(monkeypatch, server.port, trusted=None, socket_timeout=30.0)
        started = time.monotonic()
        with pytest.raises(MarketDataUnavailableError, match="too long"):
            MarketDataClient(KEY, timeout_seconds=0.3).quote("AAPL")
        assert time.monotonic() - started < 5
    finally:
        server.close()
    assert KEY.encode() not in server.received


# --- What it sends (T-NET-4) -------------------------------------------------


def test_a_request_carries_the_symbol_and_the_key_and_nothing_else(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    client.quote("BRK.B")
    ((method, path, headers),) = provider.requests
    assert method == "GET"
    assert path == "/api/v1/quote?symbol=BRK.B"
    assert headers == {
        "host": f"127.0.0.1:{provider.port}",
        "accept-encoding": "identity",
        "x-finnhub-token": KEY,
        "accept": "application/json",
        "user-agent": "Potato",
    }
    # The key is in a header, never in the address.
    assert KEY not in path
    assert "token" not in path


def test_each_call_makes_exactly_one_request(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    for symbol in ("AAPL", "MSFT", "A"):
        client.quote(symbol)
    assert [path for _, path, _ in provider.requests] == [
        "/api/v1/quote?symbol=AAPL",
        "/api/v1/quote?symbol=MSFT",
        "/api/v1/quote?symbol=A",
    ]


@pytest.mark.parametrize(
    "symbol",
    [
        "", "aapl", "1AB", "AAPL MSFT", "AAPL&token=x", "AAPL#", "AAPL?x=1", "AAPL/../x",
        "AAPL%20", "AAPL\r\nX-Evil: 1", "AAPL\n", "TOOLONGSYMBOL", "ÄPPL", "A,B", b"AAPL", None, 5,
        ["AAPL"],
    ],
)  # fmt: skip
def test_invalid_symbols_are_refused_and_nothing_is_sent(
    client: MarketDataClient, provider: FakeProvider, symbol: Any
) -> None:
    with pytest.raises(ValueError, match="ticker symbol"):
        client.quote(symbol)
    assert provider.requests == []


def test_the_symbol_rule_is_the_same_everywhere() -> None:
    assert SYMBOL_PATTERN.pattern == DATABASE_SYMBOL_PATTERN.pattern
    assert SYMBOL_FIELD.pattern.pattern == SYMBOL_PATTERN.pattern


def test_redirects_are_not_followed(client: MarketDataClient, provider: FakeProvider) -> None:
    elsewhere = FakeProvider()
    try:

        def redirect(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(307)
            handler.send_header("Location", f"http://127.0.0.1:{elsewhere.port}/api/v1/quote")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        provider.respond = redirect
        with pytest.raises(MarketDataResponseError, match="refused"):
            client.quote("AAPL")
        assert elsewhere.requests == []
    finally:
        elsewhere.close()


# R5 needs to see sockets being bound, which Python reports to audit hooks.
_BOUND: list[object] = []
_WATCHING = threading.Event()


def _hook(event: str, args: tuple[object, ...]) -> None:
    if _WATCHING.is_set() and event in {"socket.bind", "socket.listen"}:
        _BOUND.append(args)


sys.addaudithook(_hook)


def test_the_client_never_opens_a_listening_socket(client: MarketDataClient) -> None:
    _BOUND.clear()
    _WATCHING.set()
    try:
        client.quote("AAPL")
    finally:
        _WATCHING.clear()
    assert _BOUND == []


# --- What it accepts (T-NET-2) -----------------------------------------------


@pytest.mark.parametrize(
    ("body", "price"),
    [
        (GOOD, Decimal("255.493")),
        ({"c": 100, "t": 1774641600}, Decimal(100)),
        ({"c": 0.01, "t": 1}, Decimal("0.01")),
        ({"c": 0.30000000000000004, "t": 1774641600}, Decimal("0.3")),
        ({"c": 1e7, "t": 1774641600}, MAX_PRICE),
        ({"c": 12.5, "t": 1774641600, "note": CANARY, "extra": [1, 2]}, Decimal("12.5")),
    ],
)
def test_usable_replies(
    client: MarketDataClient, provider: FakeProvider, body: object, price: Decimal
) -> None:
    provider.respond = lambda handler: send_json(handler, body)
    quote = client.quote("AAPL")
    assert quote.symbol == "AAPL"
    assert quote.price == price
    assert type(quote.price) is Decimal
    assert CANARY not in repr(quote)


def test_prices_are_exact_decimals_not_floats(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    provider.respond = lambda handler: send_raw(handler, b'{"c": 0.1, "t": 5}')
    first = client.quote("A").price
    provider.respond = lambda handler: send_raw(handler, b'{"c": 0.2, "t": 5}')
    second = client.quote("B").price
    assert first + second == Decimal("0.3")


def test_an_unknown_symbol_has_no_quote(client: MarketDataClient, provider: FakeProvider) -> None:
    unknown = {"c": 0, "d": None, "dp": None, "h": 0, "l": 0, "o": 0, "pc": 0, "t": 0}
    provider.respond = lambda handler: send_json(handler, unknown)
    with pytest.raises(MarketDataNoQuoteError, match="no price") as caught:
        client.quote("ZZZZ")
    _assert_clean(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"t": 1774641600}',
        b'{"c": 255.4}',
        b'{"c": "255.4", "t": 1774641600}',
        b'{"c": true, "t": 1774641600}',
        b'{"c": null, "t": 1774641600}',
        b'{"c": [255.4], "t": 1774641600}',
        b'{"c": -1, "t": 1774641600}',
        b'{"c": -0.01, "t": 1774641600}',
        b'{"c": 0, "t": 1774641600}',
        b'{"c": 0.0, "t": 1774641600}',
        b'{"c": 10000000.01, "t": 1774641600}',
        b'{"c": 1e999999, "t": 1774641600}',
        b'{"c": NaN, "t": 1774641600}',
        b'{"c": Infinity, "t": 1774641600}',
        # Valid in every way except a NaN in a field Potato does not read.
        b'{"c": 255.4, "t": 1774641600, "d": NaN}',
        b'{"c": 255.4, "t": 1774641600, "dp": -Infinity}',
        b'{"c": 255.4, "t": 0}',
        b'{"c": 255.4, "t": -5}',
        b'{"c": 255.4, "t": 1774641600.5}',
        b'{"c": 255.4, "t": "1774641600"}',
        b'{"c": 255.4, "t": true}',
        b'{"c": 255.4, "t": 4102444800}',
        b'{"c": 255.4, "t": ' + b"9" * 5000 + b"}",
        b'{"c": ' + b"9" * 5000 + b', "t": 1774641600}',
        b'[{"c": 255.4, "t": 1774641600}]',
        b'"255.4"',
        b"255.4",
        b"null",
        b"",
        b"not json " + CANARY.encode(),
        b"\xff\xfe{}",
        b"[" * 6000 + b"]" * 6000,
        b'{"c": 255.4, "t": 1774641600',
    ],
)
def test_replies_of_the_wrong_shape_are_refused(
    client: MarketDataClient, provider: FakeProvider, raw: bytes
) -> None:
    provider.respond = lambda handler: send_raw(handler, raw)
    with pytest.raises(MarketDataResponseError, match="could not use") as caught:
        client.quote("AAPL")
    _assert_clean(caught.value)


@pytest.mark.parametrize(
    ("status", "error", "sentence"),
    [
        (401, MarketDataKeyRejectedError, "did not accept the API key"),
        (403, MarketDataNoQuoteError, "does not offer that symbol"),
        (429, MarketDataRateLimitedError, "slow down"),
        (400, MarketDataResponseError, "refused the request"),
        (404, MarketDataResponseError, "refused the request"),
        (500, MarketDataResponseError, "refused the request"),
        (503, MarketDataResponseError, "refused the request"),
        (201, MarketDataResponseError, "refused the request"),
        (206, MarketDataResponseError, "refused the request"),
        (302, MarketDataResponseError, "refused the request"),
    ],
)
def test_each_status_gets_its_own_fixed_sentence(
    client: MarketDataClient,
    provider: FakeProvider,
    status: int,
    error: type[MarketDataError],
    sentence: str,
) -> None:
    # A usable body, so that only the status can be the reason.
    provider.respond = lambda handler: send_json(handler, {**GOOD, "error": CANARY}, status)
    with pytest.raises(error, match=sentence) as caught:
        client.quote("AAPL")
    assert type(caught.value) is error
    _assert_clean(caught.value)


def test_every_error_is_a_market_data_error() -> None:
    for error in (
        MarketDataUnavailableError,
        MarketDataKeyRejectedError,
        MarketDataRateLimitedError,
        MarketDataNoQuoteError,
        MarketDataResponseError,
    ):
        assert issubclass(error, MarketDataError)
    assert set(market_data._ERRORS) == set(market_data._Failure)


# --- Size limits -------------------------------------------------------------


def test_a_reply_declared_too_large_is_refused(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(MAX_RESPONSE_BYTES + 1))
        handler.end_headers()
        handler.wfile.write(b"{")

    provider.respond = respond
    with pytest.raises(MarketDataResponseError, match="too much data"):
        client.quote("AAPL")


def test_a_reply_at_the_size_limit_is_read(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    body = b'{"c": 5, "t": 9, "pad": "' + b"x" * (MAX_RESPONSE_BYTES - 27) + b'"}'
    assert len(body) == MAX_RESPONSE_BYTES
    provider.respond = lambda handler: send_raw(handler, body)
    assert client.quote("AAPL").price == Decimal(5)


def test_a_reply_that_grows_too_large_is_cut_off(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            for _ in range(200):
                handler.wfile.write(b" " * 4096)
        except OSError:
            pass

    provider.respond = respond
    with pytest.raises(MarketDataResponseError, match="too much data"):
        client.quote("AAPL")


@pytest.mark.parametrize("length", ["abc", "-1", "1e3", "١٢"])
def test_a_strange_content_length_is_refused(
    client: MarketDataClient, provider: FakeProvider, length: str
) -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", length)
        handler.end_headers()

    provider.respond = respond
    with pytest.raises(MarketDataError):
        client.quote("AAPL")


# --- Time limits -------------------------------------------------------------


def _timed_client(
    monkeypatch: pytest.MonkeyPatch, provider: FakeProvider, *, socket_timeout: float
) -> MarketDataClient:
    use_plain(monkeypatch, provider.port, socket_timeout=socket_timeout)
    return MarketDataClient(KEY, timeout_seconds=0.4)


def _assert_cut_off(client: MarketDataClient) -> None:
    started = time.monotonic()
    with pytest.raises(MarketDataUnavailableError, match="too long") as caught:
        client.quote("AAPL")
    assert time.monotonic() - started < 5
    _assert_clean(caught.value)


def test_a_server_that_never_answers_is_cut_off(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider.respond = lambda handler: provider.release.wait(20)  # type: ignore[assignment]
    # The socket's own timeout is far away, so only the watchdog can end this.
    _assert_cut_off(_timed_client(monkeypatch, provider, socket_timeout=30.0))


def test_headers_sent_one_byte_at_a_time_are_cut_off(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        try:
            handler.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            while not provider.release.wait(0.05):
                handler.wfile.write(b"a")
                handler.wfile.flush()
        except OSError:
            pass

    provider.respond = respond
    # Each byte arrives well within the socket's timeout, so it never trips.
    _assert_cut_off(_timed_client(monkeypatch, provider, socket_timeout=1.0))


def test_a_body_sent_one_byte_at_a_time_is_cut_off(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            while not provider.release.wait(0.05):
                handler.wfile.write(b" ")
                handler.wfile.flush()
        except OSError:
            pass

    provider.respond = respond
    _assert_cut_off(_timed_client(monkeypatch, provider, socket_timeout=1.0))


def test_a_reply_cut_off_by_the_time_limit_is_never_used(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A complete-looking answer with no declared length, then silence. The
    # client cannot know it is complete, so it must not trust it.
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(json.dumps(GOOD).encode())
        handler.wfile.flush()
        provider.release.wait(20)

    provider.respond = respond
    _assert_cut_off(_timed_client(monkeypatch, provider, socket_timeout=30.0))


def test_the_socket_timeout_alone_also_ends_a_silent_server(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider.respond = lambda handler: provider.release.wait(20)  # type: ignore[assignment]
    use_plain(monkeypatch, provider.port, socket_timeout=0.2)
    started = time.monotonic()
    with pytest.raises(MarketDataUnavailableError):
        MarketDataClient(KEY, timeout_seconds=20.0).quote("AAPL")
    assert time.monotonic() - started < 5


def test_a_fast_answer_is_not_slowed_down_and_leaves_no_thread_behind(
    client: MarketDataClient,
) -> None:
    started = time.monotonic()
    for _ in range(20):
        client.quote("AAPL")
    assert time.monotonic() - started < 3
    assert not [t for t in threading.enumerate() if t.name == "potato-market-data-watchdog"]


def test_no_watchdog_is_left_behind_after_a_failure(
    provider: FakeProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider.respond = lambda handler: provider.release.wait(20)  # type: ignore[assignment]
    _assert_cut_off(_timed_client(monkeypatch, provider, socket_timeout=30.0))
    assert not [t for t in threading.enumerate() if t.name == "potato-market-data-watchdog"]


def test_the_watchdog_has_its_own_plain_handle_on_the_connection() -> None:
    # Asking a TLS socket itself to shut down first drops its encryption
    # state, and a send racing with that could leave unencrypted. The
    # watchdog therefore never touches the socket the request is using.
    server = RawServer()
    try:
        used, guard = market_data._dial("127.0.0.1", server.port, 5.0)
        try:
            assert type(guard) is socket.socket
            assert guard is not used
            assert guard.fileno() != used.fileno()
            guard.shutdown(socket.SHUT_RDWR)
            assert used.recv(1) == b"", "ending the handle ends the connection"
        finally:
            used.close()
            guard.close()
    finally:
        server.close()
    assert SOURCE.count(".shutdown(") == 1
    assert "guard.shutdown(socket.SHUT_RDWR)" in SOURCE
    assert "_sslobj" not in SOURCE
    assert "self.sock.shutdown" not in SOURCE


class _Holder:
    def __init__(self, guard: socket.socket) -> None:
        self.guard: socket.socket | None = guard


def test_the_watchdog_ends_a_connection_that_runs_out_of_time() -> None:
    ours, theirs = socket.socketpair()
    timed_out, finished = threading.Event(), threading.Event()
    watcher = threading.Thread(
        target=market_data._watch, args=(_Holder(ours), 0.05, timed_out, finished), daemon=True
    )
    watcher.start()
    try:
        theirs.settimeout(5)
        assert theirs.recv(1) == b""
        assert timed_out.is_set()
    finally:
        finished.set()
        watcher.join(timeout=5)
        ours.close()
        theirs.close()


def test_the_watchdog_keeps_trying_while_the_connection_is_still_opening() -> None:
    # At the deadline there is no connection to end yet. It appears later,
    # and must still be ended.
    ours, theirs = socket.socketpair()
    holder = _Holder(ours)
    holder.guard = None
    timed_out, finished = threading.Event(), threading.Event()
    watcher = threading.Thread(
        target=market_data._watch, args=(holder, 0.05, timed_out, finished), daemon=True
    )
    watcher.start()
    try:
        assert timed_out.wait(5)
        time.sleep(0.2)
        holder.guard = ours
        theirs.settimeout(5)
        assert theirs.recv(1) == b""
    finally:
        finished.set()
        watcher.join(timeout=5)
        ours.close()
        theirs.close()


def test_the_watchdog_does_nothing_when_the_request_finishes_in_time() -> None:
    ours, theirs = socket.socketpair()
    timed_out, finished = threading.Event(), threading.Event()
    watcher = threading.Thread(
        target=market_data._watch, args=(_Holder(ours), 30.0, timed_out, finished), daemon=True
    )
    watcher.start()
    finished.set()
    watcher.join(timeout=5)
    assert not watcher.is_alive()
    assert not timed_out.is_set()
    ours.sendall(b"x")
    assert theirs.recv(1) == b"x"
    ours.close()
    theirs.close()


# --- Unreachable -------------------------------------------------------------


def test_nothing_listening_means_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    use_plain(monkeypatch, _free_port())
    with pytest.raises(MarketDataUnavailableError, match="could not be reached") as caught:
        MarketDataClient(KEY).quote("AAPL")
    _assert_clean(caught.value)


def test_a_server_that_hangs_up_means_unavailable(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    def hang_up(handler: BaseHTTPRequestHandler) -> None:
        handler.close_connection = True
        handler.connection.shutdown(socket.SHUT_RDWR)

    provider.respond = hang_up
    with pytest.raises(MarketDataUnavailableError, match="could not be reached"):
        client.quote("AAPL")


def test_a_reply_that_is_not_http_means_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    server = RawServer(reply=f"{CANARY} is not HTTP\r\n\r\n".encode())
    try:
        use_plain(monkeypatch, server.port)
        with pytest.raises(MarketDataUnavailableError) as caught:
            MarketDataClient(KEY).quote("AAPL")
        _assert_clean(caught.value)
    finally:
        server.close()


def test_the_client_works_again_after_a_failure(
    client: MarketDataClient, provider: FakeProvider
) -> None:
    provider.respond = lambda handler: send_json(handler, {}, 500)
    with pytest.raises(MarketDataResponseError):
        client.quote("AAPL")
    provider.respond = lambda handler: send_json(handler, GOOD)
    assert client.quote("AAPL").price == Decimal("255.493")


# --- The key (T-DATA-1) ------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "", "short", "x" * 129, "has space in the key", "line\nbreak12345", "tab\tinside12345",
        "key12345\r\nX-Evil: 1", "kéy123456789", "key:with:colons", b"testkey0123456789", None,
        12345678,
    ],
)  # fmt: skip
def test_keys_that_could_break_a_header_are_refused(key: Any) -> None:
    with pytest.raises(ValueError, match="usable form") as caught:
        MarketDataClient(key)
    if isinstance(key, str) and key:
        assert key not in str(caught.value)


@pytest.mark.parametrize("timeout", [0, -1, 30.5, float("nan"), float("inf"), "10", True, None])
def test_time_limits_outside_the_bounds_are_refused(timeout: Any) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        MarketDataClient(KEY, timeout_seconds=timeout)


def test_the_key_never_appears_in_text(
    client: MarketDataClient, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    texts = [repr(client), str(client)]
    with caplog.at_level(logging.DEBUG):
        texts.append(repr(client.quote("AAPL")))
        for status in (401, 403, 429, 500):
            provider.respond = lambda handler, status=status: send_json(handler, {}, status)  # type: ignore[misc]
            with pytest.raises(MarketDataError) as caught:
                client.quote("AAPL")
            texts.extend([str(caught.value), repr(caught.value)])
    texts.append(caplog.text)
    for text in texts:
        assert KEY not in text
    assert repr(client) == "<MarketDataClient finnhub.io>"
    assert not hasattr(client, "__dict__")


def test_the_client_cannot_be_copied_or_saved(client: MarketDataClient) -> None:
    with pytest.raises(TypeError):
        pickle.dumps(client)
    with pytest.raises(TypeError):
        copy.copy(client)
    with pytest.raises(TypeError):
        copy.deepcopy(client)


def test_the_source_writes_nothing_to_a_log_or_the_screen() -> None:
    assert "logging" not in SOURCE
    assert "print(" not in SOURCE
    assert "debuglevel" not in SOURCE
