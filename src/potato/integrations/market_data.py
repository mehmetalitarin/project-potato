"""The client for market prices, from Finnhub.

This is the only code in Potato that talks to the internet. It asks one
question, "what is the latest price of this symbol?", and treats the network
and the answer as hostile (T-NET-1, T-NET-2 and T-NET-4 in
``docs/threat_model.md``):

- **Verified TLS, with no way to switch it off.** The certificate and the
  host name are both checked. If either fails, the connection ends before
  the API key or anything else is sent.
- **One fixed address.** The host is written in this file. It is not a
  setting. Redirects are not followed and proxy settings in the environment
  are not used, so a request cannot be steered elsewhere.
- **Only the symbol leaves the Mac.** A request carries a ticker symbol and
  the API key. The key travels in a header, never in the address, so it does
  not end up in the provider's access logs. Quantities and prices paid are
  never sent.
- **Bounded.** A reply is size-capped. From the moment the provider is
  reached, the secure handshake, the request and the reply share one hard
  time limit, which also stops a server that sends one byte at a time.
  Finding and reaching the provider is limited separately, per address.
- **Strict.** A price is read as an exact decimal and must be a positive
  number within fixed bounds. Nothing else in the reply is used.
- **Quiet errors.** No error contains the key or anything the server sent.

What it cannot do: tell a wrong price from a right one. If the provider sends
a wrong price, Potato shows it. Potato only ever displays prices and never
acts on them.
"""

import contextlib
import http.client
import json
import re
import socket
import ssl
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum, auto
from types import MappingProxyType
from typing import Final, NoReturn

# The provider's address. Fixed here, in code (R7).
HOST: Final = "finnhub.io"
PORT: Final = 443
_QUOTE_PATH: Final = "/api/v1/quote?symbol="
_KEY_HEADER: Final = "X-Finnhub-Token"

MAX_RESPONSE_BYTES: Final = 16 * 1024
MAX_TIMEOUT_SECONDS: Final = 30.0
MAX_PRICE: Final = Decimal(10_000_000)
PRICE_DECIMAL_PLACES: Final = 8
# Timestamps are seconds since 1970. Anything from 2100 onwards is nonsense.
_MAX_TIME: Final = 4_102_444_800
_CHUNK_BYTES: Final = 4096

# The same rule as the database uses for a ticker symbol. Every character it
# allows is safe in a web address as it is, so nothing needs encoding.
SYMBOL_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9.\-]{0,9}")
# Letters, digits, hyphens and underscores only, so a key can never break
# out of its header.
_KEY_PATTERN: Final = re.compile(r"[A-Za-z0-9_\-]{8,128}")

_ONE_UNIT: Final = Decimal(1).scaleb(-PRICE_DECIMAL_PLACES)


class MarketDataError(Exception):
    """A price could not be fetched. Carries a fixed sentence and nothing else."""


class MarketDataUnavailableError(MarketDataError):
    """The provider could not be reached in time, or not securely."""


class MarketDataKeyRejectedError(MarketDataError):
    """The provider did not accept the API key."""


class MarketDataRateLimitedError(MarketDataError):
    """The provider says too many requests were made."""


class MarketDataNoQuoteError(MarketDataError):
    """The provider has no price for the symbol, or does not offer it with this key."""


class MarketDataResponseError(MarketDataError):
    """The provider answered with something Potato will not use."""


class _Failure(Enum):
    """Why a request failed. Turned into an error after all handlers have finished."""

    TIMED_OUT = auto()
    NOT_SECURE = auto()
    UNREACHABLE = auto()
    KEY_REJECTED = auto()
    RATE_LIMITED = auto()
    NO_ACCESS = auto()
    REFUSED = auto()
    TOO_LARGE = auto()
    NOT_USABLE = auto()
    NO_QUOTE = auto()


@dataclass(frozen=True, slots=True)
class Quote:
    """The latest price of one symbol.

    Attributes:
        symbol: The symbol that was asked about.
        price: The latest price, in the currency the symbol trades in.
        time: When the provider says that price was current, in seconds
            since 1970 (UTC).
    """

    symbol: str
    price: Decimal
    time: int


def _tls_context() -> ssl.SSLContext:
    """Return the TLS settings for every connection. There is no other set."""
    context = ssl.create_default_context()
    # Both are already the defaults. Stating them means a change to the
    # defaults cannot quietly weaken this.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _dial(host: str, port: int, timeout: float | None) -> tuple[socket.socket, socket.socket]:
    """Open a connection, plus a second handle on it for the watchdog.

    The second handle is a plain socket with a descriptor of its own. The
    watchdog can end the connection through it at any moment without touching
    the socket the request is using. That matters for TLS: asking a TLS
    socket itself to shut down first makes it forget its encryption, and
    anything sent in that instant would leave unencrypted.
    """
    plain = socket.create_connection((host, port), timeout)
    try:
        guard = socket.fromfd(plain.fileno(), plain.family, plain.type)
    except BaseException:
        plain.close()
        raise
    return plain, guard


class _Connection(http.client.HTTPSConnection):
    """A connection to the provider that the watchdog can end at any stage.

    ``http.client`` is used because it never follows a redirect and never
    reads proxy settings from the environment.
    """

    guard: socket.socket | None = None

    def connect(self) -> None:
        """Connect, then check the certificate and host name."""
        plain, self.guard = _dial(self.host, self.port, self.timeout)
        try:
            self.sock = _tls_context().wrap_socket(plain, server_hostname=self.host)
        except BaseException:
            plain.close()
            raise


def _open_connection(timeout: float) -> _Connection:
    """Prepare a connection to the provider. Nothing is sent until it is used."""
    return _Connection(HOST, PORT, timeout=timeout, context=_tls_context())


def _watch(
    connection: _Connection,
    seconds: float,
    timed_out: threading.Event,
    finished: threading.Event,
) -> None:
    """End the connection if the request has not finished after ``seconds``.

    A timeout on the socket alone only limits each wait for more data. A
    server that sends one byte just in time, again and again, would never
    trip it. This ends the connection from outside at a fixed moment.
    """
    if finished.wait(seconds):
        return
    timed_out.set()
    # The connection may still be opening, so keep trying until the request
    # gives up.
    while not finished.wait(0.05):
        guard = connection.guard
        if guard is not None:
            with contextlib.suppress(OSError):
                guard.shutdown(socket.SHUT_RDWR)


def _refuse_constant(name: str) -> NoReturn:
    """Refuse NaN and Infinity, which are not valid JSON."""
    raise ValueError("not valid JSON")


def _read_capped(response: http.client.HTTPResponse) -> bytes | None:
    """Read the body, or return ``None`` if it is larger than the cap."""
    length = response.getheader("Content-Length")
    if length is not None and (
        not (length.isascii() and length.isdigit()) or int(length) > MAX_RESPONSE_BYTES
    ):
        return None
    chunks: list[bytes] = []
    total = 0
    while chunk := response.read1(_CHUNK_BYTES):
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _read_quote(symbol: str, raw: bytes) -> Quote | _Failure:
    """Check the reply's shape and turn it into a ``Quote``."""
    try:
        body = json.loads(raw.decode("utf-8"), parse_float=Decimal, parse_constant=_refuse_constant)
    except (UnicodeDecodeError, ValueError, ArithmeticError, RecursionError):
        return _Failure.NOT_USABLE
    if type(body) is not dict:
        return _Failure.NOT_USABLE

    price = body.get("c")
    time = body.get("t")
    # type(), not isinstance(): True and False are ints in Python.
    if type(price) is int:
        price = Decimal(price)
    if type(price) is not Decimal or not price.is_finite() or type(time) is not int:
        return _Failure.NOT_USABLE
    if price == 0 and time == 0:
        # The provider's answer for a symbol it does not know.
        return _Failure.NO_QUOTE
    if not 0 < price <= MAX_PRICE or not 0 < time < _MAX_TIME:
        return _Failure.NOT_USABLE
    return Quote(symbol, price.quantize(_ONE_UNIT, ROUND_HALF_EVEN).normalize(), time)


_STATUS_FAILURES: Final = {
    401: _Failure.KEY_REJECTED,
    403: _Failure.NO_ACCESS,
    429: _Failure.RATE_LIMITED,
}

# Every sentence an error can carry.
_ERRORS: Final[Mapping[_Failure, tuple[type[MarketDataError], str]]] = MappingProxyType(
    {
        _Failure.TIMED_OUT: (
            MarketDataUnavailableError,
            "the price service took too long to answer",
        ),
        _Failure.NOT_SECURE: (
            MarketDataUnavailableError,
            "the connection to the price service could not be verified, so it was refused",
        ),
        _Failure.UNREACHABLE: (
            MarketDataUnavailableError,
            "the price service could not be reached",
        ),
        _Failure.KEY_REJECTED: (
            MarketDataKeyRejectedError,
            "the price service did not accept the API key",
        ),
        _Failure.RATE_LIMITED: (
            MarketDataRateLimitedError,
            "the price service says to slow down",
        ),
        _Failure.NO_ACCESS: (
            MarketDataNoQuoteError,
            "the price service does not offer that symbol with this key",
        ),
        _Failure.NO_QUOTE: (
            MarketDataNoQuoteError,
            "the price service has no price for that symbol",
        ),
        _Failure.TOO_LARGE: (
            MarketDataResponseError,
            "the price service sent too much data",
        ),
        _Failure.REFUSED: (
            MarketDataResponseError,
            "the price service refused the request",
        ),
        _Failure.NOT_USABLE: (
            MarketDataResponseError,
            "the price service sent an answer Potato could not use",
        ),
    }
)


class MarketDataClient:
    """Fetches latest prices from the provider. Safe to use from several threads."""

    __slots__ = ("_key", "_timeout")

    def __init__(self, api_key: str, *, timeout_seconds: float = 10.0) -> None:
        """Remember the key and the time limit. Connects to nothing.

        Args:
            api_key: The user's own key for the provider.
            timeout_seconds: The longest one request may take in total.

        Raises:
            ValueError: The key is not in a usable form, or the time limit is
                out of bounds. The message never contains the key.
        """
        if type(api_key) is not str or _KEY_PATTERN.fullmatch(api_key) is None:
            raise ValueError("the API key is not in a usable form")
        if (
            type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError(f"timeout_seconds must be above 0 and at most {MAX_TIMEOUT_SECONDS}")
        self._key = api_key
        self._timeout = float(timeout_seconds)

    def __repr__(self) -> str:
        """Never show the key."""
        return f"<MarketDataClient {HOST}>"

    def __reduce__(self) -> NoReturn:
        """Refuse to be copied or saved, which would copy the key."""
        raise TypeError("an object holding the API key cannot be copied or saved")

    def quote(self, symbol: str) -> Quote:
        """Return the latest price of ``symbol``.

        Args:
            symbol: A ticker symbol such as ``AAPL``. It is the only thing
                about the user that is sent.

        Raises:
            ValueError: ``symbol`` is not a valid ticker symbol. Nothing was
                sent.
            MarketDataUnavailableError: The provider could not be reached in
                time, or the connection could not be verified.
            MarketDataKeyRejectedError: The provider did not accept the key.
            MarketDataRateLimitedError: Too many requests were made.
            MarketDataNoQuoteError: There is no price for ``symbol``.
            MarketDataResponseError: The answer was not usable.
        """
        if type(symbol) is not str or SYMBOL_PATTERN.fullmatch(symbol) is None:
            raise ValueError("not a valid ticker symbol")
        result = self._fetch(symbol)
        if isinstance(result, _Failure):
            # Raised here, outside every handler, so that no earlier error
            # (whose text is not checked) is attached to this one.
            error_class, sentence = _ERRORS[result]
            raise error_class(sentence)
        return result

    def _fetch(self, symbol: str) -> Quote | _Failure:
        """Make the request under a hard time limit and report what happened."""
        try:
            connection = _open_connection(self._timeout)
        except OSError:
            return _Failure.UNREACHABLE
        timed_out = threading.Event()
        finished = threading.Event()
        watchdog = threading.Thread(
            target=_watch,
            args=(connection, self._timeout, timed_out, finished),
            name="potato-market-data-watchdog",
            daemon=True,
        )
        try:
            watchdog.start()
            outcome = self._exchange(connection, symbol)
        except ssl.SSLCertVerificationError:
            outcome = _Failure.NOT_SECURE
        except (OSError, http.client.HTTPException):
            # Covers refused connections, timeouts, other TLS failures and
            # replies that are not HTTP. The error's own text is not kept.
            outcome = _Failure.UNREACHABLE
        finally:
            finished.set()
            if watchdog.ident is not None:
                # The watchdog must have stopped before its handle is closed.
                watchdog.join()
            if connection.guard is not None:
                connection.guard.close()
            connection.close()
        if timed_out.is_set():
            # Whatever was read before the cut is not complete.
            return _Failure.TIMED_OUT
        return outcome

    def _exchange(self, connection: _Connection, symbol: str) -> Quote | _Failure:
        """Send the one request and read the one reply."""
        connection.request(
            "GET",
            _QUOTE_PATH + symbol,
            headers={
                _KEY_HEADER: self._key,
                "Accept": "application/json",
                "User-Agent": "Potato",
            },
        )
        response = connection.getresponse()
        try:
            if response.status != 200:
                return _STATUS_FAILURES.get(response.status, _Failure.REFUSED)
            raw = _read_capped(response)
        finally:
            response.close()
        if raw is None:
            return _Failure.TOO_LARGE
        return _read_quote(symbol, raw)
