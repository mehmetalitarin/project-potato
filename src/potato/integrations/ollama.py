"""The client for Ollama, the local model server.

This is the only code that talks to the model. Everything it receives is
treated as untrusted, whoever sent it (T-LLM-7 in ``docs/threat_model.md``):

- **Loopback only** (T-NET-3, T-LLM-6). The address must be a loopback IP
  literal. The settings check this already; the client checks again. It uses
  ``http.client`` directly, which never follows redirects and never reads
  proxy settings from the environment, so a request cannot be sent anywhere
  else.
- **Bounded.** Every response is size-capped and must arrive within a total
  time limit, not just a limit per read, so a server that sends one byte at a
  time is cut off too.
- **Strict.** A reply must have exactly the expected shape. A tool call comes
  back as a plain proposal for the gate, which decides whether anything runs.
- **Quiet errors.** No error message contains anything the server sent.

Potato asks Ollama not to "think" out loud, and drops any thinking text that
comes back anyway: it is not shown and not used.
"""

import http.client
import ipaddress
import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MAX_RESPONSE_BYTES: Final = 1024 * 1024
MAX_REQUEST_BYTES: Final = 512 * 1024
MAX_MESSAGES: Final = 64
MAX_MESSAGE_CHARACTERS: Final = 32 * 1024
MAX_REPLY_CHARACTERS: Final = 16 * 1024
MAX_TOOL_CALLS: Final = 4
MAX_TOOLS: Final = 32
_CHUNK_BYTES: Final = 16 * 1024


class Role(StrEnum):
    """Who wrote a message in a conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass(frozen=True, slots=True)
class Message:
    """One message sent to the model."""

    role: Role
    content: str

    def __post_init__(self) -> None:
        """Refuse a role that is not a ``Role`` or text that is too long."""
        if not isinstance(self.role, Role):
            raise ValueError("role must be a Role")
        if type(self.content) is not str or len(self.content) > MAX_MESSAGE_CHARACTERS:
            raise ValueError(f"content must be text of at most {MAX_MESSAGE_CHARACTERS} characters")


@dataclass(frozen=True, slots=True)
class Reply:
    """What the model answered.

    Attributes:
        text: The answer, with control characters removed.
        proposals: Tool calls the model asked for, each shaped as the gate
            expects: ``{"tool": name, "arguments": {...}}``. Untrusted.
    """

    text: str
    proposals: tuple[dict[str, object], ...]


class OllamaUnavailableError(Exception):
    """Ollama could not be reached, or did not answer in time. Potato is offline."""


class OllamaResponseError(Exception):
    """Ollama answered, but with something Potato will not use."""


def _require_loopback_host(host: object) -> str:
    """Return ``host`` ready for ``http.client`` if it is a loopback IP literal, else raise."""
    if type(host) is not str:
        raise ValueError("host must be text")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("host must be a loopback IP address, not a name") from None
    if not address.is_loopback or str(address) != host:
        raise ValueError("host must be a loopback IP address in standard form")
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None or address.ipv4_mapped is not None:
            raise ValueError("host must be a plain loopback IP address")
        # http.client reads "::1" as host ":" and port 1 without the brackets.
        return f"[{host}]"
    return host


def _strip_control_characters(text: str) -> str:
    """Remove control characters except line breaks and tabs."""
    return "".join(
        character
        for character in text
        if character in "\n\t" or (ord(character) >= 0x20 and not 0x7F <= ord(character) <= 0x9F)
    )


class OllamaClient:
    """Talks to one model on a local Ollama server. Not thread-safe."""

    def __init__(
        self,
        host: str,
        port: int,
        model: str,
        *,
        timeout_seconds: float,
        context_length: int,
        keep_alive_seconds: int,
    ) -> None:
        """Check the address and remember the settings. Connects to nothing.

        Args:
            host: A loopback IP literal, such as ``127.0.0.1`` or ``::1``.
            port: The server's port.
            model: The model name, from the validated settings.
            timeout_seconds: The longest any one request may take in total.
            context_length: How much text the model may consider at once.
            keep_alive_seconds: How long Ollama keeps the model loaded after
                a request. Potato also unloads it itself after the idle
                timeout.

        Raises:
            ValueError: An argument is out of bounds, or ``host`` is not a
                loopback address.
        """
        self._host = _require_loopback_host(host)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("port must be from 1 to 65535")
        if type(model) is not str or not model or model.endswith("cloud"):
            # Cloud models run on Ollama's servers, not on this Mac (T-LLM-6).
            raise ValueError("model must be the name of a local model")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 600:
            raise ValueError("timeout_seconds must be above 0 and at most 600")
        if type(context_length) is not int or context_length < 1:
            raise ValueError("context_length must be a positive whole number")
        if type(keep_alive_seconds) is not int or keep_alive_seconds < 0:
            raise ValueError("keep_alive_seconds must be a whole number of at least 0")
        self._port = port
        self._model = model
        self._timeout = float(timeout_seconds)
        self._context_length = context_length
        self._keep_alive = keep_alive_seconds

    def __repr__(self) -> str:
        """Show the settings, which hold nothing secret."""
        return f"<OllamaClient {self._host}:{self._port} {self._model}>"

    def is_available(self) -> bool:
        """Return ``True`` if Ollama answers and has the model installed.

        Never raises: anything that goes wrong means "not available".
        """
        try:
            body = self._request("GET", "/api/tags", None)
            models = body.get("models")
            if type(models) is not list:
                return False
            return any(type(m) is dict and m.get("name") == self._model for m in models)
        except (OllamaUnavailableError, OllamaResponseError):
            return False

    def chat(
        self, messages: Sequence[Message], tools: Sequence[Mapping[str, object]] = ()
    ) -> Reply:
        """Send a conversation and return the model's reply.

        Args:
            messages: The conversation so far.
            tools: Descriptions of the tools the model may propose, in
                Ollama's format. Empty means the model is offered no tools,
                and any tool call it makes anyway is refused.

        Raises:
            ValueError: Too many messages or tools.
            OllamaUnavailableError: Ollama could not be reached in time.
            OllamaResponseError: The reply was not usable.
        """
        if not 1 <= len(messages) <= MAX_MESSAGES:
            raise ValueError(f"there must be 1 to {MAX_MESSAGES} messages")
        if not all(isinstance(message, Message) for message in messages):
            raise ValueError("every message must be a Message")
        if len(tools) > MAX_TOOLS:
            raise ValueError(f"at most {MAX_TOOLS} tools can be offered")
        request: dict[str, object] = {
            "model": self._model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "stream": False,
            "think": False,
            "keep_alive": self._keep_alive,
            "options": {"num_ctx": self._context_length},
        }
        if tools:
            request["tools"] = [dict(tool) for tool in tools]
        body = self._request("POST", "/api/chat", request)
        return self._read_reply(body, tools_offered=bool(tools))

    def unload(self) -> None:
        """Ask Ollama to free the model's memory now.

        Raises:
            OllamaUnavailableError: Ollama could not be reached in time.
            OllamaResponseError: Ollama refused.
        """
        self._request("POST", "/api/generate", {"model": self._model, "keep_alive": 0})

    def _read_reply(self, body: dict[str, object], *, tools_offered: bool) -> Reply:
        """Check the reply's shape and turn it into a ``Reply``."""
        if body.get("done") is not True:
            raise OllamaResponseError("the reply was incomplete")
        message = body.get("message")
        if type(message) is not dict or message.get("role") != "assistant":
            raise OllamaResponseError("the reply had no assistant message")
        content = message.get("content", "")
        if type(content) is not str or len(content) > MAX_REPLY_CHARACTERS:
            raise OllamaResponseError("the reply's text was not usable")

        calls = message.get("tool_calls", [])
        if type(calls) is not list or len(calls) > MAX_TOOL_CALLS:
            raise OllamaResponseError("the reply's tool calls were not usable")
        if calls and not tools_offered:
            # The model was offered no tools, so a call means something is
            # wrong: an impostor server, or a prompt-injection attempt.
            raise OllamaResponseError("the model called a tool when none were offered")
        proposals = tuple(_proposal(call) for call in calls)
        return Reply(_strip_control_characters(content), proposals)

    def _request(self, method: str, path: str, payload: object) -> dict[str, object]:
        """Send one request and return the JSON object that comes back."""
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("ascii")
            if len(data) > MAX_REQUEST_BYTES:
                raise ValueError("the request is too large")
            headers["Content-Type"] = "application/json"

        deadline = time.monotonic() + self._timeout
        connection = http.client.HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            # Closed here as well as with the connection: http.client lets
            # go of a reply that ends the connection, so closing the
            # connection alone would leave its socket open.
            try:
                if response.status != 200:
                    raise OllamaResponseError("Ollama refused the request")
                raw = _read_bounded(response, deadline)
            finally:
                response.close()
        except (OSError, http.client.HTTPException) as error:
            # Covers refused connections, timeouts and broken replies. The
            # error's own text is not kept.
            if isinstance(error, http.client.HTTPException) and not isinstance(
                error, http.client.RemoteDisconnected
            ):
                raise OllamaResponseError("the reply was not valid HTTP") from None
            raise OllamaUnavailableError("Ollama could not be reached") from None
        finally:
            connection.close()

        try:
            body = json.loads(raw.decode("utf-8"), parse_constant=_refuse_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            body = None
        if type(body) is not dict:
            raise OllamaResponseError("the reply was not a JSON object")
        return body


def _read_bounded(response: http.client.HTTPResponse, deadline: float) -> bytes:
    """Read the body, refusing one that is too large or too slow."""
    length = response.getheader("Content-Length")
    if length is not None and (
        not (length.isascii() and length.isdigit()) or int(length) > MAX_RESPONSE_BYTES
    ):
        raise OllamaResponseError("the reply was too large")
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError
        chunk = response.read1(_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise OllamaResponseError("the reply was too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _refuse_constant(name: str) -> object:
    """Refuse NaN and Infinity, which are not valid JSON."""
    raise ValueError("not valid JSON")


def _proposal(call: object) -> dict[str, object]:
    """Turn one tool call from the model into a proposal for the gate.

    Only the shape is checked here. Whether the tool exists and whether its
    arguments are allowed is the gate's decision.
    """
    function = call.get("function") if type(call) is dict else None
    if type(function) is not dict:
        raise OllamaResponseError("a tool call was not usable")
    name = function.get("name")
    arguments = function.get("arguments", {})
    if type(name) is not str or type(arguments) is not dict:
        raise OllamaResponseError("a tool call was not usable")
    return {"tool": name, "arguments": arguments}
