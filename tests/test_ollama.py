"""Tests for the Ollama client (T-LLM-6, T-LLM-7, T-NET-3; R5).

A small fake Ollama server runs on loopback for each test, so that every bad
behaviour is played for real: oversized replies, slow replies, redirects and
nonsense.
"""

import json
import socket
import sys
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler
from typing import Any

import pytest

import potato.integrations.ollama as ollama_module
from fake_ollama import MODEL, FakeOllama, chat_reply, send_json
from potato.integrations.ollama import (
    MAX_MESSAGE_CHARACTERS,
    MAX_RESPONSE_BYTES,
    Message,
    OllamaClient,
    OllamaModelMissingError,
    OllamaResponseError,
    OllamaUnavailableError,
    Reply,
    Role,
)

CANARY = "server-said-canary-5521"
USER = [Message(Role.USER, "hello")]
TOOL = {"type": "function", "function": {"name": "open_app", "parameters": {}}}


@pytest.fixture
def server() -> Iterator[FakeOllama]:
    fake = FakeOllama()
    yield fake
    fake.close()


def make_client(port: int, host: str = "127.0.0.1", **options: Any) -> OllamaClient:
    settings: dict[str, Any] = {
        "timeout_seconds": 5.0,
        "context_length": 4096,
        "keep_alive_seconds": 300,
    }
    settings.update(options)
    return OllamaClient(host, port, MODEL, **settings)


@pytest.fixture
def client(server: FakeOllama) -> OllamaClient:
    return make_client(server.port)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


# --- Where it connects (T-NET-3, T-LLM-6) ------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "localhost", "ollama.local", "example.org", "0.0.0.0", "192.168.1.10", "10.0.0.1",  # noqa: S104
        "::", "::ffff:127.0.0.1", "127.000.0.1", "fe80::1%lo0", " 127.0.0.1", "127.0.0.1 ",
        "[::1]", "", "http://127.0.0.1", "127.0.0.1:11434", 2130706433, None,
        "0:0:0:0:0:0:0:1", "::0001", "0000::1",
    ],
)  # fmt: skip
def test_only_loopback_addresses_are_accepted(host: Any) -> None:
    with pytest.raises(ValueError, match="host"):
        OllamaClient(
            host, 11434, MODEL, timeout_seconds=5, context_length=4096, keep_alive_seconds=0
        )


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1"])
def test_loopback_addresses_are_accepted(host: str) -> None:
    OllamaClient(host, 11434, MODEL, timeout_seconds=5, context_length=4096, keep_alive_seconds=0)


def test_ipv6_loopback_is_bracketed_for_http_client() -> None:
    # Without brackets, http.client reads "::1" as host ":" and port 1.
    assert ollama_module._require_loopback_host("::1") == "[::1]"
    assert ollama_module._require_loopback_host("127.0.0.1") == "127.0.0.1"


def test_ipv6_loopback_really_works() -> None:
    try:
        fake = FakeOllama("::1")
    except OSError:
        pytest.skip("IPv6 loopback is not available here")
    try:
        assert make_client(fake.port, host="::1").chat(USER).text == "Hi."
    finally:
        fake.close()


@pytest.mark.parametrize("model", ["gpt-oss:120b-cloud", "qwen3:cloud", "", 5, None])
def test_cloud_and_empty_model_names_are_refused(model: Any) -> None:
    with pytest.raises(ValueError, match="model"):
        OllamaClient("127.0.0.1", 11434, model, timeout_seconds=5, context_length=4096,
                     keep_alive_seconds=0)  # fmt: skip


@pytest.mark.parametrize(
    "options",
    [
        {"timeout_seconds": 0}, {"timeout_seconds": -1}, {"timeout_seconds": 601},
        {"timeout_seconds": float("nan")}, {"timeout_seconds": True}, {"context_length": 0},
        {"context_length": 4096.0}, {"keep_alive_seconds": -1}, {"keep_alive_seconds": "5m"},
    ],
)  # fmt: skip
def test_bad_settings_are_refused(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        make_client(11434, **options)


@pytest.mark.parametrize("port", [0, 65536, -1, "11434", 11434.0, True])
def test_bad_ports_are_refused(port: Any) -> None:
    with pytest.raises(ValueError, match="port"):
        make_client(port)


def test_redirects_are_not_followed(server: FakeOllama) -> None:
    elsewhere = FakeOllama()
    try:

        def redirect(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
            handler.send_response(307)
            handler.send_header("Location", f"http://127.0.0.1:{elsewhere.port}/api/chat")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        server.respond = redirect
        with pytest.raises(OllamaResponseError):
            make_client(server.port).chat(USER)
        assert elsewhere.requests == []
    finally:
        elsewhere.close()


def test_proxy_settings_in_the_environment_are_ignored(
    server: FakeOllama, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy = FakeOllama()
    try:
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        assert make_client(server.port).chat(USER).text == "Hi."
        assert proxy.requests == []
        assert len(server.requests) == 1
    finally:
        proxy.close()


# R5 needs to see sockets being bound, which Python reports to audit hooks.
_BOUND: list[object] = []
_WATCHING = threading.Event()


def _hook(event: str, args: tuple[object, ...]) -> None:
    if _WATCHING.is_set() and event in {"socket.bind", "socket.listen"}:
        _BOUND.append(args)


sys.addaudithook(_hook)


def test_the_client_never_opens_a_listening_socket(client: OllamaClient) -> None:
    # The fake server is already listening, so anything recorded here was
    # done by the client.
    _BOUND.clear()
    _WATCHING.set()
    try:
        client.is_available()
        client.chat(USER, [TOOL])
        client.unload()
    finally:
        _WATCHING.clear()
    assert _BOUND == []


def test_the_hook_does_notice_a_bind() -> None:
    _BOUND.clear()
    _WATCHING.set()
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
    finally:
        _WATCHING.clear()
    assert _BOUND


# --- What it sends -----------------------------------------------------------


def test_chat_sends_exactly_the_expected_request(server: FakeOllama, client: OllamaClient) -> None:
    messages = [Message(Role.SYSTEM, "Be brief."), Message(Role.USER, "hello")]
    client.chat(messages)
    ((method, path, body),) = server.requests
    assert (method, path) == ("POST", "/api/chat")
    assert body == {
        "model": MODEL,
        "messages": [{"role": "system", "content": "Be brief."},
                     {"role": "user", "content": "hello"}],
        "stream": False,
        "think": False,
        "keep_alive": 300,
        "options": {"num_ctx": 4096},
    }  # fmt: skip


def test_tools_are_sent_only_when_offered(server: FakeOllama, client: OllamaClient) -> None:
    client.chat(USER, [TOOL])
    assert server.requests[-1][2]["tools"] == [TOOL]  # type: ignore[index]
    client.chat(USER)
    assert "tools" not in server.requests[-1][2]  # type: ignore[operator]


def test_unload_asks_ollama_to_free_the_model(server: FakeOllama, client: OllamaClient) -> None:
    client.unload()
    assert server.requests == [("POST", "/api/generate", {"model": MODEL, "keep_alive": 0})]


@pytest.mark.parametrize(
    "build",
    [
        lambda: Message("user", "x"),  # type: ignore[arg-type]
        lambda: Message(Role.USER, "x" * (MAX_MESSAGE_CHARACTERS + 1)),
        lambda: Message(Role.USER, b"x"),  # type: ignore[arg-type]
    ],
)
def test_bad_messages_are_refused(build: Callable[[], Message]) -> None:
    with pytest.raises(ValueError):
        build()


def test_conversation_size_is_bounded(client: OllamaClient) -> None:
    with pytest.raises(ValueError, match="messages"):
        client.chat([])
    with pytest.raises(ValueError, match="messages"):
        client.chat([Message(Role.USER, "x")] * 65)
    with pytest.raises(ValueError, match="Message"):
        client.chat([{"role": "user", "content": "x"}])  # type: ignore[list-item]
    with pytest.raises(ValueError, match="tools"):
        client.chat(USER, [TOOL] * 33)


# --- What it accepts ---------------------------------------------------------


def test_a_normal_reply(client: OllamaClient) -> None:
    assert client.chat(USER) == Reply("Hi.", ())


def test_control_characters_are_removed_and_thinking_is_dropped(
    server: FakeOllama, client: OllamaClient
) -> None:
    text = "Line one\nTab\there\x1b[31mred\x07\x00\u009b end"
    server.respond = lambda h, p, b: send_json(h, chat_reply(text, thinking="secret plan"))
    reply = client.chat(USER)
    assert reply.text == "Line one\nTab\there[31mred end"
    assert "secret plan" not in repr(reply)


def test_tool_calls_become_proposals_for_the_gate(server: FakeOllama, client: OllamaClient) -> None:
    calls = [
        {"function": {"name": "open_app", "arguments": {"name": "Safari"}}},
        {"function": {"name": "run_shell", "arguments": {"command": "rm -rf ~"}}},
        {"function": {"name": "security_posture"}},
    ]
    server.respond = lambda h, p, b: send_json(h, chat_reply("", tool_calls=calls))
    reply = client.chat(USER, [TOOL])
    # The client only reshapes. Refusing run_shell is the gate's job.
    assert reply.proposals == (
        {"tool": "open_app", "arguments": {"name": "Safari"}},
        {"tool": "run_shell", "arguments": {"command": "rm -rf ~"}},
        {"tool": "security_posture", "arguments": {}},
    )


def test_a_tool_call_when_no_tools_were_offered_is_refused(
    server: FakeOllama, client: OllamaClient
) -> None:
    calls = [{"function": {"name": "open_app", "arguments": {"name": "Safari"}}}]
    server.respond = lambda h, p, b: send_json(h, chat_reply("", tool_calls=calls))
    with pytest.raises(OllamaResponseError, match="none were offered"):
        client.chat(USER)


@pytest.mark.parametrize(
    "body",
    [
        {"message": {"role": "assistant", "content": "Hi."}},
        {**chat_reply(), "done": False},
        {**chat_reply(), "done": "true"},
        {"done": True},
        {"done": True, "message": "Hi."},
        {"done": True, "message": {"role": "user", "content": "Hi."}},
        {"done": True, "message": {"role": "tool", "content": "Hi."}},
        chat_reply(5),
        chat_reply(None),
        chat_reply("x" * (16 * 1024 + 1)),
        chat_reply("", tool_calls="open_app"),
        chat_reply("", tool_calls=[{"function": {"name": "a"}}] * 5),
        chat_reply("", tool_calls=[{"name": "open_app"}]),
        chat_reply("", tool_calls=[{"function": {"name": 5}}]),
        chat_reply("", tool_calls=[{"function": {"arguments": {}}}]),
        chat_reply("", tool_calls=[{"function": {"name": "a", "arguments": "{}"}}]),
        chat_reply("", tool_calls=[{"function": {"name": "a", "arguments": ["x"]}}]),
        chat_reply("", tool_calls=["open_app"]),
        [chat_reply()],
        "Hi.",
        None,
    ],
)
def test_replies_of_the_wrong_shape_are_refused(
    server: FakeOllama, client: OllamaClient, body: object
) -> None:
    server.respond = lambda h, p, b: send_json(h, body)
    with pytest.raises(OllamaResponseError):
        client.chat(USER, [TOOL])


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b'{"done": true, "message": {"role": "assistant", "content": NaN}}',
        b'{"x": Infinity}',
        # Valid in every way except a NaN in a field Potato does not read.
        b'{"done": true, "eval_duration": NaN, "message": {"role": "assistant", "content": "Hi."}}',
        b'{"done": true, "message": {"role": "assistant", "content": "Hi.", "score": -Infinity}}',
        b"\xff\xfe{}",
        b"[" * 100_000 + b"]" * 100_000,
        b"",
    ],
)
def test_replies_that_are_not_valid_json_are_refused(
    server: FakeOllama, client: OllamaClient, raw: bytes
) -> None:
    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    server.respond = respond
    with pytest.raises(OllamaResponseError):
        client.chat(USER)


@pytest.mark.parametrize("status", [201, 203, 204, 206, 299, 302, 304, 400, 404, 503])
def test_only_status_200_is_accepted(server: FakeOllama, client: OllamaClient, status: int) -> None:
    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        data = b"" if status in (204, 304) else json.dumps(chat_reply()).encode()
        handler.send_response(status)
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    server.respond = respond
    with pytest.raises(OllamaResponseError):
        client.chat(USER)


def test_a_missing_model_gets_its_own_clear_error(server: FakeOllama, client: OllamaClient) -> None:
    # What a real Ollama answers when the model has not been pulled.
    body = {"error": f"model '{CANARY}' not found"}
    server.respond = lambda h, p, b: send_json(h, body, status=404)
    with pytest.raises(OllamaModelMissingError) as caught:
        client.chat(USER)
    assert str(caught.value) == "the model is not installed in Ollama"
    assert CANARY not in repr(caught.value)
    assert caught.value.__cause__ is None
    # Code that handles any unusable reply still handles this one.
    assert isinstance(caught.value, OllamaResponseError)
    assert client.is_available() is False


def test_an_error_status_is_refused_without_repeating_the_server(
    server: FakeOllama, client: OllamaClient
) -> None:
    server.respond = lambda h, p, b: send_json(h, {"error": CANARY}, status=500)
    with pytest.raises(OllamaResponseError) as caught:
        client.chat(USER)
    assert CANARY not in str(caught.value)
    assert "500" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "body",
    [
        chat_reply("", tool_calls=[{"function": {"name": CANARY}}]),
        {"done": True, "message": {"role": CANARY, "content": "x"}},
        CANARY,
    ],
)
def test_no_error_repeats_what_the_server_sent(
    server: FakeOllama, client: OllamaClient, body: object
) -> None:
    server.respond = lambda h, p, b: send_json(h, body)
    with pytest.raises(OllamaResponseError) as caught:
        client.chat(USER)
    assert CANARY not in str(caught.value)
    assert CANARY not in repr(caught.value.__context__)


# --- Size and time limits ----------------------------------------------------


def test_a_reply_declared_too_large_is_refused_before_reading(
    server: FakeOllama, client: OllamaClient
) -> None:
    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", str(MAX_RESPONSE_BYTES + 1))
        handler.end_headers()
        handler.wfile.write(b"{")

    server.respond = respond
    with pytest.raises(OllamaResponseError, match="too large"):
        client.chat(USER)


def test_a_reply_that_grows_too_large_is_cut_off(server: FakeOllama, client: OllamaClient) -> None:
    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        # No Content-Length: the server simply keeps sending until it closes.
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            for _ in range(200):
                handler.wfile.write(b" " * 16384)
        except OSError:
            pass

    server.respond = respond
    with pytest.raises(OllamaResponseError, match="too large"):
        client.chat(USER)


@pytest.mark.parametrize("length", ["abc", "-1", "1e3", "١٢"])
def test_a_strange_content_length_is_refused(
    server: FakeOllama, client: OllamaClient, length: str
) -> None:
    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        handler.send_response(200)
        handler.send_header("Content-Length", length)
        handler.end_headers()

    server.respond = respond
    with pytest.raises((OllamaResponseError, OllamaUnavailableError)):
        client.chat(USER)


def test_a_server_that_drips_one_byte_at_a_time_is_cut_off(server: FakeOllama) -> None:
    stop = threading.Event()

    def respond(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            while not stop.is_set():
                handler.wfile.write(b" ")
                handler.wfile.flush()
                stop.wait(0.05)
        except OSError:
            pass

    server.respond = respond
    client = make_client(server.port, timeout_seconds=0.5)
    started = time.monotonic()
    try:
        with pytest.raises(OllamaUnavailableError):
            client.chat(USER)
    finally:
        stop.set()
    assert time.monotonic() - started < 3


def test_a_server_that_never_answers_times_out(server: FakeOllama) -> None:
    stop = threading.Event()
    server.respond = lambda h, p, b: stop.wait(10)  # type: ignore[assignment]
    client = make_client(server.port, timeout_seconds=0.3)
    started = time.monotonic()
    try:
        with pytest.raises(OllamaUnavailableError):
            client.chat(USER)
    finally:
        stop.set()
    assert time.monotonic() - started < 3


def test_a_request_that_is_too_large_is_not_sent(server: FakeOllama, client: OllamaClient) -> None:
    big = [Message(Role.USER, "x" * MAX_MESSAGE_CHARACTERS)] * 20
    with pytest.raises(ValueError, match="too large"):
        client.chat(big)
    assert server.requests == []


# --- Offline (T-LLM-7) -------------------------------------------------------


def test_nothing_listening_means_offline() -> None:
    client = make_client(_free_port())
    with pytest.raises(OllamaUnavailableError) as caught:
        client.chat(USER)
    assert caught.value.__cause__ is None
    with pytest.raises(OllamaUnavailableError):
        client.unload()
    assert client.is_available() is False


def test_a_server_that_hangs_up_means_offline(server: FakeOllama, client: OllamaClient) -> None:
    def hang_up(handler: BaseHTTPRequestHandler, path: str, body: object) -> None:
        handler.close_connection = True
        handler.connection.shutdown(socket.SHUT_RDWR)

    server.respond = hang_up
    with pytest.raises(OllamaUnavailableError):
        client.chat(USER)


def test_availability_needs_the_model_to_be_installed(server: FakeOllama) -> None:
    assert make_client(server.port).is_available() is True
    other = OllamaClient("127.0.0.1", server.port, "mistral:7b", timeout_seconds=5,
                         context_length=4096, keep_alive_seconds=0)  # fmt: skip
    assert other.is_available() is False


@pytest.mark.parametrize(
    "body", [{"models": "qwen3:8b"}, {"models": [MODEL]}, {}, [], {"models": [{"name": 5}]}]
)
def test_a_strange_model_list_means_not_available(
    server: FakeOllama, client: OllamaClient, body: object
) -> None:
    server.respond = lambda h, p, b: send_json(h, body)
    assert client.is_available() is False


def test_repr_shows_only_settings(client: OllamaClient, server: FakeOllama) -> None:
    assert repr(client) == f"<OllamaClient 127.0.0.1:{server.port} {MODEL}>"
