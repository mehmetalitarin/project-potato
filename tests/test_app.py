"""Tests for start-up (potato.app): how Potato's parts are put together.

Covers R4 (who gets the approval maker), R7 (the fixed list of tools), R8
(fail closed at start-up) and required test 14 (the model unloads after the
idle timeout). Potato is built for real: a real window drawn into memory, the
real gate, audit log and turn engine, and the real Ollama client talking to a
fake Ollama server on loopback.
"""

import ast
import json
import logging
import re
import time
import tokenize
from collections.abc import Callable, Iterator, Mapping
from decimal import Decimal
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel

import potato.app as app_module
from fake_ollama import FakeOllama, chat_reply, send_json
from potato.app import (
    EXIT_BAD_SETTINGS,
    EXIT_CANNOT_START,
    TEXT_CANNOT_START,
    Application,
    Locations,
    ModelUnloader,
    build,
    default_locations,
    enabled_tools,
    load_settings,
    run,
)
from potato.core.config import ConfigError, Settings, parse_settings
from potato.core.state import AssistantState, Event
from potato.core.turns import TurnResult, TurnStatus
from potato.integrations.ollama import OllamaClient
from potato.security.approvals import ApprovalIssuer
from potato.security.audit import AUDIT_FILE_NAME, AuditLog, verify_audit_chain
from potato.security.gate import Gate, RequestOrigin
from potato.security.redaction import Redactor
from potato.security.tools import ArgumentValue, ChoiceField, RiskLevel, ToolDefinition
from potato.storage.database import Database, Holding
from potato.ui.approval import ApprovalDialog
from potato.ui.window import POTATO, TEXT_DONE, YOU

SOURCE = Path(app_module.__file__)
PERMISSIONS = Path(__file__).parent.parent / "docs" / "permissions.md"


@pytest.fixture(scope="module")
def qt() -> QApplication:
    existing = QApplication.instance()
    return existing if isinstance(existing, QApplication) else QApplication([])


@pytest.fixture(autouse=True)
def keep_logging_as_it_was() -> Iterator[None]:
    # Building Potato replaces the handlers on the root logger.
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
def locations(tmp_path: Path) -> Locations:
    return Locations(
        settings=tmp_path / "settings.toml",
        logs=tmp_path / "Logs",
        database=tmp_path / "Data" / "potato.sqlite3",
    )


class Script:
    """What the fake model does: call a tool when asked to, then summarise."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, Any]] = {
            "check": {"name": "analyse_link", "arguments": {"link": "https://example.com/a"}},
            "wipe": {"name": "wipe", "arguments": {"target": "cache"}},
        }

    def __call__(
        self, handler: BaseHTTPRequestHandler, path: str, body: dict[str, Any] | None
    ) -> None:
        if path != "/api/chat" or body is None:
            send_json(handler, {})
            return
        messages = body["messages"]
        if any(message["role"] == "tool" for message in messages):
            send_json(handler, chat_reply("Here is what I found."))
            return
        words = messages[-1]["content"]
        for trigger, call in self.calls.items():
            if trigger in words:
                send_json(handler, chat_reply("", tool_calls=[{"function": call}]))
                return
        send_json(handler, chat_reply("Hello from the model."))


@pytest.fixture
def server() -> Iterator[FakeOllama]:
    fake = FakeOllama()
    fake.respond = Script()
    yield fake
    fake.close()


def settings_for(server: FakeOllama, extra: str = "") -> Settings:
    return parse_settings(f"[ollama]\nport = {server.port}\nrequest_timeout_seconds = 5\n{extra}")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def wait_for(qt: QApplication, condition: Callable[[], bool], seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        qt.processEvents()
        time.sleep(0.005)


def now(application: Application) -> AssistantState:
    """Read the state through a call, so the type checker does not assume it is fixed."""
    return application.state.state


def lines(application: Application) -> list[str]:
    return application.window.transcript.toPlainText().splitlines()


def say(qt: QApplication, application: Application, words: str) -> None:
    before = len(lines(application))
    application.window.entry.setText(words)
    application.window.send()
    wait_for(qt, lambda: len(lines(application)) >= before + 2 and not _thinking(application))


def _thinking(application: Application) -> bool:
    return application.window.busy and not application.window.findChildren(ApprovalDialog)


def records(locations: Locations) -> list[dict[str, Any]]:
    text = (locations.logs / AUDIT_FILE_NAME).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def requests_to(server: FakeOllama, path: str) -> list[dict[str, Any]]:
    return [body for _, where, body in server.requests if where == path and body is not None]


@pytest.fixture
def potato(qt: QApplication, server: FakeOllama, locations: Locations) -> Iterator[Application]:
    application = build(settings_for(server), locations)
    yield application
    application.close()
    qt.processEvents()


# --- The tools that are switched on (R7) -------------------------------------

ENABLED = {
    "calendar_upcoming": "low",
    "homework_deadlines": "low",
    "open_app": "low",
    "analyse_link": "low",
    "portfolio_summary": "low",
    "portfolio_add_holding": "medium",
    "portfolio_remove_holding": "sensitive",
    "security_posture": "low",
    "process_overview": "low",
    "network_overview": "low",
    "check_security_updates": "medium",
}
PLANNED = {"dependency_scan"}


def test_exactly_these_tools_are_switched_on(tmp_path: Path) -> None:
    tools = enabled_tools(tmp_path / "potato.sqlite3")
    assert {tool.name: tool.risk.value for tool in tools} == ENABLED
    assert len(tools) == len(ENABLED)  # No name appears twice.


def test_the_switched_on_tools_match_the_documented_table(tmp_path: Path) -> None:
    text = PERMISSIONS.read_text(encoding="utf-8")
    section = text.split("## Planned tools", 1)[1].split("\n## ", 1)[0]
    rows = dict(re.findall(r"^\| `([a-z_]+)` \|.*\| (Low|Medium|Sensitive) \|$", section, re.M))
    documented = {name: risk.lower() for name, risk in rows.items()}
    assert {name: documented[name] for name in ENABLED} == ENABLED
    assert set(documented) - set(ENABLED) == PLANNED


def test_every_tool_has_a_description_the_approval_dialog_can_show(tmp_path: Path) -> None:
    for tool in enabled_tools(tmp_path / "potato.sqlite3"):
        assert re.fullmatch(r"[\x20-\x7e]{10,200}", tool.description), tool.name


def test_listing_the_tools_touches_nothing(tmp_path: Path) -> None:
    enabled_tools(tmp_path / "Data" / "potato.sqlite3")
    assert list(tmp_path.iterdir()) == []


def test_the_gate_holds_exactly_the_switched_on_tools(potato: Application) -> None:
    gate = potato.window._gate
    assert isinstance(gate, Gate)
    assert set(gate.available_tools(RequestOrigin.TYPED)) == set(ENABLED)
    assert set(gate.available_tools(RequestOrigin.VOICE)) == {
        name for name, risk in ENABLED.items() if risk == "low"
    }


def test_settings_cannot_add_a_tool(server: FakeOllama) -> None:
    for extra in ('[tools]\nenabled = ["shell"]\n', "[security]\nextra_tools = 1\n"):
        with pytest.raises(ConfigError):
            settings_for(server, extra)


# --- Who gets the approval maker (R4) ----------------------------------------


def _tree() -> ast.Module:
    return ast.parse(SOURCE.read_text(encoding="utf-8"))


Place = tuple[int, int]


def _loads(name: str) -> list[Place]:
    """Where in the file ``name`` is read, as line and column."""
    return [
        (node.lineno, node.col_offset)
        for node in ast.walk(_tree())
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
    ]


def _keyword_uses(function: str, keyword: str) -> list[Place]:
    """Where ``function(keyword=...)`` is called, as the place of the value."""
    return [
        (item.value.lineno, item.value.col_offset)
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == function
        for item in node.keywords
        if item.arg == keyword
    ]


def test_the_pair_is_made_exactly_once_and_named_plainly() -> None:
    made = [
        node
        for node in ast.walk(_tree())
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "create_approval_pair"
    ]
    assert len(made) == 1
    (target,) = made[0].targets
    assert isinstance(target, ast.Tuple)
    assert [element.id for element in target.elts if isinstance(element, ast.Name)] == [
        "issuer",
        "verifier",
    ]
    assert len(_loads("create_approval_pair")) == 1
    stores = [
        node
        for node in ast.walk(_tree())
        if isinstance(node, ast.Name)
        and node.id in ("issuer", "verifier")
        and isinstance(node.ctx, ast.Store)
    ]
    assert len(stores) == 2


def test_the_maker_is_handed_to_the_window_and_used_nowhere_else() -> None:
    uses = _loads("issuer")
    assert len(uses) == 1
    assert _keyword_uses("PotatoWindow", "issuer") == uses
    # No attribute, argument or other spelling carries it anywhere else:
    # the word appears in the code three times (made, "issuer=", handed over).
    with SOURCE.open("rb") as file:
        names = [token.string for token in tokenize.tokenize(file.readline)]
    assert names.count("issuer") == 3
    assert not any(
        "issuer" in name.lower() and name != "issuer" for name in names if name.isidentifier()
    )


def test_the_gate_gets_only_the_half_that_checks() -> None:
    uses = _loads("verifier")
    assert len(uses) == 1
    assert _keyword_uses("Gate", "approvals") == uses


def test_only_the_window_holds_the_maker(potato: Application) -> None:
    assert isinstance(potato.window._issuer, ApprovalIssuer)
    for holder in (potato, potato.state, potato.window._gate, potato.window._conversation):
        held = vars(holder).values() if hasattr(holder, "__dict__") else ()
        assert not any(isinstance(value, ApprovalIssuer) for value in held)
    assert not any(isinstance(value, ApprovalIssuer) for value in vars(app_module).values())


def test_run_never_chooses_the_tools_itself() -> None:
    assert _keyword_uses("build", "tools") == []
    assert _keyword_uses("build", "clock") == []
    # The entry point only starts Potato: it cannot build it differently.
    entry = SOURCE.with_name("__main__.py").read_text(encoding="utf-8")
    assert "from potato.app import run\n" in entry
    assert not re.search(r"\b(build|enabled_tools|Application)\(", entry)


# --- A whole conversation ----------------------------------------------------


def test_nothing_happens_until_the_user_acts(
    potato: Application, server: FakeOllama, locations: Locations
) -> None:
    assert now(potato) is AssistantState.SLEEPING
    assert server.requests == []
    assert not potato.window.isVisible()
    assert not locations.database.exists()


def test_a_typed_request_reaches_the_model_and_the_reply_is_shown(
    qt: QApplication, potato: Application, server: FakeOllama
) -> None:
    say(qt, potato, "hello")
    assert lines(potato) == [f"{YOU}: hello", f"{POTATO}: Hello from the model."]
    assert now(potato) is AssistantState.ACTIVE
    (chat,) = requests_to(server, "/api/chat")
    assert chat["model"] == "qwen3:14b"
    assert {tool["function"]["name"] for tool in chat["tools"]} == set(ENABLED)


def test_potato_remembers_the_conversation_until_it_sleeps(
    qt: QApplication, potato: Application, server: FakeOllama
) -> None:
    say(qt, potato, "my name is Mehmet")
    say(qt, potato, "what's my name?")
    second = requests_to(server, "/api/chat")[1]["messages"]
    assert {"role": "user", "content": "my name is Mehmet"} in second
    assert {"role": "assistant", "content": "Hello from the model."} in second

    potato.window.sleep_button.click()
    say(qt, potato, "what's my name?")
    third = requests_to(server, "/api/chat")[2]["messages"]
    assert [m["role"] for m in third] == ["system", "user"]


def test_the_smaller_model_can_be_chosen(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    settings = parse_settings(f'[ollama]\nport = {server.port}\nmodel = "qwen3:8b"\n')
    application = build(settings, locations)
    try:
        say(qt, application, "hello")
        assert requests_to(server, "/api/chat")[0]["model"] == "qwen3:8b"
    finally:
        application.close()


def test_a_tool_runs_through_the_gate_and_is_audited(
    qt: QApplication, potato: Application, server: FakeOllama, locations: Locations
) -> None:
    say(qt, potato, "check this link")
    assert lines(potato)[-1] == f"{POTATO}: Here is what I found."
    chats = requests_to(server, "/api/chat")
    assert len(chats) == 2
    assert "tools" not in chats[1]  # Pass 2 is offered no tools.
    executed = [r["data"] for r in records(locations) if r["event"] == "tool_executed"]
    assert [(r["tool"], r["origin"], r["outcome"]) for r in executed] == [
        ("analyse_link", "typed", "ok")
    ]


def test_ollama_is_told_to_drop_the_model_by_itself_after_the_idle_time(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    application = build(
        settings_for(server, "[assistant]\nidle_timeout_seconds = 90.5\n"), locations
    )
    try:
        say(qt, application, "hello")
        assert requests_to(server, "/api/chat")[0]["keep_alive"] == 91
    finally:
        application.close()


def test_when_ollama_is_not_running_potato_says_so(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    settings = settings_for(server)
    server.close()
    application = build(settings, locations)
    try:
        say(qt, application, "hello")
        assert "Ollama" in lines(application)[-1] or "AI engine" in lines(application)[-1]
    finally:
        application.close()


# --- A sensitive action, through everything ----------------------------------


@pytest.fixture
def wiped() -> list[dict[str, ArgumentValue]]:
    return []


@pytest.fixture
def with_wipe(
    qt: QApplication,
    server: FakeOllama,
    locations: Locations,
    wiped: list[dict[str, ArgumentValue]],
) -> Iterator[Application]:
    def wipe(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        wiped.append(dict(arguments))
        return {"wiped": True}

    tool = ToolDefinition(
        name="wipe",
        risk=RiskLevel.SENSITIVE,
        arguments={"target": ChoiceField(frozenset({"cache", "history"}))},
        handler=wipe,
        description="Wipe a test folder that exists only in the tests.",
    )
    application = build(settings_for(server), locations, tools=[tool])
    application.window._approve_delay_ms = 0
    yield application
    application.close()
    qt.processEvents()


def _dialog(qt: QApplication, application: Application) -> ApprovalDialog:
    wait_for(qt, lambda: bool(application.window.findChildren(ApprovalDialog)))
    (dialog,) = application.window.findChildren(ApprovalDialog)
    wait_for(qt, lambda: dialog.armed)
    return dialog


def test_a_sensitive_action_waits_for_a_real_press_then_runs_once(
    qt: QApplication,
    with_wipe: Application,
    wiped: list[dict[str, ArgumentValue]],
    locations: Locations,
) -> None:
    say(qt, with_wipe, "wipe it")
    dialog = _dialog(qt, with_wipe)
    assert wiped == []
    shown = {label.text() for label in dialog.findChildren(QLabel)}
    assert "Action: wipe" in shown
    assert 'target: "cache"' in shown
    assert "Wipe a test folder that exists only in the tests." in shown

    dialog.approve_button.click()  # A press made by code.
    qt.processEvents()
    assert wiped == []

    QTest.mouseClick(dialog.approve_button, Qt.MouseButton.LeftButton)
    wait_for(qt, lambda: lines(with_wipe)[-1] == f"{POTATO}: {TEXT_DONE}")
    assert wiped == [{"target": "cache"}]
    events = [(r["event"], r["data"].get("decision")) for r in records(locations)]
    assert ("approval_decided", "approved") in events
    executed = [r["data"] for r in records(locations) if r["event"] == "tool_executed"]
    assert [(r["tool"], r["origin"]) for r in executed] == [("wipe", "typed")]


def test_denying_a_sensitive_action_runs_nothing(
    qt: QApplication, with_wipe: Application, wiped: list[dict[str, ArgumentValue]]
) -> None:
    say(qt, with_wipe, "wipe it")
    dialog = _dialog(qt, with_wipe)
    QTest.keyClick(dialog, Qt.Key.Key_Return)
    wait_for(qt, lambda: not with_wipe.window.busy)
    assert wiped == []


def test_removing_a_real_holding_needs_a_real_click_on_approve(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    # The real portfolio tool, the real gate and the real dialog, end to end.
    server.respond.calls["remove"] = {  # type: ignore[attr-defined]
        "name": "portfolio_remove_holding",
        "arguments": {"symbol": "AAPL"},
    }
    with Database(locations.database) as database:
        database.set_holding(Holding("AAPL", Decimal(2), Decimal(150)))
    application = build(settings_for(server), locations)
    application.window._approve_delay_ms = 0
    try:
        say(qt, application, "remove my apple shares")
        dialog = _dialog(qt, application)
        shown = {label.text() for label in dialog.findChildren(QLabel)}
        assert "Action: portfolio_remove_holding" in shown
        assert 'symbol: "AAPL"' in shown
        dialog.approve_button.click()  # A press made by code does nothing.
        qt.processEvents()
        with Database(locations.database) as database:
            assert [holding.symbol for holding in database.holdings()] == ["AAPL"]

        QTest.mouseClick(dialog.approve_button, Qt.MouseButton.LeftButton)
        wait_for(qt, lambda: lines(application)[-1] == f"{POTATO}: {TEXT_DONE}")
        with Database(locations.database) as database:
            assert database.holdings() == []
    finally:
        application.close()


# --- The model leaves memory (required test 14) ------------------------------


def _unloads(server: FakeOllama) -> list[dict[str, Any]]:
    return requests_to(server, "/api/generate")


def test_the_model_unloads_after_the_idle_timeout(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    clock = FakeClock()
    application = build(
        settings_for(server, "[assistant]\nidle_timeout_seconds = 120\n"), locations, clock=clock
    )
    try:
        say(qt, application, "hello")
        assert now(application) is AssistantState.ACTIVE
        clock.now += 119
        assert application.check_idle() is False
        assert _unloads(server) == []

        clock.now += 2
        assert application.check_idle() is True
        assert now(application) is AssistantState.STANDBY
        wait_for(qt, lambda: bool(_unloads(server)))
        assert _unloads(server) == [{"model": "qwen3:14b", "keep_alive": 0}]
    finally:
        application.close()


def test_the_idle_check_runs_on_a_timer(potato: Application) -> None:
    timer = potato._idle_timer
    assert timer.isActive()
    assert timer.interval() == app_module.IDLE_CHECK_MS == 5000


def test_a_request_in_progress_is_not_cut_off_by_the_idle_timeout(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    clock = FakeClock()
    application = build(settings_for(server), locations, clock=clock)
    try:
        say(qt, application, "hello")
        application.window._set_busy(True)
        clock.now += 10_000
        assert application.check_idle() is False
        assert now(application) is AssistantState.ACTIVE
        application.window._set_busy(False)
        assert application.check_idle() is True
    finally:
        application.close()


def test_a_slow_reply_still_leaves_time_to_read_it(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    # The idle timer counts from when the reply arrives, not from when the
    # request was sent.
    clock = FakeClock()
    application = build(settings_for(server), locations, clock=clock)
    try:
        say(qt, application, "hello")
        clock.now += 400
        application.window._show_result(TurnResult(TurnStatus.ANSWERED, "A slow answer."))
        assert application.check_idle() is False
        clock.now += 301
        assert application.check_idle() is True
    finally:
        application.close()


def test_the_model_is_never_asked_unless_potato_is_active(
    potato: Application, server: FakeOllama
) -> None:
    # The turn engine checks the state itself, whatever the window does.
    engine = potato.window._conversation
    assert now(potato) is AssistantState.SLEEPING
    result = engine.run("hello", RequestOrigin.TYPED)
    assert result.status is TurnStatus.REFUSED
    assert server.requests == []


def test_a_reply_restarts_the_idle_timer(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    clock = FakeClock()
    application = build(settings_for(server), locations, clock=clock)
    try:
        say(qt, application, "hello")
        clock.now += 299
        say(qt, application, "hello again")
        clock.now += 299
        assert application.check_idle() is False
    finally:
        application.close()


@pytest.mark.parametrize("how", ["sleep_button", "failure", "close"])
def test_the_model_unloads_whenever_potato_leaves_the_active_state(
    qt: QApplication, server: FakeOllama, locations: Locations, how: str
) -> None:
    application = build(settings_for(server), locations)
    try:
        say(qt, application, "hello")
        if how == "sleep_button":
            application.window.sleep_button.click()
        elif how == "failure":
            application.state.fail()
        else:
            application.close()
        wait_for(qt, lambda: bool(_unloads(server)))
        assert _unloads(server) == [{"model": "qwen3:14b", "keep_alive": 0}]
    finally:
        application.close()


def test_the_model_is_not_touched_if_it_was_never_used(
    qt: QApplication, potato: Application, server: FakeOllama
) -> None:
    potato.window.wake_button.click()
    potato.window.sleep_button.click()
    potato.close()
    qt.processEvents()
    assert server.requests == []


def test_a_failed_unload_is_logged_and_nothing_else_happens(
    server: FakeOllama, caplog: pytest.LogCaptureFixture
) -> None:
    client = OllamaClient(
        "127.0.0.1", server.port, "qwen3:14b",
        timeout_seconds=1.0, context_length=4096, keep_alive_seconds=60,
    )  # fmt: skip
    server.close()
    ran: list[Callable[[], None]] = []

    def start(work: Callable[[], None]) -> None:
        ran.append(work)

    unloader = ModelUnloader(client, start)
    unloader(AssistantState.STANDBY, AssistantState.SLEEPING)
    unloader(AssistantState.SLEEPING, AssistantState.ACTIVE)
    assert ran == []
    unloader(AssistantState.ACTIVE, AssistantState.STANDBY)
    assert len(ran) == 1
    with caplog.at_level(logging.WARNING):
        ran[0]()  # Must not raise.
    assert "could not be unloaded" in caplog.text
    unloader.wait(0.1)


def test_the_unloader_has_its_own_client(potato: Application) -> None:
    engine = potato.window._conversation
    assert potato._unloader._client is not engine._model  # type: ignore[attr-defined]


# --- Shutting down -----------------------------------------------------------


def test_closing_puts_potato_to_sleep_and_closes_the_audit_log(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    application = build(settings_for(server), locations)
    handler = application._log_handler
    say(qt, application, "check this link")
    application.close()
    application.close()  # Safe to call twice.
    assert now(application) is AssistantState.SLEEPING
    assert not application._idle_timer.isActive()
    assert handler not in logging.getLogger().handlers
    # The lock is released, so the log can be opened again, and it is whole.
    assert verify_audit_chain(locations.logs / AUDIT_FILE_NAME).ok
    with AuditLog(locations.logs / AUDIT_FILE_NAME, Redactor()):
        pass
    kinds = [r["event"] for r in records(locations)]
    assert kinds[-1] == "state_changed"
    assert records(locations)[-1]["data"]["to_state"] == "sleeping"


def test_a_log_folder_open_to_others_is_closed_before_use(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    locations.logs.mkdir()
    locations.logs.chmod(0o777)
    application = build(settings_for(server), locations)
    try:
        assert locations.logs.stat().st_mode & 0o777 == 0o700
    finally:
        application.close()


def test_shutdown_waits_for_the_unload_to_be_sent(
    qt: QApplication, potato: Application, monkeypatch: pytest.MonkeyPatch
) -> None:
    waited: list[float] = []
    monkeypatch.setattr(ModelUnloader, "wait", lambda self, seconds: waited.append(seconds))
    potato.close()
    assert waited == [app_module.SHUTDOWN_WAIT_SECONDS]
    assert app_module.SHUTDOWN_WAIT_SECONDS > app_module.UNLOAD_TIMEOUT_SECONDS


def test_the_approval_lifetime_comes_from_the_settings(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    application = build(
        settings_for(server, "[security]\napproval_lifetime_seconds = 7\n"), locations
    )
    try:
        issuer = application.window._issuer
        assert issuer is not None
        assert issuer._lifetime_ms == 7000
    finally:
        application.close()


def test_a_start_that_fails_after_the_audit_log_opened_releases_it(
    server: FakeOllama, locations: Locations
) -> None:
    locations.logs.mkdir(mode=0o700)
    (locations.logs / "potato.log").mkdir()  # The application log cannot be opened.
    with pytest.raises(Exception, match="could not be opened safely"):
        build(settings_for(server), locations)
    with AuditLog(locations.logs / AUDIT_FILE_NAME, Redactor()):
        pass  # Not left locked.


def test_the_files_potato_makes_are_private(
    qt: QApplication, potato: Application, locations: Locations
) -> None:
    assert locations.logs.stat().st_mode & 0o077 == 0
    for path in locations.logs.iterdir():
        assert path.stat().st_mode & 0o077 == 0, path.name


# --- Fail closed at start-up (R8) --------------------------------------------


def test_a_second_copy_does_not_start(
    potato: Application, server: FakeOllama, locations: Locations
) -> None:
    with pytest.raises(Exception, match="another copy of Potato"):
        build(settings_for(server), locations)


def test_a_tampered_audit_log_stops_potato_from_starting(
    qt: QApplication, server: FakeOllama, locations: Locations
) -> None:
    application = build(settings_for(server), locations)
    say(qt, application, "hello")
    application.close()
    path = locations.logs / AUDIT_FILE_NAME
    path.write_text(path.read_text(encoding="utf-8").replace("sleeping", "active", 1))
    with pytest.raises(Exception, match="failed verification"):
        build(settings_for(server), locations)


def test_a_failed_start_leaves_logging_as_it_was(
    potato: Application, server: FakeOllama, locations: Locations
) -> None:
    before = list(logging.getLogger().handlers)
    with pytest.raises(Exception, match="another copy"):
        build(settings_for(server), locations)
    assert logging.getLogger().handlers == before


def _never_show(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a window was built")

    monkeypatch.setattr(app_module, "PotatoWindow", refuse)


def test_run_refuses_invalid_settings(
    qt: QApplication,
    locations: Locations,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _never_show(monkeypatch)
    locations.settings.write_text('[ollama]\nhost = "192.168.1.50"\n', encoding="utf-8")
    locations.settings.chmod(0o600)
    assert run(locations) == EXIT_BAD_SETTINGS == 2
    assert "Settings problem" in capsys.readouterr().err
    assert not locations.logs.exists()


@pytest.mark.parametrize(
    "problem", ["is_a_link", "is_a_file", "parent_is_a_file", "log_file_is_a_folder", "second_copy"]
)
def test_run_refuses_to_start_without_safe_logs(
    qt: QApplication,
    locations: Locations,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    problem: str,
) -> None:
    held = None
    if problem == "is_a_link":
        elsewhere = locations.logs.with_name("Elsewhere")
        elsewhere.mkdir()
        locations.logs.symlink_to(elsewhere, target_is_directory=True)
    elif problem == "is_a_file":
        locations.logs.write_text("not a folder", encoding="utf-8")
    elif problem == "log_file_is_a_folder":
        locations.logs.mkdir(mode=0o700)
        (locations.logs / "potato.log").mkdir()
    elif problem == "parent_is_a_file":
        blocked = locations.logs.with_name("blocked")
        blocked.write_text("not a folder", encoding="utf-8")
        locations = Locations(locations.settings, blocked / "Logs", locations.database)
    else:
        locations.logs.mkdir(mode=0o700)
        held = AuditLog(locations.logs / AUDIT_FILE_NAME, Redactor())
    _never_show(monkeypatch)
    try:
        assert run(locations) == EXIT_CANNOT_START == 3
    finally:
        if held is not None:
            held.close()
    error = capsys.readouterr().err
    assert TEXT_CANNOT_START in error
    assert "Reason:" in error


def test_run_shows_the_window_and_shuts_down_when_it_closes(
    qt: QApplication,
    server: FakeOllama,
    locations: Locations,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locations.settings.write_text(f"[ollama]\nport = {server.port}\n", encoding="utf-8")
    locations.settings.chmod(0o600)
    seen: list[Application] = []
    real_build = app_module.build

    def spy(*args: Any, **kwargs: Any) -> Application:
        seen.append(real_build(*args, **kwargs))
        return seen[-1]

    def fake_exec() -> int:
        (application,) = seen
        assert application.window.isVisible()
        application.window.close()
        return 0

    monkeypatch.setattr(app_module, "build", spy)
    monkeypatch.setattr(qt, "exec", fake_exec)
    assert run(locations) == 0
    (application,) = seen
    assert application._closed
    assert now(application) is AssistantState.SLEEPING
    with AuditLog(locations.logs / AUDIT_FILE_NAME, Redactor()):
        pass  # The audit log was released.


def test_the_default_locations_are_in_the_users_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/Users/someone")
    places = default_locations()
    support = Path("/Users/someone/Library/Application Support/Potato")
    assert places.settings == support / "settings.toml"
    assert places.logs == Path("/Users/someone/Library/Logs/Potato")
    assert places.database.parent == support


def test_no_settings_file_means_the_defaults(locations: Locations) -> None:
    assert load_settings(locations.settings) == Settings()


def test_wake_event_is_not_sent_at_start_up(potato: Application, locations: Locations) -> None:
    # Potato starts asleep. Only the user's own action wakes it.
    assert [r["event"] for r in records(locations)] == []
    assert Event.INTERFACE_WAKE.value not in json.dumps(records(locations))
