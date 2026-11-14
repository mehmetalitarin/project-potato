"""Tests for the portfolio tools, always run through the gate (R8)."""

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from potato.core.turns import TurnEngine, TurnStatus
from potato.integrations.ollama import Message, Reply
from potato.modules.portfolio import MAX_HOLDINGS_LISTED, portfolio_tools
from potato.security.audit import AuditLog
from potato.security.gate import MESSAGES, Gate, GateResult, ReasonCode, RequestOrigin
from potato.security.redaction import Redactor
from potato.security.tools import RiskLevel
from potato.storage.database import Database, Holding

VOICE, TYPED, INTERFACE = RequestOrigin.VOICE, RequestOrigin.TYPED, RequestOrigin.INTERFACE
PERMISSIONS = Path(__file__).parent.parent / "docs" / "permissions.md"


@pytest.fixture
def database_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "potato.db"


@pytest.fixture
def gate(tmp_path: Path, database_path: Path) -> Iterator[Gate]:
    with AuditLog(tmp_path / "logs" / "audit.jsonl", Redactor()) as audit:
        # Generous limits so that tests can make many calls.
        yield Gate(portfolio_tools(database_path), audit, max_submissions=1000)


def _call(gate: Gate, tool: str, origin: RequestOrigin = TYPED, **arguments: object) -> GateResult:
    return gate.submit({"tool": tool, "arguments": arguments}, origin)


def _holdings(database_path: Path) -> list[Holding]:
    with Database(database_path) as database:
        return database.holdings()


# --- Adding, listing and removing ---------------------------------------------


def test_an_empty_portfolio(gate: Gate) -> None:
    result = _call(gate, "portfolio_summary")
    assert result.ok
    assert result.result == {
        "count": 0,
        "holdings": [],
        "currency_note": "Amounts are in each holding's own currency and are not added up.",
    }


def test_add_list_replace_and_remove(gate: Gate, database_path: Path) -> None:
    added = _call(gate, "portfolio_add_holding", symbol="AAPL", quantity=2.5, average_price=150.1)
    assert added.result == {
        "symbol": "AAPL",
        "quantity": "2.5",
        "average_price": "150.1",
        "cost": "375.25",
        "replaced": False,
    }
    _call(gate, "portfolio_add_holding", symbol="BRK.B", quantity=1, average_price=400)
    assert _holdings(database_path) == [
        Holding("AAPL", Decimal("2.5"), Decimal("150.1")),
        Holding("BRK.B", Decimal(1), Decimal(400)),
    ]

    replaced = _call(gate, "portfolio_add_holding", symbol="AAPL", quantity=3, average_price=160)
    assert replaced.result["replaced"] is True  # type: ignore[index]

    summary = _call(gate, "portfolio_summary")
    assert summary.result["holdings"] == [  # type: ignore[index]
        {"symbol": "AAPL", "quantity": "3", "average_price": "160", "cost": "480.00"},
        {"symbol": "BRK.B", "quantity": "1", "average_price": "400", "cost": "400.00"},
    ]

    assert _call(gate, "portfolio_remove_holding", symbol="AAPL").result == {
        "symbol": "AAPL",
        "removed": True,
    }
    assert _call(gate, "portfolio_remove_holding", symbol="AAPL").result == {
        "symbol": "AAPL",
        "removed": False,
    }
    assert _holdings(database_path) == [Holding("BRK.B", Decimal(1), Decimal(400))]


def test_amounts_stay_exact(gate: Gate, database_path: Path) -> None:
    _call(gate, "portfolio_add_holding", symbol="VWRL", quantity=0.1, average_price=0.2)
    (holding,) = _holdings(database_path)
    assert holding.quantity == Decimal("0.1")
    assert holding.average_price == Decimal("0.2")


def test_cost_is_rounded_to_cents_half_to_even(gate: Gate) -> None:
    _call(gate, "portfolio_add_holding", symbol="A", quantity=0.5, average_price=0.05)
    _call(gate, "portfolio_add_holding", symbol="B", quantity=0.5, average_price=0.07)
    summary: Any = _call(gate, "portfolio_summary").result
    assert [holding["cost"] for holding in summary["holdings"]] == ["0.02", "0.04"]


def test_a_holding_without_a_price_has_no_cost(gate: Gate, database_path: Path) -> None:
    with Database(database_path) as database:
        database.set_holding(Holding("OLD", Decimal(4)))
    holdings = _call(gate, "portfolio_summary").result["holdings"]  # type: ignore[index]
    assert holdings == [{"symbol": "OLD", "quantity": "4", "average_price": None, "cost": None}]


def test_the_largest_portfolio_still_fits(gate: Gate, database_path: Path) -> None:
    with Database(database_path) as database:
        for number in range(MAX_HOLDINGS_LISTED + 20):
            database.set_holding(
                Holding(
                    f"Z{number:09d}", Decimal("999999999.12345678"), Decimal("9999999.12345678")
                )
            )
    # The widest possible values, so this is the largest result there can be.
    result = _call(gate, "portfolio_summary")
    assert result.ok
    summary: Any = result.result
    assert summary["count"] == MAX_HOLDINGS_LISTED + 20
    assert len(summary["holdings"]) == MAX_HOLDINGS_LISTED


# --- The gate's rules apply --------------------------------------------------


@pytest.mark.parametrize("origin", [TYPED, INTERFACE])
def test_typed_and_interface_can_change_the_portfolio(gate: Gate, origin: RequestOrigin) -> None:
    assert _call(gate, "portfolio_add_holding", origin, symbol="A", quantity=1, average_price=1).ok
    assert _call(gate, "portfolio_remove_holding", origin, symbol="A").ok


def test_voice_can_read_but_not_change_the_portfolio(gate: Gate, database_path: Path) -> None:
    assert _call(gate, "portfolio_summary", VOICE).ok
    added = _call(gate, "portfolio_add_holding", VOICE, symbol="A", quantity=1, average_price=1)
    assert added.reason is ReasonCode.ORIGIN_NOT_ALLOWED
    removed = _call(gate, "portfolio_remove_holding", VOICE, symbol="A")
    assert removed.reason is ReasonCode.ORIGIN_NOT_ALLOWED
    assert not database_path.exists() or _holdings(database_path) == []


def test_voice_is_offered_only_the_summary(gate: Gate) -> None:
    assert gate.available_tools(VOICE) == ("portfolio_summary",)
    assert gate.available_tools(TYPED) == (
        "portfolio_add_holding",
        "portfolio_remove_holding",
        "portfolio_summary",
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"symbol": "aapl", "quantity": 1, "average_price": 1},
        {"symbol": "AAPL; DROP TABLE holding", "quantity": 1, "average_price": 1},
        {"symbol": "A'B", "quantity": 1, "average_price": 1},
        {"symbol": "TOOLONGSYMB", "quantity": 1, "average_price": 1},
        {"symbol": "AAPL", "quantity": "1", "average_price": 1},
        {"symbol": "AAPL", "quantity": 1, "average_price": "150"},
        {"symbol": "AAPL", "quantity": True, "average_price": 1},
        {"symbol": "AAPL", "quantity": 0, "average_price": 1},
        {"symbol": "AAPL", "quantity": -1, "average_price": 1},
        {"symbol": "AAPL", "quantity": 1, "average_price": 0},
        {"symbol": "AAPL", "quantity": 1_000_000_001, "average_price": 1},
        {"symbol": "AAPL", "quantity": 1, "average_price": 10_000_001},
        {"symbol": "AAPL", "quantity": 0.000000001, "average_price": 1},
        {"symbol": "AAPL", "quantity": 1},
        {"symbol": "AAPL", "quantity": 1, "average_price": 1, "currency": "USD"},
        {"symbol": "AAPL", "quantity": 1, "average_price": 1, "confirmed": True},
    ],
)
def test_invalid_holdings_are_refused_before_anything_is_written(
    gate: Gate, database_path: Path, arguments: dict[str, Any]
) -> None:
    result = gate.submit({"tool": "portfolio_add_holding", "arguments": arguments}, TYPED)
    assert result.reason is ReasonCode.INVALID_ARGUMENTS
    assert not database_path.exists()


def test_changes_are_rate_limited(gate: Gate) -> None:
    results = [
        _call(gate, "portfolio_add_holding", symbol="A", quantity=n, average_price=1)
        for n in range(1, 13)
    ]
    assert [result.ok for result in results] == [True] * 10 + [False] * 2
    assert results[-1].reason is ReasonCode.RATE_LIMITED


def test_a_broken_database_is_a_fixed_refusal(gate: Gate, database_path: Path) -> None:
    database_path.parent.mkdir(mode=0o700)
    database_path.write_bytes(b"not a database " * 100)
    database_path.chmod(0o600)
    result = _call(gate, "portfolio_summary")
    assert result.reason is ReasonCode.TOOL_FAILED
    assert result.message == MESSAGES[ReasonCode.TOOL_FAILED]
    assert database_path.read_bytes() == b"not a database " * 100


# --- Through a whole turn ------------------------------------------------------


class ScriptedModel:
    def __init__(self, *replies: Reply) -> None:
        self.replies = list(replies)
        self.seen: list[list[Message]] = []

    def chat(
        self, messages: Sequence[Message], tools: Sequence[Mapping[str, object]] = ()
    ) -> Reply:
        self.seen.append(list(messages))
        return self.replies.pop(0)


def test_a_typed_turn_records_a_holding_and_summarises_it(gate: Gate, database_path: Path) -> None:
    proposal: dict[str, object] = {
        "tool": "portfolio_add_holding",
        "arguments": {"symbol": "AAPL", "quantity": 2, "average_price": 150},
    }
    model = ScriptedModel(Reply("", (proposal,)), Reply("Recorded 2 AAPL at 150.", ()))
    result = TurnEngine(model, gate).run("I bought 2 Apple shares at 150", TYPED)
    assert result.status is TurnStatus.ANSWERED
    assert _holdings(database_path) == [Holding("AAPL", Decimal(2), Decimal(150))]
    data = json.loads(model.seen[1][2].content)
    assert data["result"]["cost"] == "300.00"


def test_a_spoken_request_to_change_the_portfolio_is_refused(
    gate: Gate, database_path: Path
) -> None:
    proposal: dict[str, object] = {
        "tool": "portfolio_remove_holding",
        "arguments": {"symbol": "AAPL"},
    }
    result = TurnEngine(ScriptedModel(Reply("", (proposal,))), gate).run("sell apple", VOICE)
    assert result.status is TurnStatus.REFUSED
    assert result.text == MESSAGES[ReasonCode.ORIGIN_NOT_ALLOWED]


# --- Documentation -------------------------------------------------------------


def _planned_tools() -> dict[str, str]:
    text = PERMISSIONS.read_text(encoding="utf-8")
    section = text.split("## Planned tools", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| `([a-z_]+)` \|.*\| (Low|Medium|Sensitive) \|$", section, re.M)
    return {name: risk.lower() for name, risk in rows}


def test_every_tool_is_in_the_documented_table_with_the_same_risk(database_path: Path) -> None:
    planned = _planned_tools()
    assert len(planned) >= 12
    for tool in portfolio_tools(database_path):
        assert planned.get(tool.name) == tool.risk.value, tool.name


def test_descriptions_never_mention_risk_or_approval(database_path: Path) -> None:
    for tool in portfolio_tools(database_path):
        assert tool.risk in (RiskLevel.LOW, RiskLevel.MEDIUM)
        lowered = tool.description.lower()
        assert "approv" not in lowered
        assert "risk" not in lowered
