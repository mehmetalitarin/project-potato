"""The portfolio tools: see, record and remove holdings.

Three tools, as listed in ``docs/permissions.md``:

- ``portfolio_summary`` (low risk): every holding, with what it cost.
- ``portfolio_add_holding`` (medium risk): record a new holding. It never
  changes one that is already recorded: replacing a holding destroys the old
  figures, so that has to go through removing it, which needs approval.
- ``portfolio_remove_holding`` (sensitive): remove a holding.

Medium risk means voice cannot change the portfolio: only typed requests and
the interface can (P6). Removing is sensitive because it destroys data: it
runs only after the user approves it in the approval dialog (P7). The gate
checks every argument before a handler runs, so the handlers here receive
only valid symbols and exact decimal text.

Nothing here talks to the network. Current prices, value and profit or loss
need market data, which arrives in a later commit. Until then the summary
shows what each holding cost, not what it is worth.

Each call opens the database itself, because the gate runs every tool in its
own thread and an SQLite connection belongs to the thread that opened it.
"""

from collections.abc import Mapping
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Final

from potato.security.tools import (
    ArgumentValue,
    DecimalField,
    RiskLevel,
    TextField,
    ToolDefinition,
)
from potato.storage.database import (
    MAX_PRICE,
    MAX_PRICE_DECIMAL_PLACES,
    MAX_QUANTITY,
    MAX_QUANTITY_DECIMAL_PLACES,
    MAX_SYMBOL_CHARACTERS,
    SYMBOL_PATTERN,
    Database,
    Holding,
)

# More than this many holdings are counted but not listed, so that a result
# always fits within the gate's size cap.
MAX_HOLDINGS_LISTED: Final = 100

_CENT: Final = Decimal("0.01")

SYMBOL_FIELD: Final = TextField(SYMBOL_PATTERN, MAX_SYMBOL_CHARACTERS)
QUANTITY_FIELD: Final = DecimalField(
    minimum=Decimal(1).scaleb(-MAX_QUANTITY_DECIMAL_PLACES),
    maximum=MAX_QUANTITY,
    max_places=MAX_QUANTITY_DECIMAL_PLACES,
)
PRICE_FIELD: Final = DecimalField(
    minimum=Decimal(1).scaleb(-MAX_PRICE_DECIMAL_PLACES),
    maximum=MAX_PRICE,
    max_places=MAX_PRICE_DECIMAL_PLACES,
)


def _text(amount: Decimal) -> str:
    """Write an amount as plain digits."""
    return format(amount.normalize(), "f")


def _describe(holding: Holding) -> dict[str, object]:
    """One holding as plain data."""
    price = holding.average_price
    cost = None
    if price is not None:
        cost = format((holding.quantity * price).quantize(_CENT, ROUND_HALF_EVEN), "f")
    return {
        "symbol": holding.symbol,
        "quantity": _text(holding.quantity),
        "average_price": None if price is None else _text(price),
        "cost": cost,
    }


ALREADY_RECORDED: Final = (
    "A holding for this symbol is already recorded, and it was not changed. To change "
    "it, remove it first (that needs your approval), then add it again."
)


def portfolio_tools(database_path: Path) -> tuple[ToolDefinition, ...]:
    """Return the three portfolio tools, working on the database at ``database_path``."""

    def summary(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        with Database(database_path) as database:
            holdings = database.holdings()
        return {
            "count": len(holdings),
            "holdings": [_describe(holding) for holding in holdings[:MAX_HOLDINGS_LISTED]],
            "currency_note": "Amounts are in each holding's own currency and are not added up.",
        }

    def add(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        holding = Holding(
            str(arguments["symbol"]),
            Decimal(str(arguments["quantity"])),
            Decimal(str(arguments["average_price"])),
        )
        with Database(database_path) as database:
            added = database.add_new_holding(holding)
        if not added:
            return {
                "symbol": holding.symbol,
                "added": False,
                "reason": "already_recorded",
                "note": ALREADY_RECORDED,
            }
        return {**_describe(holding), "added": True}

    def remove(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        symbol = str(arguments["symbol"])
        with Database(database_path) as database:
            removed = database.remove_holding(symbol)
        return {"symbol": symbol, "removed": removed}

    return (
        ToolDefinition(
            name="portfolio_summary",
            risk=RiskLevel.LOW,
            arguments={},
            handler=summary,
            description="List the user's stock and fund holdings with quantity and cost.",
        ),
        ToolDefinition(
            name="portfolio_add_holding",
            risk=RiskLevel.MEDIUM,
            arguments={
                "symbol": SYMBOL_FIELD,
                "quantity": QUANTITY_FIELD,
                "average_price": PRICE_FIELD,
            },
            handler=add,
            description=(
                "Record a new holding: ticker symbol in capitals, number of units and "
                "average price paid per unit. Does not change a holding already recorded."
            ),
        ),
        ToolDefinition(
            name="portfolio_remove_holding",
            # The one tool that destroys data, so it needs a real click on
            # Approve in the approval dialog.
            risk=RiskLevel.SENSITIVE,
            arguments={"symbol": SYMBOL_FIELD},
            handler=remove,
            description="Remove the holding for a ticker symbol in capitals.",
        ),
    )
