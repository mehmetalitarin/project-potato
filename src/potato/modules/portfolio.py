"""The portfolio tools: see, record and remove holdings.

Three tools, as listed in ``docs/permissions.md``:

- ``portfolio_summary`` (low risk): every holding, with what it cost.
- ``portfolio_add_holding`` (medium risk): record a holding, or replace the
  one already recorded for that symbol.
- ``portfolio_remove_holding`` (medium risk): remove a holding.

Medium risk means voice cannot change the portfolio: only typed requests and
the interface can (P6). The gate checks every argument before a handler runs,
so the handlers here receive only valid symbols and exact decimal text.

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
            replaced = any(h.symbol == holding.symbol for h in database.holdings())
            database.set_holding(holding)
        return {**_describe(holding), "replaced": replaced}

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
                "Record a holding: ticker symbol in capitals, number of units and average "
                "price paid per unit. Replaces any holding already recorded for that symbol."
            ),
        ),
        ToolDefinition(
            name="portfolio_remove_holding",
            risk=RiskLevel.MEDIUM,
            arguments={"symbol": SYMBOL_FIELD},
            handler=remove,
            description="Remove the holding for a ticker symbol in capitals.",
        ),
    )
