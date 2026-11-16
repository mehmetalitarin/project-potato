"""The network overview tool: which of your programs use the network.

One tool, ``network_overview`` (low risk). It reports which of your programs
accept connections, and whether only this Mac or other devices can reach
them, and which programs have connections open and to what kind of place.

How it works, and why it is safe (T-TOOL-3 and T-TOOL-4 in
``docs/threat_model.md``):

- The list comes from ``lsof``, run by ``potato.integrations.processes`` as
  a fixed command that prints numbers only. Nothing is looked up on the
  network, and nothing is scanned: Potato reads this Mac's own list.
- **Remote addresses are counted, never shown.** Which addresses a Mac talks
  to is private. Each connection is sorted into "this Mac", "local network"
  or "internet", and only the counts leave this module.
- **Names are untrusted.** Program names get the same treatment as in the
  process overview: short and plain, or a fixed label.
- **It is partial, and says so.** Without administrator rights, which
  Potato never has, only the user's own programs are visible. The result
  always says that system services are missing.
- Every other piece of text in the result is fixed text written here.
"""

import ipaddress
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from potato.integrations.processes import Probe, run_probe
from potato.modules.process_overview import display_name
from potato.security.tools import ArgumentValue, RiskLevel, ToolDefinition

MAX_LISTENING: Final = 10
MAX_CONNECTED_PROGRAMS: Final = 8

THIS_MAC: Final = "this_mac"
LOCAL_NETWORK: Final = "local_network"
INTERNET: Final = "internet"
NETWORK: Final = "network"

# Addresses that belong to a home or office network rather than the internet.
_LOCAL_NETWORKS: Final = tuple(
    ipaddress.ip_network(text)
    for text in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
)

_BROADCAST: Final = ipaddress.IPv4Address("255.255.255.255")

_PID: Final = re.compile(r"p([0-9]{1,7})")
_SOCKET: Final = re.compile(r"f([0-9]{1,7})")
# TCP and UDP are reported. Other protocols, such as ICMP (used by "ping"),
# are recognised and counted, never listed.
_PROTOCOL: Final = re.compile(r"P([A-Z][A-Z0-9]{0,9})")
_REPORTED: Final = frozenset({"TCP", "UDP"})
_TCP_INFO: Final = re.compile(r"T([A-Z]{2})=([A-Za-z0-9_]{0,32})")
_HOST: Final = r"\*|[0-9.]{7,15}|\[[0-9A-Fa-f:.]{2,45}(?:%[A-Za-z0-9]{1,16})?\]"
_HOST_PATTERN: Final = re.compile(_HOST)
_ENDPOINT: Final = rf"({_HOST}):(\*|[0-9]{{1,5}})"
_ADDRESSES: Final = re.compile(rf"n{_ENDPOINT}(?:->{_ENDPOINT})?")

SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "reachable": (
            "At least one of your programs accepts TCP connections from other devices. "
            "The firewall decides whether they can actually reach it."
        ),
        "this_mac_only": "None of your programs accepts TCP connections from other devices.",
        "incomplete": (
            "No program was found accepting TCP connections from other devices, but some "
            "entries could not be read."
        ),
        "unavailable": "The list of network connections could not be read.",
    }
)
WARNING_UNUSUAL_NAMES: Final = (
    "Some programs have names with unexpected characters. Those names are not shown."
)
WARNING_UNREADABLE: Final = "Some entries could not be read, so this overview may be incomplete."
WARNING_OPEN_UDP: Final = (
    "Some programs have UDP ports open to other devices. UDP is counted, not listed, and "
    "is not part of the summary."
)
NOTE: Final = (
    "This shows only your own programs: system services are hidden without "
    "administrator rights, so the list is not complete. Remote addresses are counted, "
    "never shown, and Potato never looks them up. A program chooses its own name."
)


@dataclass(slots=True)
class Socket:
    """One network socket, as far as Potato looks at it."""

    pid: int
    name: str
    plain_name: bool
    protocol: str = ""
    local_host: str = ""
    local_port: int | None = None
    remote_place: str | None = None
    state: str = ""
    complete: bool = False


@dataclass(slots=True)
class Listing:
    """What was read from the list."""

    sockets: list[Socket] = field(default_factory=list)
    unreadable: int = 0


def place(host: str) -> str | None:
    """Sort an address into this Mac, the local network or the internet.

    ``*`` and the unspecified addresses mean "any address", returned as
    ``network``. ``None`` means the text is not a valid address.
    """
    if _HOST_PATTERN.fullmatch(host) is None:
        return None
    if host == "*":
        return NETWORK
    text = host
    if text.startswith("["):
        text = text[1:-1].split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return NETWORK
    if address.is_loopback:
        return THIS_MAC
    # Multicast and broadcast reach devices on the same network, such as
    # printers announcing themselves.
    if address.is_multicast or address == _BROADCAST:
        return LOCAL_NETWORK
    if any(address in network for network in _LOCAL_NETWORKS):
        return LOCAL_NETWORK
    return INTERNET


def _port(text: str) -> int | None:
    if text == "*":
        return 0
    number = int(text)
    return number if number <= 65535 else None


def _read_addresses(sock: Socket, text: str) -> bool:
    found = _ADDRESSES.fullmatch(text)
    if found is None:
        return False
    local_host, local_port, remote_host, remote_port = found.groups()
    local_place = place(local_host)
    port = _port(local_port)
    if local_place is None or port is None:
        return False
    if remote_host is not None:
        remote = place(remote_host)
        if remote is None or remote == NETWORK or _port(remote_port) is None:
            return False
        sock.remote_place = remote
    sock.local_host = local_place
    sock.local_port = port
    return True


def parse_listing(output: str) -> Listing:
    """Read ``lsof`` field output. Never guesses: an odd entry is counted, not used."""
    listing = Listing()
    pid: int | None = None
    name, plain = "", True
    current: Socket | None = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            if current.complete and current.protocol and current.local_port is not None:
                listing.sockets.append(current)
            else:
                listing.unreadable += 1
        current = None

    # Split on the newline only: other separators may appear inside a name.
    for line in output.split("\n"):
        if not line:
            continue
        kind = line[0]
        if kind == "p":
            finish()
            found = _PID.fullmatch(line)
            pid = int(found.group(1)) if found else None
            name, plain = "", True
            if found is None:
                listing.unreadable += 1
        elif kind == "c" and pid is not None and current is None:
            name, plain = display_name(line[1:])
        elif kind == "f" and pid is not None:
            finish()
            if _SOCKET.fullmatch(line) is None:
                listing.unreadable += 1
                continue
            # A process with no name line gets the fixed label.
            shown, ok = (name, plain) if name else display_name("")
            current = Socket(pid=pid, name=shown, plain_name=ok, complete=True)
        elif current is None:
            # A field outside a socket, or before any process: never guess.
            listing.unreadable += 1
        elif kind == "P":
            found = _PROTOCOL.fullmatch(line)
            if found is None or current.protocol:
                current.complete = False
            else:
                current.protocol = found.group(1)
        elif kind == "n":
            if current.local_port is not None or not _read_addresses(current, line):
                current.complete = False
        elif kind == "T":
            found = _TCP_INFO.fullmatch(line)
            if found is None:
                current.complete = False
            elif found.group(1) == "ST":
                current.state = found.group(2)
        else:
            current.complete = False
    finish()
    return listing


def _listening(sockets: list[Socket]) -> Iterator[tuple[Socket, int]]:
    for sock in sockets:
        if (
            sock.protocol == "TCP"
            and sock.state == "LISTEN"
            and sock.remote_place is None
            and sock.local_port is not None
        ):
            yield sock, sock.local_port


def _connected(sockets: list[Socket]) -> Iterator[tuple[Socket, str]]:
    for sock in sockets:
        if sock.protocol in _REPORTED and sock.remote_place is not None:
            yield sock, sock.remote_place


def read_overview(runner: Callable[[Probe], str | None] = run_probe) -> dict[str, object]:
    """Read the network list and return an overview as plain data."""
    output = runner(Probe.NETWORK)
    if type(output) is not str:
        return {"summary": SUMMARIES["unavailable"], "partial": True, "note": NOTE}
    listing = parse_listing(output)
    # A Mac in use always has some sockets. Finding none means the list was
    # not really read, and must never look like an all-clear.
    if not listing.sockets:
        return {"summary": SUMMARIES["unavailable"], "partial": True, "note": NOTE}

    # One entry per program and port: IPv4 and IPv6 sockets are merged, and
    # "reachable from other devices" wins over "this Mac only".
    servers: dict[tuple[int, int], dict[str, object]] = {}
    for sock, port in _listening(listing.sockets):
        reach = THIS_MAC if sock.local_host == THIS_MAC else NETWORK
        entry = servers.setdefault(
            (sock.pid, port), {"name": sock.name, "pid": sock.pid, "port": port, "reach": reach}
        )
        if reach == NETWORK:
            entry["reach"] = NETWORK
    listening = sorted(
        servers.values(),
        key=lambda entry: (entry["reach"] != NETWORK, entry["port"], entry["pid"]),
    )

    totals = {THIS_MAC: 0, LOCAL_NETWORK: 0, INTERNET: 0}
    programs: dict[int, dict[str, object]] = {}
    for sock, where in _connected(listing.sockets):
        totals[where] += 1
        entry = programs.setdefault(
            sock.pid,
            {"name": sock.name, "pid": sock.pid, "total": 0,
             THIS_MAC: 0, LOCAL_NETWORK: 0, INTERNET: 0},
        )  # fmt: skip
        entry["total"] = int(str(entry["total"])) + 1
        entry[where] = int(str(entry[where])) + 1
    connected = sorted(
        programs.values(), key=lambda entry: (-int(str(entry["total"])), entry["pid"])
    )
    # "*:*" is a UDP socket with no port yet: nothing can reach it.
    open_udp = [
        sock
        for sock in listing.sockets
        if sock.protocol == "UDP" and sock.remote_place is None and sock.local_port
    ]
    other = sum(1 for sock in listing.sockets if sock.protocol not in _REPORTED)
    udp_to_network = any(sock.local_host != THIS_MAC for sock in open_udp)

    unusual = len({sock.pid for sock in listing.sockets if not sock.plain_name})
    warnings: list[str] = []
    if unusual:
        warnings.append(WARNING_UNUSUAL_NAMES)
    if listing.unreadable:
        warnings.append(WARNING_UNREADABLE)
    if udp_to_network:
        warnings.append(WARNING_OPEN_UDP)
    if any(entry["reach"] == NETWORK for entry in listening):
        summary = "reachable"
    elif listing.unreadable:
        summary = "incomplete"
    else:
        summary = "this_mac_only"
    return {
        "summary": SUMMARIES[summary],
        "listening": listening[:MAX_LISTENING],
        "listening_total": len(listening),
        "connections": totals,
        "connected_programs": connected[:MAX_CONNECTED_PROGRAMS],
        "connected_programs_total": len(connected),
        "open_udp_sockets": len(open_udp),
        "other_sockets": other,
        "unusual_names": unusual,
        "unreadable_entries": listing.unreadable,
        "warnings": warnings,
        "partial": True,
        "note": NOTE,
    }


def network_overview_tools(
    runner: Callable[[Probe], str | None] = run_probe,
) -> tuple[ToolDefinition, ...]:
    """Return the network overview tool.

    The argument exists for tests, which supply a prepared list.
    """

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return read_overview(runner)

    return (
        ToolDefinition(
            name="network_overview",
            risk=RiskLevel.LOW,
            arguments={},
            handler=handle,
            description=(
                "Report which of your programs accept network connections, and how many "
                "connections each has open. Shows no remote addresses."
            ),
            timeout_seconds=15.0,
            max_calls=5,
        ),
    )
