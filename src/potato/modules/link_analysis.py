"""The link analyser: looks at a link's text for signs of phishing.

One tool, ``analyse_link`` (low risk). It answers "does this link look like a
trick?" by examining the text alone (T-TOOL-5 in ``docs/threat_model.md``):

- **It never opens the link.** No network request of any kind is made, so
  checking a link cannot alert whoever sent it. A test fails if this module
  imports anything that can reach the network.
- **Fixed explanations.** Every finding is a code with a sentence written
  here and reviewed. The model is not asked to judge the link, so injected
  text cannot argue its way to "safe" (T-LLM-4).
- **Honest limits.** Text analysis cannot see what a page does. "No warning
  signs" is never presented as "safe", and the result always says so.

The checks are heuristics. Each looks for a trick that phishing links use:
a lookalike name, a disguised address, a real brand name in the wrong place,
characters that hide or reorder text, and so on.
"""

import ipaddress
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final
from urllib.parse import SplitResult, urlsplit

from potato.security.tools import ArgumentValue, RiskLevel, TextField, ToolDefinition

MAX_LINK_CHARACTERS: Final = 2048
LONG_LINK_CHARACTERS: Final = 200
MAX_SUBDOMAINS: Final = 3

# Any visible or invisible character except spaces and control characters.
# Invisible formatting characters are allowed in, so that they can be found.
LINK_FIELD: Final = TextField(
    re.compile(r"[^\s\x00-\x1f\x7f-\x9f]+"), max_characters=MAX_LINK_CHARACTERS
)


class Severity(StrEnum):
    """How strongly a finding suggests a trick."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(StrEnum):
    """One sign of a trick. Each has a fixed severity and sentence."""

    NOT_A_LINK = "not_a_link"
    DANGEROUS_SCHEME = "dangerous_scheme"
    NOT_A_WEB_ADDRESS = "not_a_web_address"
    HIDDEN_CHARACTERS = "hidden_characters"
    BACKSLASH = "backslash"
    USER_INFO = "user_info"
    ENCODED_NAME = "encoded_name"
    DISGUISED_IP_ADDRESS = "disguised_ip_address"
    IP_ADDRESS = "ip_address"
    MIXED_SCRIPTS = "mixed_scripts"
    LOOKALIKE_BRAND = "lookalike_brand"
    BRAND_ELSEWHERE = "brand_elsewhere"
    BRAND_IN_PATH = "brand_in_path"
    UNUSUAL_NAME_CHARACTERS = "unusual_name_characters"
    NON_LATIN_NAME = "non_latin_name"
    PUNYCODE = "punycode"
    UNREADABLE_NAME = "unreadable_name"
    LINK_SHORTENER = "link_shortener"
    FILE_LIKE_ENDING = "file_like_ending"
    UNUSUAL_PORT = "unusual_port"
    EMBEDDED_LINK = "embedded_link"
    MANY_SUBDOMAINS = "many_subdomains"
    CHEAP_ENDING = "cheap_ending"
    NOT_ENCRYPTED = "not_encrypted"
    URGENT_WORDS = "urgent_words"
    MANY_HYPHENS = "many_hyphens"
    VERY_LONG = "very_long"


H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW

# Every sentence a result can carry, written here and nowhere else.
EXPLANATIONS: Final[Mapping[Finding, tuple[Severity, str]]] = MappingProxyType(
    {
        Finding.NOT_A_LINK: (M, "This does not look like a web address, so it was not analysed."),
        Finding.DANGEROUS_SCHEME: (
            H,
            "This is not a web page. Links of this kind can run code or open files directly.",
        ),
        Finding.NOT_A_WEB_ADDRESS: (
            M,
            "This is not an ordinary web address, so most of the checks do not apply.",
        ),
        Finding.HIDDEN_CHARACTERS: (
            H,
            "The link contains invisible characters, which can hide or reorder what you see.",
        ),
        Finding.BACKSLASH: (
            H,
            "The link contains a backslash. Browsers read it as a slash, which can change "
            "where the link really goes.",
        ),
        Finding.USER_INFO: (
            H,
            "The link contains an @ before the address. Everything before the @ is ignored, "
            "so the real destination is the part after it.",
        ),
        Finding.ENCODED_NAME: (
            H,
            "The site's name is written in encoded form, which hides what it really is.",
        ),
        Finding.DISGUISED_IP_ADDRESS: (
            H,
            "The link uses a number written in an unusual form instead of a name. "
            "This is a known way to disguise where a link goes.",
        ),
        Finding.IP_ADDRESS: (
            M,
            "The link uses a numeric address instead of a name. Real companies rarely do this.",
        ),
        Finding.MIXED_SCRIPTS: (
            H,
            "The site's name mixes letters from different alphabets, such as Latin and "
            "Cyrillic. This is a common way to imitate a real name.",
        ),
        Finding.LOOKALIKE_BRAND: (
            H,
            "The site's name imitates a well-known company's name with lookalike letters "
            "or digits.",
        ),
        Finding.BRAND_ELSEWHERE: (
            H,
            "The link mentions a well-known company, but the address does not belong to "
            "that company.",
        ),
        Finding.BRAND_IN_PATH: (
            M,
            "The link names a well-known company's address after the site name, but the "
            "site itself does not belong to that company.",
        ),
        Finding.UNUSUAL_NAME_CHARACTERS: (
            H,
            "The site's name contains characters that real site names do not use.",
        ),
        Finding.NON_LATIN_NAME: (
            M,
            "The site's name uses letters outside the basic Latin alphabet, which can look "
            "like familiar letters.",
        ),
        Finding.PUNYCODE: (
            M,
            "The site's name is written in the encoded form used for non-Latin letters. "
            "What it shows in a browser may look like a different name.",
        ),
        Finding.UNREADABLE_NAME: (M, "The site's name could not be read in a standard form."),
        Finding.LINK_SHORTENER: (
            M,
            "This is a link shortener, which hides the real destination until it is opened.",
        ),
        Finding.FILE_LIKE_ENDING: (
            M,
            "The address ends in something that looks like a file name, such as .zip or .mov.",
        ),
        Finding.UNUSUAL_PORT: (
            M,
            "The link names an unusual port. Ordinary websites do not need one.",
        ),
        Finding.EMBEDDED_LINK: (
            M,
            "The link contains another web address inside it, which it may forward you to.",
        ),
        Finding.MANY_SUBDOMAINS: (
            M,
            "The address has many parts before the main site name, which can push the real "
            "name out of view.",
        ),
        Finding.CHEAP_ENDING: (
            L,
            "The address uses an ending that is often chosen for short-lived scam sites.",
        ),
        Finding.NOT_ENCRYPTED: (L, "The link does not use an encrypted connection (https)."),
        Finding.URGENT_WORDS: (
            L,
            "The link uses words like login, verify or account, which phishing links "
            "often use to seem official.",
        ),
        Finding.MANY_HYPHENS: (
            L,
            "The site's name has many hyphens, which is common in made-up lookalike names.",
        ),
        Finding.VERY_LONG: (L, "The link is unusually long, which can hide its real destination."),
    }
)

SUMMARIES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "high": "This link shows strong signs of a trick. Do not open it or enter any details.",
        "medium": "This link shows warning signs. Be careful before opening it.",
        "low": "This link shows minor warning signs only.",
        "none": "No warning signs were found in the text of this link.",
    }
)
LIMITS_NOTE: Final = (
    "Potato did not open the link. It only examined the text, which cannot show what a "
    "page does, so no warning signs does not mean the link is safe."
)

# Schemes that can run code or open local files.
_DANGEROUS_SCHEMES: Final = frozenset({"javascript", "vbscript", "data", "file", "blob"})
_WEB_SCHEMES: Final = frozenset({"http", "https"})

# Two-part endings under which a name is registered, such as example.co.uk.
_TWO_PART_SUFFIXES: Final = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "nhs.uk",
        "police.uk", "sch.uk", "com.au", "net.au", "org.au", "gov.au", "co.nz", "co.jp",
        "com.br", "com.tr", "co.in", "com.cn", "com.mx", "co.za", "com.sg", "co.kr",
    }
)  # fmt: skip

_SHORTENERS: Final = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
        "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "lnkd.in",
    }
)  # fmt: skip
_FILE_LIKE_ENDINGS: Final = frozenset({"zip", "mov"})
_CHEAP_ENDINGS: Final = frozenset(
    {"xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga", "rest", "cam"}
)
_URGENT_WORDS: Final = frozenset(
    {
        "login", "signin", "logon", "verify", "verification", "account", "secure",
        "security", "update", "password", "banking", "wallet", "unlock", "suspended", "confirm",
        "refund", "invoice",
    }
)  # fmt: skip

# Well-known names that phishing imitates, and the addresses that really
# belong to each. A name is "official" on these addresses and their parts.
_BRANDS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "paypal": frozenset({"paypal.com", "paypal.me"}),
        "apple": frozenset({"apple.com", "icloud.com"}),
        "icloud": frozenset({"icloud.com", "apple.com"}),
        "microsoft": frozenset({"microsoft.com", "live.com", "office.com", "outlook.com",
                                "microsoftonline.com"}),
        "outlook": frozenset({"outlook.com", "live.com", "office.com", "microsoft.com"}),
        "office365": frozenset({"office.com", "microsoft.com"}),
        "google": frozenset({"google.com", "google.co.uk", "gmail.com"}),
        "gmail": frozenset({"gmail.com", "google.com"}),
        "amazon": frozenset({"amazon.com", "amazon.co.uk"}),
        "netflix": frozenset({"netflix.com"}),
        "facebook": frozenset({"facebook.com", "fb.com"}),
        "instagram": frozenset({"instagram.com"}),
        "whatsapp": frozenset({"whatsapp.com"}),
        "linkedin": frozenset({"linkedin.com"}),
        "github": frozenset({"github.com"}),
        "steam": frozenset({"steampowered.com", "steamcommunity.com"}),
        "hsbc": frozenset({"hsbc.co.uk", "hsbc.com"}),
        "barclays": frozenset({"barclays.co.uk", "barclays.com"}),
        "lloyds": frozenset({"lloydsbank.com"}),
        "natwest": frozenset({"natwest.com"}),
        "santander": frozenset({"santander.co.uk"}),
        "monzo": frozenset({"monzo.com"}),
        "revolut": frozenset({"revolut.com"}),
        "royalmail": frozenset({"royalmail.com"}),
        "dhl": frozenset({"dhl.com", "dhl.co.uk"}),
        "evri": frozenset({"evri.com"}),
        "hmrc": frozenset({"gov.uk"}),
        "dvla": frozenset({"gov.uk"}),
        "nhs": frozenset({"nhs.uk", "nhs.net"}),
        "coinbase": frozenset({"coinbase.com"}),
        "binance": frozenset({"binance.com"}),
    }
)  # fmt: skip

# Characters that are drawn like a Latin letter. Used only to recognise an
# imitation, never to change what is shown.
_LOOKALIKES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "|": "l",
        # Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t",
        "в": "b", "н": "h",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "χ": "x",
        "ε": "e",
        # Others
        "ɡ": "g", "ɑ": "a", "ı": "i", "ℓ": "l",
    }
)  # fmt: skip
_LOOKALIKE_PAIRS: Final = (("rn", "m"), ("vv", "w"), ("cl", "d"))

_SCHEME: Final = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_NUMERIC_HOST: Final = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}\.?")
_PLAIN_NAME: Final = re.compile(r"[a-z0-9_\-]{1,63}(\.[a-z0-9_\-]{1,63})*")
_EMBEDDED: Final = re.compile(r"https?:|https?%3a|%2f%2f|www\.", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class LinkReport:
    """What the analyser found.

    Attributes:
        verdict: ``"high"``, ``"medium"``, ``"low"`` or ``"none"``: the most
            severe finding.
        findings: Each sign found, in a fixed order, at most once.
        host: The site's name in its standard ASCII form, when it could be
            read. Shown so the user sees where the link really goes.
        site: The part of the name that is registered to someone, such as
            ``example.co.uk``, when it could be worked out. A best guess
            from a short list of endings, not a full public suffix list.
    """

    verdict: str
    findings: tuple[Finding, ...]
    host: str | None
    site: str | None

    def as_result(self) -> dict[str, object]:
        """The report as plain data, with every sentence taken from the fixed tables."""
        return {
            "verdict": self.verdict,
            "summary": SUMMARIES[self.verdict],
            "findings": [
                {
                    "code": finding.value,
                    "severity": EXPLANATIONS[finding][0].value,
                    "explanation": EXPLANATIONS[finding][1],
                }
                for finding in self.findings
            ],
            "host": self.host,
            "site": self.site,
            "note": LIMITS_NOTE,
        }


def _report(findings: list[Finding], host: str | None, site: str | None) -> LinkReport:
    unique = tuple(dict.fromkeys(findings))
    severities = {EXPLANATIONS[finding][0] for finding in unique}
    verdict = "none"
    for level in (Severity.LOW, Severity.MEDIUM, Severity.HIGH):
        if level in severities:
            verdict = level.value
    return LinkReport(verdict, unique, host, site)


def _site(labels: list[str]) -> str:
    """The registered part of a name: the last two labels, or three under a known ending."""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_official(host: str, domains: frozenset[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def _script(character: str) -> str | None:
    """The alphabet a letter belongs to, such as LATIN or CYRILLIC, or ``None``."""
    if not character.isalpha():
        return None
    name = unicodedata.name(character, "")
    return name.split(" ", 1)[0] if name else "UNKNOWN"


def _unmask(token: str) -> str:
    """Reduce a name to how it looks, so that lookalikes compare equal.

    Lookalike characters become the Latin letters they imitate, and letters
    that are hard to tell apart in many fonts are treated as one: a capital
    "I" is drawn like "l", but site names are lower-cased before they are
    checked, so "paypaI" arrives here as "paypai". Applied to both the name
    and the brand, so that "paypai" and "paypal" compare equal.
    """
    plain = "".join(_LOOKALIKES.get(character, character) for character in token)
    for pair, letter in _LOOKALIKE_PAIRS:
        plain = plain.replace(pair, letter)
    return plain.replace("i", "l")


def _brand_findings(unicode_host: str, ascii_host: str) -> list[Finding]:
    """Look for a real brand's name, or an imitation of it, on an address that is not theirs."""
    findings: list[Finding] = []
    tokens = [token for token in re.split(r"[.\-]", unicode_host) if token]
    for brand, domains in _BRANDS.items():
        if _is_official(ascii_host, domains):
            continue
        for token in tokens:
            if token == brand:
                findings.append(Finding.BRAND_ELSEWHERE)
            elif _unmask(token) == _unmask(brand):
                findings.append(Finding.LOOKALIKE_BRAND)
    return findings


def _brand_address_in(text: str, ascii_host: str) -> bool:
    """Whether ``text`` contains a brand's own address, on a site that is not theirs.

    Only a full address such as "paypal.com" counts, not the bare name, so an
    article that merely mentions a company is not flagged.
    """
    for domains in _BRANDS.values():
        if _is_official(ascii_host, domains):
            continue
        if any(
            re.search(rf"(?<![a-z0-9]){re.escape(domain)}(?![a-z0-9])", text) for domain in domains
        ):
            return True
    return False


def _host_findings(host: str) -> tuple[list[Finding], str | None]:
    """Check the site's name. Return the findings and its ASCII form, if readable."""
    findings: list[Finding] = []
    if "%" in host:
        return [Finding.ENCODED_NAME], None

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return [Finding.IP_ADDRESS], str(address)
    if _NUMERIC_HOST.fullmatch(host):
        # Digits only, or hexadecimal, or fewer than four parts: browsers
        # still read these as a numeric address.
        return [Finding.DISGUISED_IP_ADDRESS], None

    if host.isascii():
        ascii_host = host
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except UnicodeError:
            return [Finding.UNREADABLE_NAME], None
        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append(Finding.PUNYCODE)
    else:
        unicode_host = host
        if any(not character.isascii() and character.isalpha() for character in host):
            findings.append(Finding.NON_LATIN_NAME)
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return [*findings, Finding.UNREADABLE_NAME], None

    for label in unicode_host.split("."):
        scripts = {script for character in label if (script := _script(character))}
        if len(scripts) > 1:
            findings.append(Finding.MIXED_SCRIPTS)
            break

    ascii_host = ascii_host.lower()
    if _PLAIN_NAME.fullmatch(ascii_host) is None:
        # Not a name a browser would accept, and not text Potato will repeat:
        # the model reads the result, so a name must not carry a message.
        return [*findings, Finding.UNUSUAL_NAME_CHARACTERS], None
    findings.extend(_brand_findings(unicode_host.lower(), ascii_host))
    return findings, ascii_host


def _name_findings(labels: list[str], site: str) -> list[Finding]:
    """Checks on the shape of a readable name."""
    findings: list[Finding] = []
    if site in _SHORTENERS:
        findings.append(Finding.LINK_SHORTENER)
    ending = labels[-1]
    if ending in _FILE_LIKE_ENDINGS:
        findings.append(Finding.FILE_LIKE_ENDING)
    if len(labels) - len(site.split(".")) > MAX_SUBDOMAINS:
        findings.append(Finding.MANY_SUBDOMAINS)
    if ending in _CHEAP_ENDINGS:
        findings.append(Finding.CHEAP_ENDING)
    name = site.split(".", 1)[0]
    if name.startswith("xn--"):
        # The encoded form always has hyphens of its own; count the real ones.
        try:
            name = name.encode("ascii").decode("idna")
        except UnicodeError:
            name = ""
    if name.count("-") >= 3:
        findings.append(Finding.MANY_HYPHENS)
    return findings


def _split(link: str) -> SplitResult | None:
    try:
        parts = urlsplit(link)
        _ = parts.port  # Raises ValueError for a port that is not a number.
    except ValueError:
        return None
    return parts


def _normalise(link: str) -> tuple[str, str, bool]:
    """Read the link the way a browser would, before any check looks at it.

    Returns the link to parse, its scheme, and whether the scheme was added
    because the link had none. A browser treats a backslash as a slash and
    accepts any number of slashes after ``https:``. Reading the link
    differently from a browser would report the wrong destination, so the
    same rules are applied here.
    """
    link = link.replace("\\", "/")
    found = _SCHEME.match(link)
    # "example.com:8080/x" is a name and a port, not a scheme.
    if found is None or "." in found.group(1):
        return "http://" + link.lstrip("/"), "http", True
    scheme = found.group(1).lower()
    rest = link[found.end() :].lstrip("/")
    return f"{scheme}://{rest}", scheme, False


def analyse(link: str) -> LinkReport:
    """Examine ``link`` as text and report signs of a trick. Never opens it."""
    findings: list[Finding] = []
    if any(unicodedata.category(character) == "Cf" for character in link):
        findings.append(Finding.HIDDEN_CHARACTERS)
    if "\\" in link:
        findings.append(Finding.BACKSLASH)

    normalised, scheme, assumed = _normalise(link)
    if scheme in _DANGEROUS_SCHEMES:
        return _report([*findings, Finding.DANGEROUS_SCHEME], None, None)
    if scheme not in _WEB_SCHEMES:
        return _report([*findings, Finding.NOT_A_WEB_ADDRESS], None, None)

    parts = _split(normalised)
    host = parts.hostname if parts is not None else None
    if parts is None or not host:
        return _report([*findings, Finding.NOT_A_LINK], None, None)

    if "@" in parts.netloc:
        findings.append(Finding.USER_INFO)
    host_findings, ascii_host = _host_findings(host.rstrip("."))
    findings.extend(host_findings)

    site: str | None = None
    numeric = {Finding.IP_ADDRESS, Finding.DISGUISED_IP_ADDRESS} & set(host_findings)
    if ascii_host is not None and not numeric:
        labels = [label for label in ascii_host.split(".") if label]
        if len(labels) < 2:
            return _report([*findings, Finding.NOT_A_LINK], ascii_host, None)
        site = _site(labels)
        findings.extend(_name_findings(labels, site))

    if parts.port is not None and parts.port not in (80, 443):
        findings.append(Finding.UNUSUAL_PORT)
    after_name = f"{parts.path}?{parts.query}#{parts.fragment}"
    if _EMBEDDED.search(after_name):
        findings.append(Finding.EMBEDDED_LINK)
    if ascii_host is not None and _brand_address_in(after_name.lower(), ascii_host):
        findings.append(Finding.BRAND_IN_PATH)
    if scheme == "http" and not assumed:
        findings.append(Finding.NOT_ENCRYPTED)
    if set(re.split(r"[^a-z0-9]+", normalised.lower())) & _URGENT_WORDS:
        findings.append(Finding.URGENT_WORDS)
    if len(link) > LONG_LINK_CHARACTERS:
        findings.append(Finding.VERY_LONG)
    return _report(findings, ascii_host, site)


def link_analysis_tools() -> tuple[ToolDefinition, ...]:
    """Return the link analysis tool."""

    def handle(arguments: Mapping[str, ArgumentValue]) -> Mapping[str, object]:
        return analyse(str(arguments["link"])).as_result()

    return (
        ToolDefinition(
            name="analyse_link",
            risk=RiskLevel.LOW,
            arguments={"link": LINK_FIELD},
            handler=handle,
            description=(
                "Check a link the user received for signs of phishing, by examining its text. "
                "The link is never opened."
            ),
        ),
    )
