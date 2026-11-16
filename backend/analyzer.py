"""Deterministic, explainable email risk scoring engine.

Security notes:
- Every email field is untrusted input.
- URLs are parsed statically. They are never fetched, resolved or followed.
- Nothing from the email is logged or stored.
- Values from the email that appear in findings are limited to hostnames,
  passed through `_safe()` (strict character set, truncated). Attachment
  names and body text are never echoed back.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.utils import getaddresses, parseaddr
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from backend.schemas import EmailAnalyzeRequest, EmailAnalyzeResponse

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

SENDER, LINKS, CONTENT, EVASION = "sender", "links", "content", "evasion"

# EVASION holds techniques aimed at our own parsers and scanners. It has its
# own cap so a single evasion signal (40) can't be absorbed by another
# category's cap, and on its own it lands at least at Medium.
CATEGORY_CAPS: dict[str, int] = {SENDER: 35, LINKS: 40, CONTENT: 25, EVASION: 40}
CATEGORY_LABELS: dict[str, str] = {
    SENDER: "sender spoofing indicators",
    LINKS: "deceptive or risky links",
    CONTENT: "risky attachments or pressure language",
    EVASION: "techniques built to evade security scanners",
}
EVASION_POINTS = 40

# Bodies at or above this size are treated as possible padding. Gmail clips
# messages over ~102 KB, so legitimate bulk mail is built to stay below it.
# ">=" on purpose: the add-on truncates plain bodies to exactly 100,000 characters.
TRUNCATION_THRESHOLD = 100_000

# (minimum score, verdict), checked from the top down. Anything lower is "Low".
VERDICT_THRESHOLDS: list[tuple[int, str]] = [(70, "Critical"), (45, "High"), (20, "Medium")]

# Limits that bound processing work on attacker-controlled input.
MAX_LINKS = 500
MAX_URL_LEN = 2_048
MAX_ANCHOR_TEXT_LEN = 500
MAX_TEXT_SCAN_LEN = 200_000

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# Brand name -> registrable domains the brand legitimately sends from or links to.
OFFICIAL_BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "gmail.com", "googleusercontent.com", "googleapis.com", "youtube.com"},
    "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
}

# Multi-label public suffixes, so "evil.co.uk" -> registrable "evil.co.uk".
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
    "co.jp", "co.za", "co.in", "co.il", "com.br", "com.mx", "com.cn", "com.tr",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "ml", "cf", "tk", "ga",
    "work", "loan", "download", "review", "icu", "cam", "rest", "buzz", "monster",
    "cyou", "sbs",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "ps1", "psm1", "msi", "msp", "jar", "lnk", "reg", "cpl", "dll", "iso", "img",
    "vhd", "vhdx", "sct", "chm", "appx", "msix", "apk", "application", "gadget",
}
MACRO_EXTENSIONS = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace", "cab", "arj"}
DECOY_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif",
}
# "TLDs" that are really file extensions, to avoid reading "report.pdf" as a domain.
FILE_LIKE_TLDS = (
    DECOY_EXTENSIONS | DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS | {"htm", "html", "php", "aspx"}
) - {"com"}  # ".com" is both an executable type and the most common real TLD

URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "immediate action", "act now", "within 24 hours",
    "within 48 hours", "final notice", "last warning", "suspended", "suspension",
    "locked", "expire", "expires", "expired", "deactivated", "unusual activity",
    "unauthorized",
]
CREDENTIAL_KEYWORDS = [
    "password", "verify your account", "verify your identity", "confirm your identity",
    "login", "log in", "sign in", "credentials", "security code", "one-time code",
    "ssn", "social security",
]
FINANCIAL_KEYWORDS = [
    "invoice", "payment", "wire transfer", "bank details", "bank account", "gift card",
    "overdue", "refund", "billing", "outstanding balance", "remittance",
]

# Characters attackers use to hide text or flip how a filename is displayed.
INVISIBLE_CHARS_RE = re.compile("[­​-‏⁠﻿]")
BIDI_OVERRIDE_RE = re.compile("[‪-‮⁦-⁩]")

EMAIL_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
)
DOMAIN_IN_TEXT_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.IGNORECASE
)
PLAIN_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)
# A backslash in the authority of an http(s) URL, e.g. "https://evil.com\@paypal.com".
# Browsers (WHATWG URL standard) treat "\" as "/" and go to evil.com;
# urlsplit treats it as part of the userinfo and reports paypal.com.
BACKSLASH_AUTHORITY_RE = re.compile(r"^https?:[/\\]{2}[^/?#]*\\", re.IGNORECASE)
# An archive password given in the message, e.g. "Archive password: 4471" or
# "the password for the file is X".
ARCHIVE_PASSWORD_RE = re.compile(
    r"\b(?:password|passcode|passwd|pwd)\b[^.]{0,40}?(?:\s+is\s+|\s*[:=]\s*)\S{3,}",
    re.IGNORECASE,
)
LEET_TABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _keyword_re(keywords: list[str]) -> re.Pattern[str]:
    ordered = sorted(keywords, key=len, reverse=True)  # longest phrase wins
    return re.compile(r"\b(?:" + "|".join(map(re.escape, ordered)) + r")\b", re.IGNORECASE)


URGENCY_RE = _keyword_re(URGENCY_KEYWORDS)
CREDENTIAL_RE = _keyword_re(CREDENTIAL_KEYWORDS)
FINANCIAL_RE = _keyword_re(FINANCIAL_KEYWORDS)

# Tag groups used for attack classification and recommendations.
MALWARE_TAGS = {
    "dangerous_attachment", "double_extension", "bidi_attachment",
    "macro_attachment", "dangerous_download", "encrypted_archive_lure",
}
PHISHING_LINK_TAGS = {
    "link_text_mismatch", "brand_link_mismatch", "url_userinfo", "ip_url",
    "punycode_url", "brand_in_url", "dangerous_scheme", "url_backslash",
}
IMPERSONATION_TAGS = {
    "reply_to_domain_mismatch", "display_name_spoof", "display_name_email",
    "sender_brand_impersonation", "reply_to_multiple",
}
SPOOF_TAGS = IMPERSONATION_TAGS | {
    "reply_to_address_mismatch", "reply_to_malformed", "sender_idn", "sender_ip",
    "malformed_sender",
}
ATTACHMENT_TAGS = MALWARE_TAGS - {"dangerous_download"} | {"archive_attachment"}

# Definitive indicators of compromise: they override the weighted sum, because
# an executable disguised as an attachment is malicious on its own.
CRITICAL_OVERRIDE_TAGS = {"dangerous_attachment", "double_extension", "bidi_attachment"}
CRITICAL_OVERRIDE_MIN_SCORE = 75

# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    """One triggered rule: its category, stable tag, points and finding text."""

    category: str
    tag: str
    points: int
    message: str


@dataclass(frozen=True)
class Link:
    href: str
    text: str  # visible anchor text; "" for bare URLs found in plain text


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _safe(value: str, max_len: int = 80) -> str:
    """Restrict an untrusted value to a hostname-like charset before display."""
    return re.sub(r"[^A-Za-z0-9.\-:_\[\]]", "", value)[:max_len]


def _display_host(host: str) -> str:
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return "non-ASCII domain"
    return _safe(host)


def _join(items: list[str], limit: int = 3) -> str:
    shown = items[:limit]
    extra = len(items) - len(shown)
    text = ", ".join(shown)
    return f"{text} and {extra} more" if extra else text


def _human_list(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + (", and " if len(parts) > 2 else " and ") + parts[-1]


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    if host.isdigit() or re.fullmatch(r"0x[0-9a-f]+", host, re.IGNORECASE):
        return True  # decimal / hex encoded IPv4, e.g. http://3232235777
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) without network lookups."""
    host = host.lower().rstrip(".")
    if _is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _tld(host: str) -> str:
    return host.lower().rstrip(".").rsplit(".", 1)[-1]


def _brands_in(text: str, *, leet: bool = False) -> set[str]:
    """Brand names mentioned in text (or in a domain, with leet-speak undone)."""
    lowered = text.lower()
    if leet:
        lowered = lowered.translate(LEET_TABLE)
    tokens = re.findall(r"[a-z0-9]+", lowered)
    compact = "".join(tokens)
    token_set = set(tokens)
    return {
        brand for brand in OFFICIAL_BRAND_DOMAINS
        if brand in token_set or (len(brand) >= 6 and brand in compact)
    }


def _impersonated_brands(brands: set[str], domain: str) -> list[str]:
    reg = _registrable(domain)
    return sorted(b for b in brands if reg not in OFFICIAL_BRAND_DOMAINS[b])


def _normalize_text(text: str) -> str:
    text = INVISIBLE_CHARS_RE.sub("", text[:MAX_TEXT_SCAN_LEN])
    return " ".join(text.split())


def _address(raw: str | None) -> str:
    """Bare lowercase address from 'Name <addr>' or 'addr'."""
    if not raw:
        return ""
    return parseaddr(raw)[1].strip().lower()


def _addresses(raw: str | None) -> list[str]:
    """Every bare lowercase address in a header that may list several.

    Unlike parseaddr, which (strict, Python 3.13+) returns nothing at all
    for "a@x.com, b@evil.com", this keeps every address so none is hidden.
    """
    if not raw:
        return []
    return [addr.strip().lower() for _, addr in getaddresses([raw]) if addr and addr.strip()]


def _domain_of(address: str) -> str:
    return address.rpartition("@")[2].strip("[]").rstrip(".") if "@" in address else ""


# ---------------------------------------------------------------------------
# Extraction (static only, no network access)
# ---------------------------------------------------------------------------


def _parse_html(html: str) -> tuple[str, list[Link]]:
    """Return (visible text, anchor links) from an HTML body."""
    soup = BeautifulSoup(html, "html.parser")
    links = [
        Link(
            href=str(a["href"])[:MAX_URL_LEN],
            text=a.get_text(" ", strip=True)[:MAX_ANCHOR_TEXT_LEN],
        )
        for a in soup.find_all("a", href=True, limit=MAX_LINKS)
    ]
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return soup.get_text(" ", strip=True), links


def _extract_plain_urls(text: str) -> list[Link]:
    links = []
    for match in PLAIN_URL_RE.finditer(text[:MAX_TEXT_SCAN_LEN]):
        links.append(Link(href=match.group(0).rstrip(".,;:!?")[:MAX_URL_LEN], text=""))
        if len(links) >= MAX_LINKS:
            break
    return links


def _domain_in_text(text: str) -> str | None:
    for match in DOMAIN_IN_TEXT_RE.finditer(text):
        candidate = match.group(1).lower()
        if _tld(candidate) not in FILE_LIKE_TLDS:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Rule: Sender & spoofing (max 35)
# ---------------------------------------------------------------------------


def check_sender(email: EmailAnalyzeRequest) -> list[Signal]:
    signals: list[Signal] = []

    def add(tag: str, points: int, message: str) -> None:
        signals.append(Signal(SENDER, tag, points, message))

    parsed_name, _ = parseaddr(email.sender_email)
    address = _address(email.sender_email)
    domain = _domain_of(address)
    display_name = email.sender_name or parsed_name or ""

    if not domain:
        add("malformed_sender", 20, "The sender address is malformed or missing a domain.")
    elif _is_ip(domain):
        add("sender_ip", 20, f"The sender uses a raw IP address ({_safe(domain)}) instead of a domain.")
    elif not domain.isascii() or "xn--" in domain:
        add("sender_idn", 15,
            f"The sender domain ({_display_host(domain)}) uses internationalized characters "
            "that can imitate a legitimate domain (homograph attack).")
    elif not EMAIL_RE.fullmatch(address):
        add("malformed_sender", 20, "The sender address is malformed.")
    else:
        if _tld(domain) in SUSPICIOUS_TLDS:
            add("sender_suspicious_tld", 10,
                f"The sender domain uses a top-level domain often abused for phishing (.{_tld(domain)}).")
        first_label = domain.split(".")[0]
        if first_label.count("-") >= 3 or sum(c.isdigit() for c in first_label) >= 4:
            add("sender_odd_domain", 5,
                f"The sender domain ({_safe(domain)}) has an unusual, auto-generated looking structure.")

    if domain and domain.isascii():
        brands = _impersonated_brands(_brands_in(domain, leet=True), domain)
        if brands:
            add("sender_brand_impersonation", 20,
                f"The sender domain ({_safe(domain)}) contains the brand name "
                f"'{_join(brands)}' but is not an official domain of that brand.")

    if display_name and domain:
        brands = _impersonated_brands(_brands_in(display_name), domain)
        if brands:
            add("display_name_spoof", 15,
                f"The display name claims to be '{_join(brands)}', but the email was sent "
                f"from an unrelated domain ({_display_host(domain)}).")
        embedded = EMAIL_RE.search(display_name)
        if embedded and embedded.group(0).lower() != address:
            add("display_name_email", 15,
                "The display name contains a different email address than the real sender, "
                "a common trick to fake the sender's identity.")

    raw_reply_to = (email.reply_to or "").strip()
    reply_addrs = _addresses(raw_reply_to)

    if raw_reply_to and not reply_addrs:
        add("reply_to_malformed", 15,
            "The Reply-To header is malformed, so where replies would go cannot be verified.")
    if len(reply_addrs) > 1:
        domains = list(dict.fromkeys(_display_host(_domain_of(a)) for a in reply_addrs))
        signals.append(Signal(
            EVASION, "reply_to_multiple", EVASION_POINTS,
            f"The Reply-To header lists {len(reply_addrs)} addresses ({_join(domains)}), so "
            "replies would go to all of them. Extra Reply-To addresses are a known trick "
            "to slip a hidden recipient past email parsers."))

    others = [a for a in reply_addrs if a != address]
    foreign = [a for a in others if not domain or _registrable(_domain_of(a)) != _registrable(domain)]
    if foreign:
        reply_domains = list(dict.fromkeys(_display_host(_domain_of(a)) for a in foreign))
        add("reply_to_domain_mismatch", 20,
            f"Replies would go to a different domain ({_join(reply_domains)}) "
            f"than the sender's ({_display_host(domain) or 'unknown'}).")
    elif others:
        add("reply_to_address_mismatch", 8,
            "The Reply-To address differs from the sender address (same domain).")

    return signals


# ---------------------------------------------------------------------------
# Rule: URLs & links (max 40)
# ---------------------------------------------------------------------------

# tag -> (points, finding template). Each tag scores once; matching items are listed.
LINK_RULES: dict[str, tuple[int, str]] = {
    "link_text_mismatch": (30, "Link text shows one domain but the link actually points to another "
                               "({items}). This is a classic phishing technique."),
    "dangerous_scheme": (20, "A link uses a dangerous URL scheme ({items}) that can run code or hide content."),
    "url_userinfo": (20, "A link hides its real destination using the 'user@host' URL trick ({items})."),
    "ip_url": (20, "A link points to a raw IP address instead of a domain name ({items})."),
    "brand_link_mismatch": (15, "Link text mentions a well-known brand but points to an unrelated "
                                "domain ({items})."),
    "brand_in_url": (15, "A link domain contains a brand name but is not owned by that brand ({items})."),
    "punycode_url": (15, "A link uses an internationalized (punycode) domain that may imitate a "
                         "legitimate one ({items})."),
    "dangerous_download": (15, "A link points directly to an executable or macro-enabled file ({items})."),
    "suspicious_tld_url": (10, "A link uses a top-level domain often abused for phishing ({items})."),
    "shortener": (10, "A link uses a URL shortener that hides its final destination ({items})."),
    "insecure_http": (5, "A link uses unencrypted HTTP ({items})."),
    "url_backslash": (EVASION_POINTS, "A link uses a backslash trick so that browsers open a different "
                                      "site than the address appears to show ({items})."),
}
# Link tags scored under the EVASION category instead of LINKS.
EVASION_LINK_TAGS = {"url_backslash"}


def _analyze_link(link: Link, hits: dict[str, dict[str, None]]) -> None:
    """Record every rule a single link triggers into `hits` (tag -> ordered set of items)."""

    def hit(tag: str, item: str) -> None:
        hits.setdefault(tag, {})[item] = None

    href = link.href.strip()
    if href.lower().startswith("www."):
        href = "http://" + href
    # Analyze the URL the way a browser will resolve it, not the way urlsplit
    # reads it: for http(s), WHATWG treats every "\" as "/".
    backslash_trick = bool(BACKSLASH_AUTHORITY_RE.match(href))
    if backslash_trick:
        href = href.replace("\\", "/")
    try:
        parts = urlsplit(href)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return  # unparseable URL: nothing reliable to analyze

    scheme = parts.scheme.lower()
    if scheme in {"javascript", "data", "vbscript"}:
        hit("dangerous_scheme", f"{scheme}:")
        return
    if not host:
        return  # mailto:, tel:, cid:, relative or in-page anchors

    shown = _display_host(host)
    reg = _registrable(host)

    if backslash_trick:
        hit("url_backslash", shown)  # `shown` is the host the browser will really visit
    if parts.username is not None or "@" in parts.netloc:
        hit("url_userinfo", shown)
    if _is_ip(host):
        hit("ip_url", shown)
    if "xn--" in host or not host.isascii():
        hit("punycode_url", shown)
    if _tld(host) in SUSPICIOUS_TLDS:
        hit("suspicious_tld_url", shown)
    if host in URL_SHORTENERS or reg in URL_SHORTENERS:
        hit("shortener", shown)
    if host.isascii() and _impersonated_brands(_brands_in(host, leet=True), host):
        hit("brand_in_url", shown)
    path_ext = parts.path.lower().rsplit(".", 1)[-1] if "." in parts.path else ""
    if path_ext in DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS:
        hit("dangerous_download", f"{shown} (.{path_ext})")
    if scheme == "http":
        hit("insecure_http", shown)

    if link.text:
        text_domain = _domain_in_text(link.text)
        if text_domain and _registrable(text_domain) != reg:
            hit("link_text_mismatch", f"{_safe(text_domain)} -> {shown}")
        for brand in _impersonated_brands(_brands_in(link.text), host):
            hit("brand_link_mismatch", f"{brand} -> {shown}")


def check_links(links: list[Link]) -> list[Signal]:
    hits: dict[str, dict[str, None]] = {}
    for link in links[:MAX_LINKS]:
        _analyze_link(link, hits)

    signals = []
    for tag, (points, template) in LINK_RULES.items():
        if tag in hits:
            category = EVASION if tag in EVASION_LINK_TAGS else LINKS
            signals.append(Signal(category, tag, points, template.format(items=_join(list(hits[tag])))))
    return signals


# ---------------------------------------------------------------------------
# Rule: Content & attachments (max 25)
# ---------------------------------------------------------------------------


def _check_attachments(names: list[str]) -> list[Signal]:
    dangerous: set[str] = set()
    macro: set[str] = set()
    archive: set[str] = set()
    double = bidi = False

    for raw in names:
        if BIDI_OVERRIDE_RE.search(raw):
            bidi = True
        name = INVISIBLE_CHARS_RE.sub("", BIDI_OVERRIDE_RE.sub("", raw)).strip().rstrip(". ").lower()
        parts = name.split(".")
        if len(parts) < 2:
            continue
        ext = parts[-1]
        if ext in DANGEROUS_EXTENSIONS:
            dangerous.add(ext)
        elif ext in MACRO_EXTENSIONS:
            macro.add(ext)
        elif ext in ARCHIVE_EXTENSIONS:
            archive.add(ext)
        if len(parts) >= 3 and parts[-2] in DECOY_EXTENSIONS and ext in DANGEROUS_EXTENSIONS | MACRO_EXTENSIONS:
            double = True

    def exts(values: set[str]) -> str:
        return _join(sorted(f".{v}" for v in values))  # only our own known extensions are echoed

    signals = []
    if dangerous:
        signals.append(Signal(CONTENT, "dangerous_attachment", 20,
                              f"An attachment has a dangerous executable file type ({exts(dangerous)})."))
    if bidi:
        signals.append(Signal(CONTENT, "bidi_attachment", 20,
                              "An attachment name contains hidden text-direction characters that "
                              "disguise its real file type."))
    if double:
        signals.append(Signal(CONTENT, "double_extension", 10,
                              "An attachment uses a double extension (e.g. 'invoice.pdf.exe') to look "
                              "like a harmless document."))
    if macro:
        signals.append(Signal(CONTENT, "macro_attachment", 12,
                              f"An attachment is a macro-enabled Office file ({exts(macro)}), a common "
                              "malware delivery method."))
    if archive:
        signals.append(Signal(CONTENT, "archive_attachment", 5,
                              f"An attachment is a compressed archive ({exts(archive)}) that can hide "
                              "malicious files from scanners."))
    return signals


def _check_keywords(text: str) -> list[Signal]:
    # (tag, pattern, points per distinct keyword, cap, description)
    groups = [
        ("urgency_keywords", URGENCY_RE, 4, 10, "urgency or pressure language"),
        ("credential_keywords", CREDENTIAL_RE, 4, 10, "requests related to credentials or account access"),
        ("financial_keywords", FINANCIAL_RE, 3, 8, "payment or financial language"),
    ]
    signals = []
    for tag, pattern, per_hit, cap, description in groups:
        found = sorted({m.group(0).lower() for m in pattern.finditer(text)})
        if found:
            quoted = [f"'{k}'" for k in found]  # keywords come from our own lists
            signals.append(Signal(CONTENT, tag, min(per_hit * len(found), cap),
                                  f"The message contains {description}: {_join(quoted, limit=5)}."))
    return signals


def check_content(attachment_names: list[str], text: str) -> list[Signal]:
    return _check_attachments(attachment_names) + _check_keywords(text)


# ---------------------------------------------------------------------------
# Rule: Scanner evasion (max 40)
# ---------------------------------------------------------------------------


def _has_archive(names: list[str]) -> bool:
    for raw in names:
        name = INVISIBLE_CHARS_RE.sub("", BIDI_OVERRIDE_RE.sub("", raw)).strip().rstrip(". ").lower()
        if "." in name and name.rsplit(".", 1)[-1] in ARCHIVE_EXTENSIONS:
            return True
    return False


def check_evasion(email: EmailAnalyzeRequest, text: str) -> list[Signal]:
    """Content shaped to defeat scanners rather than to fool the reader.

    Reply-To and URL-parser evasion are scored where they are parsed
    (check_sender, check_links) but in this same EVASION category.
    """
    signals = []

    oversized = [label for label, body in (("plain-text", email.body_plain), ("HTML", email.body_html))
                 if body and len(body) >= TRUNCATION_THRESHOLD]
    if oversized:
        signals.append(Signal(
            EVASION, "oversized_body", EVASION_POINTS,
            f"The {' and '.join(oversized)} body is at least {TRUNCATION_THRESHOLD:,} characters long. "
            "Padding an email this much is a known way to push malicious content past scanner "
            "limits, so part of this email may not have been analyzed."))

    # Fail-closed: an encrypted archive can't be scanned, and sending its
    # password in the same email exists only to get it past the scanner.
    if _has_archive(email.attachment_names) and ARCHIVE_PASSWORD_RE.search(text):
        signals.append(Signal(
            EVASION, "encrypted_archive_lure", EVASION_POINTS,
            "An archive is attached and the message supplies its password. Encrypting an "
            "archive stops security scanners from seeing what is inside, a common malware "
            "delivery technique."))

    return signals


# ---------------------------------------------------------------------------
# Verdict, classification and explanation
# ---------------------------------------------------------------------------


def _verdict(score: int) -> str:
    for minimum, verdict in VERDICT_THRESHOLDS:
        if score >= minimum:
            return verdict
    return "Low"


def _attack_type(tags: set[str], verdict: str) -> str:
    if verdict == "Low":
        return "None Detected"
    if tags & MALWARE_TAGS:
        return "Malware Delivery"
    if tags & PHISHING_LINK_TAGS:
        return "Credential Phishing"
    if "financial_keywords" in tags and tags & IMPERSONATION_TAGS:
        return "Business Email Compromise (BEC)"
    if tags & SPOOF_TAGS:
        return "Sender Spoofing / Impersonation"
    if "oversized_body" in tags:
        return "Detection Evasion"
    return "Social Engineering"


def _explanation(score: int, verdict: str, attack_type: str,
                 category_scores: dict[str, int], signals: list[Signal],
                 overridden: bool = False) -> str:
    if overridden:
        return (f"This email is classified as {verdict} risk (score {score}/100), consistent with "
                f"{attack_type}. It carries a definitive indicator of compromise, which overrides "
                f"the weighted score: {signals[0].message}")
    if not signals:
        return (f"This email is classified as Low risk (score {score}/100). The rule engine found "
                "no indicators of phishing, spoofing, or malware.")

    ranked = sorted(CATEGORY_CAPS, key=lambda c: category_scores[c], reverse=True)
    parts = [f"{CATEGORY_LABELS[c]} ({category_scores[c]}/{CATEGORY_CAPS[c]})"
             for c in ranked if category_scores[c] > 0]

    if verdict == "Low":
        return (f"This email is classified as Low risk (score {score}/100). Only minor indicators "
                f"were found: {_human_list(parts)}. No strong signs of an attack were detected.")
    return (f"This email is classified as {verdict} risk (score {score}/100), consistent with "
            f"{attack_type}, because it shows {_human_list(parts)}. "
            f"Strongest indicator: {signals[0].message}")


def _recommendations(verdict: str, tags: set[str]) -> list[str]:
    if verdict == "Low":
        return ["No action required. Stay alert for unexpected requests for credentials or payments."]

    recs = []
    if verdict in ("High", "Critical"):
        recs.append("Do not reply, click any links, or open any attachments in this email.")
        recs.append("Report this email to your security team using Gmail's 'Report phishing' option.")
    else:
        recs.append("Treat this email with caution and verify it is legitimate before acting on it.")

    if any(t in LINK_RULES for t in tags):
        recs.append("Do not click the links. Open the official website by typing its address into your browser.")
    if tags & ATTACHMENT_TAGS:
        recs.append("Do not open or download the attachments. Ask your security team to inspect them in a sandbox.")
    if tags & SPOOF_TAGS:
        recs.append("Verify the sender's identity through a known, independent channel, such as a phone "
                    "number from the organization's official website.")
    if "credential_keywords" in tags:
        recs.append("Never enter your password through an email link. If you already did, change it "
                    "immediately and enable multi-factor authentication.")
    if "financial_keywords" in tags:
        recs.append("Do not make payments or change bank details without confirming through a trusted channel.")
    if "oversized_body" in tags:
        recs.append("Part of this email was too large to analyze. Treat it as unverified until you "
                    "confirm it with the sender through a trusted channel.")
    return recs


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze_email(email: EmailAnalyzeRequest) -> EmailAnalyzeResponse:
    html_text, links = _parse_html(email.body_html) if email.body_html else ("", [])
    links += _extract_plain_urls(email.body_plain or html_text)
    text = _normalize_text(" ".join(filter(None, [email.subject, email.body_plain, html_text])))

    signals = (check_sender(email) + check_links(links)
               + check_content(email.attachment_names, text) + check_evasion(email, text))
    signals.sort(key=lambda s: s.points, reverse=True)

    category_scores = {
        category: min(sum(s.points for s in signals if s.category == category), cap)
        for category, cap in CATEGORY_CAPS.items()
    }
    score = min(sum(category_scores.values()), 100)
    tags = {s.tag for s in signals}

    # Critical override: a definitive IoC bypasses the category caps.
    overridden = bool(tags & CRITICAL_OVERRIDE_TAGS)
    if overridden:
        score = max(score, CRITICAL_OVERRIDE_MIN_SCORE)
        verdict, attack_type = "Critical", "Malware Delivery"
        # Lead the findings with the indicator that triggered the override.
        signals.sort(key=lambda s: s.tag not in CRITICAL_OVERRIDE_TAGS)
    else:
        verdict = _verdict(score)
        attack_type = _attack_type(tags, verdict)

    return EmailAnalyzeResponse(
        score=score,
        verdict=verdict,
        attack_type=attack_type,
        category_scores=category_scores,
        findings=[s.message for s in signals],
        explanation=_explanation(score, verdict, attack_type, category_scores, signals, overridden),
        recommendations=_recommendations(verdict, tags),
    )
