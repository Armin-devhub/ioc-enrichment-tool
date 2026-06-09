"""IOC extraction from arbitrary text/log content.

Extracts and normalises the IOC types most useful for Tier-1 triage:
IPv4 addresses, domains, URLs, file hashes (MD5/SHA1/SHA256) and emails.
Handles common "defanged" notations (hxxp://, 1.2.3.4[.]5, evil[.]com,
foo[at]bar[.]com) so IOCs copied from reports/emails are still recognised.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

# Ordered so that more specific / containing types are matched first.
IOC_TYPES = ("url", "email", "sha256", "sha1", "md5", "ipv4", "domain")

# --- Defang normalisation ----------------------------------------------------

_DEFANG_REPLACEMENTS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[at]", "@"),
    ("(at)", "@"),
    (" at ", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)


def refang(text: str) -> str:
    """Convert defanged IOC notation back to a parsable form."""
    out = text
    for needle, repl in _DEFANG_REPLACEMENTS:
        out = out.replace(needle, repl)
    return out


# --- Patterns ----------------------------------------------------------------

_TLD = r"[a-z]{2,24}"
_LABEL = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
_DOMAIN = rf"(?:{_LABEL}\.)+{_TLD}"

# Authoritative set of real top-level domains, loaded from the bundled IANA
# list (data/tlds.txt). A string like "core.msi" or "host.client" only *looks*
# like a domain; validating the final label against this set rejects the
# filenames / internal identifiers that pollute real logs.
_FALLBACK_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "mil", "info", "biz",
    "xyz", "online", "site", "top", "club", "shop", "app", "dev", "ru",
    "cn", "uk", "de", "fr", "nl", "br", "in", "jp", "au", "ca", "us", "my",
}


def _load_tlds() -> frozenset[str]:
    path = os.path.join(os.path.dirname(__file__), "data", "tlds.txt")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return frozenset(
                line.strip().lower()
                for line in fh
                if line.strip() and not line.startswith("#")
            )
    except OSError:
        return frozenset(_FALLBACK_TLDS)


_VALID_TLDS = _load_tlds()

# Final-label values that look like a TLD but are really file extensions,
# so "file.exe" / "report.log" aren't reported as domains.
_FILE_EXT_SUFFIXES = {
    "exe", "dll", "sys", "bin", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "log", "txt", "tmp", "dat", "cfg", "ini", "csv", "json", "xml", "yml",
    "yaml", "png", "jpg", "jpeg", "gif", "bmp", "ico", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "zip", "rar", "gz", "tar", "7z", "iso",
    "py", "c", "cpp", "h", "go", "rs", "html", "css", "php", "asp", "aspx",
}

_PATTERNS = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]+", re.IGNORECASE),
    "email": re.compile(rf"\b[a-z0-9._%+-]+@{_DOMAIN}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(rf"\b{_DOMAIN}\b", re.IGNORECASE),
}


@dataclass
class IOC:
    value: str
    type: str
    count: int = 1
    sources: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "count": self.count,
            "sources": sorted(self.sources),
        }


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_public_ipv4(value: str) -> bool:
    """True only for globally-routable IPs worth enriching."""
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def extract(
    text: str, include_private_ips: bool = False, source: str | None = None
) -> list[IOC]:
    """Extract, normalise and de-duplicate IOCs from ``text``.

    Returns a list of :class:`IOC`, each carrying an occurrence ``count`` and,
    when ``source`` is given, the originating file recorded in ``sources`` so a
    multi-file report can show where each IOC came from.
    """
    refanged = refang(text)
    found: dict[tuple[str, str], IOC] = {}
    # Character spans already claimed by a more specific type, so we don't
    # also report the bare domain inside a URL/email as its own IOC.
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for ioc_type in IOC_TYPES:
        for m in _PATTERNS[ioc_type].finditer(refanged):
            start, end = m.span()
            value = m.group(0)

            if ioc_type == "domain":
                if overlaps(start, end):
                    continue
                tld = value.rsplit(".", 1)[-1].lower()
                # Must end in a real TLD, and not in an extension that merely
                # collides with one (e.g. an "archive.zip" filename — .zip is a
                # real TLD but here it's almost certainly a file).
                if tld not in _VALID_TLDS or tld in _FILE_EXT_SUFFIXES:
                    continue
            if ioc_type == "ipv4":
                if not _valid_ipv4(value):
                    continue
                if not include_private_ips and not _is_public_ipv4(value):
                    continue

            value = value.rstrip(".,;:)»\"'").lower()
            if not value:
                continue

            # A bare 4-octet match that is actually part of a hash etc. is
            # already excluded by \b boundaries; nothing more to do here.
            claimed.append((start, end))
            key = (ioc_type, value)
            if key in found:
                found[key].count += 1
            else:
                found[key] = IOC(value=value, type=ioc_type, count=1)
            if source:
                found[key].sources.add(source)

    return sorted(found.values(), key=lambda i: (i.type, i.value))


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def extract_from_file(
    path: str, include_private_ips: bool = False, source: str | None = None
) -> list[IOC]:
    return extract(
        _read_text(path),
        include_private_ips=include_private_ips,
        source=source if source is not None else os.path.basename(path),
    )


def merge(*ioc_lists: list[IOC]) -> list[IOC]:
    """Combine IOC lists from several files, summing counts and unioning sources."""
    merged: dict[tuple[str, str], IOC] = {}
    for iocs in ioc_lists:
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key in merged:
                merged[key].count += ioc.count
                merged[key].sources |= ioc.sources
            else:
                merged[key] = IOC(
                    value=ioc.value,
                    type=ioc.type,
                    count=ioc.count,
                    sources=set(ioc.sources),
                )
    return sorted(merged.values(), key=lambda i: (i.type, i.value))


def extract_from_files(
    paths: list[str], include_private_ips: bool = False
) -> list[IOC]:
    """Extract and merge IOCs across many files (deduped, with source tracking)."""
    per_file = [
        extract_from_file(p, include_private_ips=include_private_ips) for p in paths
    ]
    return merge(*per_file)
