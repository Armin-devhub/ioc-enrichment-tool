"""Lightweight log parser - turns raw log lines into readable fields.

This is a pragmatic, format-agnostic parser (not a full SIEM normaliser): it
pulls a timestamp, a source/category, a level/action, common key=value fields
(mapped to canonical names), and any IOCs out of each line, so an analyst can
read messy logs at a glance instead of squinting at raw text.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .extractor import extract, refang

_TS_ISO = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
# Windows event-log export style, e.g. "02/06/2026 18:34:14" or "2/6/2026 6:34:14 AM"
_TS_SLASH = re.compile(
    r"\b\d{1,2}/\d{1,2}/\d{4}[ T]\d{1,2}:\d{2}:\d{2}(?:\s?[AP]M)?\b"
)
_TS_SYSLOG = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")
# A leading "[1234]" event-id token (how the Windows export tags each line).
_EVENTID = re.compile(r"^\s*\[(\d{1,6})\]\s*")
_KV = re.compile(r"([A-Za-z_][\w.\-]*)=(\"[^\"]*\"|'[^']*'|\S+)")
_LEVEL = re.compile(
    r"\b(CRITICAL|ERROR|WARNING|WARN|NOTICE|INFO|DEBUG|"
    r"ALLOW|ALLOWED|DENY|DENIED|BLOCK|BLOCKED|DROP|DROPPED|ACCEPT|"
    r"FAIL|FAILED|FAILURE|SUCCESS|QUARANTINED)\b"
)
# A "source"/category token: the first word that ends in a colon (after any
# leading timestamp), e.g. "firewall:", "proxy:", "dns:".
_SOURCE = re.compile(r"^\s*([A-Za-z][\w\-]*)\s*:")

# Recognised Windows/Sysmon log channels - for these, the channel name is the
# source rather than any "word:" found inside the event message.
_KNOWN_CHANNELS = {"System", "Application", "Security", "Sysmon", "Defender"}

# Map the many real-world field names to a handful of canonical ones.
_FIELD_ALIASES = {
    "src_ip": ("src", "source", "src_ip", "srcip", "source_ip", "saddr", "client", "client_ip", "from"),
    "dst_ip": ("dst", "dest", "dst_ip", "dstip", "destination", "destination_ip", "daddr", "server", "server_ip", "to"),
    "user": ("user", "username", "account", "usr", "uid", "subject", "logon"),
    "port": ("dport", "dst_port", "dest_port", "port"),
    "proto": ("proto", "protocol"),
    "action": ("action", "act", "disposition"),
    "host": ("host", "hostname", "computer", "dvc", "device"),
}


@dataclass
class ParsedLine:
    lineno: int
    raw: str
    ts: str = ""
    source: str = ""
    level: str = ""
    fields: dict = field(default_factory=dict)
    iocs: list = field(default_factory=list)
    message: str = ""

    def as_dict(self) -> dict:
        d = {
            "lineno": self.lineno, "ts": self.ts, "source": self.source,
            "level": self.level, "iocs": self.iocs, "message": self.message,
        }
        d.update(self.fields)
        return d


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def parse_line(lineno: int, line: str, default_source: str = "") -> ParsedLine:
    raw = line.rstrip("\n")
    text = refang(raw)

    ts_match = _TS_ISO.search(text) or _TS_SLASH.search(text) or _TS_SYSLOG.search(text)
    ts = ts_match.group(0) if ts_match else ""

    # Everything after the timestamp is the "body" we describe.
    body = text[ts_match.end():].strip() if ts_match else text.strip()

    # Windows export tags each line with the event id, e.g. "[134] message".
    event_id = ""
    eid = _EVENTID.match(body)
    if eid:
        event_id = eid.group(1)
        body = body[eid.end():].strip()

    # For known Windows/Sysmon channels the channel name IS the source, and the
    # whole body is the message. For generic logs, a leading "word:" prefix
    # (firewall:/proxy:/dns:) is the inline source.
    if default_source in _KNOWN_CHANNELS:
        source = default_source
        message = body
    else:
        src_match = _SOURCE.search(body)
        if src_match:
            source = src_match.group(1)
            message = body[src_match.end():].strip()
        else:
            source = default_source
            message = body

    kv = {k.lower(): _strip_quotes(v) for k, v in _KV.findall(text)}
    fields: dict[str, str] = {}
    for canonical, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in kv:
                fields[canonical] = kv[alias]
                break
    if event_id:
        fields["event_id"] = event_id

    # Level/action: explicit action= field, else a keyword, else the event id.
    level = fields.get("action", "")
    if not level:
        lvl = _LEVEL.search(text)
        if lvl:
            level = lvl.group(0)
        elif event_id:
            level = f"ID {event_id}"

    iocs = [i.value for i in extract(text, include_private_ips=True)]

    return ParsedLine(
        lineno=lineno, raw=raw, ts=ts, source=source, level=level,
        fields=fields, iocs=iocs, message=message or body,
    )


def _channel_name(path: str) -> str:
    """Friendly log-channel name from a filename, used as the default source."""
    name = os.path.splitext(os.path.basename(path))[0]
    if "Sysmon" in name:
        return "Sysmon"
    if "Defender" in name:
        return "Defender"
    if "_" in name or "-" in name:
        return name.replace("-", "_").split("_")[-1]
    return name


def parse_text(text: str, default_source: str = "") -> list[ParsedLine]:
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            out.append(parse_line(i, line, default_source))
    return out


def parse_file(path: str) -> list[ParsedLine]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_text(fh.read(), default_source=_channel_name(path))


def parse_files(paths: list[str]) -> list[ParsedLine]:
    out: list[ParsedLine] = []
    for p in paths:
        out.extend(parse_file(p))
    return out
