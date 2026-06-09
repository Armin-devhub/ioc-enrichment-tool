"""Rendering and export of enriched IOC results."""

from __future__ import annotations

import csv
import json
import os
import time

from rich.console import Console
from rich.table import Table

from .enrichment import Enrichment, worst_verdict
from .extractor import IOC

_VERDICT_STYLE = {
    "malicious": "bold red",
    "suspicious": "yellow",
    "clean": "green",
    "unknown": "dim",
    "skipped": "dim",
}


# Short action label + full analyst-style conclusion, derived deterministically
# from the verdict (and, for unknowns, whether enrichment was attempted at all).
def conclude(verdict: str, ioc_type: str, enrich_attempted: bool) -> tuple[str, str]:
    if verdict == "malicious":
        return ("Escalate & block", "Confirmed malicious by threat intel - escalate to L2 and block.")
    if verdict == "suspicious":
        return ("Investigate", "Flagged by at least one source - investigate before closing.")
    if verdict == "clean":
        return ("Dismiss (benign)", "Known-good across sources - low priority, likely a false positive.")
    # verdict == "unknown"
    if not enrich_attempted:
        return ("Enrich first", "Not yet enriched - add API keys and re-run to assess.")
    if ioc_type == "email":
        return ("Check sender", "No email-reputation source - verify the sender/header manually.")
    return ("Manual review", "No threat intel on record - review manually (may be new or unseen).")


def _looks_like_version_ip(value: str) -> bool:
    """e.g. 4.0.0.0 / 1.0.0.0 - a version string or network base, not a host."""
    octets = value.split(".")
    return len(octets) == 4 and octets[1:] == ["0", "0", "0"]


def explain(ioc_type: str, ioc_value: str, enrichments: list[Enrichment]) -> str:
    """Plain-English 'why this verdict' hint, to nudge true- vs false-positive
    judgement - built from the structured signals each provider returned."""
    notes: list[str] = []

    if ioc_type == "ipv4" and _looks_like_version_ip(ioc_value):
        notes.append("looks like a version number / network base - probably not a real host IP")

    for e in enrichments:
        s = e.signals or {}
        if e.provider == "VirusTotal":
            mal, total = s.get("malicious", 0), s.get("total", 0)
            if mal:
                if mal <= 3:
                    notes.append(f"only {mal}/{total} VT engines flagged it - low confidence, verify manually")
                elif mal >= 10:
                    notes.append(f"{mal}/{total} VT engines - strong consensus, likely real")
                else:
                    notes.append(f"{mal}/{total} VT engines flagged it")
            cd = s.get("creation_date")
            if cd:
                age_days = int((time.time() - cd) / 86400)
                if 0 <= age_days < 30:
                    notes.append(f"domain registered ~{age_days} days ago - newly registered, higher risk")
        elif e.provider == "AbuseIPDB":
            conf, rep = s.get("confidence", 0), s.get("reports", 0)
            if s.get("is_tor"):
                notes.append("Tor exit node - anonymised traffic, suspicious in most networks")
            if conf >= 75 and rep >= 20:
                notes.append(f"{conf}% abuse confidence across {rep} reports - strong signal")
            elif (conf > 0 or rep > 0) and rep <= 2 and conf < 25:
                notes.append(f"only {rep} report(s) at {conf}% - likely noise / false positive")

    return "; ".join(notes)


def _row(ioc: IOC, enrichments: list[Enrichment], enrich_attempted: bool) -> dict:
    overall = worst_verdict(enrichments) if enrichments else "unknown"
    providers = "; ".join(
        f"{e.provider}:{e.verdict}" + (f" ({e.score})" if e.score else "")
        for e in enrichments
    )
    action, conclusion = conclude(overall, ioc.type, enrich_attempted)
    return {
        "value": ioc.value,
        "type": ioc.type,
        "count": ioc.count,
        "verdict": overall,
        "action": action,
        "conclusion": conclusion,
        "why": explain(ioc.type, ioc.value, enrichments),
        "providers": providers,
        "sources": sorted(ioc.sources),
        "enrichments": [e.as_dict() for e in enrichments],
    }


def build_rows(
    results: list[tuple[IOC, list[Enrichment]]], enrich_attempted: bool = True
) -> list[dict]:
    rows = [_row(ioc, enr, enrich_attempted) for ioc, enr in results]
    # Most dangerous first.
    order = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3, "skipped": 3}
    rows.sort(key=lambda r: (order.get(r["verdict"], 4), r["type"], r["value"]))
    return rows


def render_console(rows: list[dict], console: Console | None = None) -> None:
    console = console or Console()
    # Only show the source-file column when more than one file is in play.
    all_sources = {s for r in rows for s in r.get("sources", [])}
    show_sources = len(all_sources) > 1

    table = Table(title="IOC Enrichment Results", header_style="bold cyan", show_lines=False)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("IOC", overflow="fold")
    table.add_column("Hits", justify="right")
    table.add_column("Action", no_wrap=True)
    table.add_column("Intel", overflow="fold")
    if show_sources:
        table.add_column("Files", overflow="fold")

    for r in rows:
        style = _VERDICT_STYLE.get(r["verdict"], "")
        cells = [
            f"[{style}]{r['verdict']}[/]" if style else r["verdict"],
            r["type"],
            r["value"],
            str(r["count"]),
            f"[{style}]{r['action']}[/]" if style else r["action"],
            r["providers"] or "-",
        ]
        if show_sources:
            cells.append(", ".join(r.get("sources", [])) or "-")
        table.add_row(*cells)
    console.print(table)

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    console.print(f"\n[bold]{len(rows)} IOCs[/]  |  {summary}")


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def export_json(rows: list[dict], path: str) -> None:
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)


def export_csv(rows: list[dict], path: str) -> None:
    _ensure_parent(path)
    # utf-8-sig so Excel opens it with the right encoding.
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["verdict", "type", "ioc", "count", "action", "conclusion", "why", "intel", "files"]
        )
        for r in rows:
            writer.writerow([
                r["verdict"], r["type"], r["value"], r["count"],
                r.get("action", ""), r.get("conclusion", ""), r.get("why", ""),
                r["providers"], "; ".join(r.get("sources", [])),
            ])
