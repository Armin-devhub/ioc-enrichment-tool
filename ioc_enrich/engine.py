"""Shared analysis pipeline used by both the CLI and the GUI.

Keeping the parse -> enrich -> rows flow in one place means the GUI and the
command line always behave identically; each is just a thin front-end over
:func:`analyse`.
"""

from __future__ import annotations

import os
from typing import Callable

from .enrichment import Enricher
from .extractor import extract_from_files
from .report import build_rows

# progress(done, total, message) — called as enrichment proceeds.
ProgressFn = Callable[[int, int, str], None]


def collect_files(
    paths: list[str] | None = None,
    folder: str | None = None,
    recursive: bool = False,
) -> list[str]:
    """Resolve explicit files + an optional folder into a deduped file list.

    Raises ``FileNotFoundError`` / ``NotADirectoryError`` on bad inputs so the
    caller (CLI or GUI) can present the error however it likes.
    """
    files: list[str] = []

    for path in paths or []:
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        files.append(path)

    if folder:
        if not os.path.isdir(folder):
            raise NotADirectoryError(folder)
        if recursive:
            for root, _dirs, names in os.walk(folder):
                files.extend(os.path.join(root, n) for n in names)
        else:
            files.extend(
                os.path.join(folder, n)
                for n in os.listdir(folder)
                if os.path.isfile(os.path.join(folder, n))
            )

    seen: set[str] = set()
    unique: list[str] = []
    for f in files:
        key = os.path.abspath(f)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyse(
    files: list[str],
    enrich: bool = True,
    vt_key: str | None = None,
    abuse_key: str | None = None,
    pause: float = 0.0,
    include_private_ips: bool = False,
    progress: ProgressFn | None = None,
    usage_out: dict | None = None,
) -> list[dict]:
    """Parse ``files``, optionally enrich, and return report rows.

    ``progress`` (if given) is invoked as ``(done, total, message)`` so a UI can
    show a live progress bar without this module knowing anything about it.
    ``usage_out`` (if given) is filled with each provider's quota after
    enrichment, so a UI can update its usage bars.
    """
    iocs = extract_from_files(files, include_private_ips=include_private_ips)
    total = len(iocs)
    if progress:
        progress(0, total, f"Found {total} unique IOCs")

    results = []
    enrich_attempted = enrich and (bool(vt_key) or bool(abuse_key))
    if not enrich_attempted:
        results = [(ioc, []) for ioc in iocs]
        if progress:
            progress(total, total, "Extraction complete (no enrichment)")
    else:
        enricher = Enricher(vt_key, abuse_key, pause=pause)
        for i, ioc in enumerate(iocs, start=1):
            results.append((ioc, enricher.enrich(ioc.value, ioc.type)))
            if progress:
                progress(i, total, f"Enriching {i}/{total}: {ioc.value}")
        if usage_out is not None:
            usage_out.update(enricher.usage(refresh_vt=bool(vt_key)))

    return build_rows(results, enrich_attempted=enrich_attempted)
