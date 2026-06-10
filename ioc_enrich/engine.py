"""Shared analysis pipeline used by both the CLI and the GUI.

Keeping the parse -> enrich -> rows flow in one place means the GUI and the
command line always behave identically; each is just a thin front-end over
:func:`analyse`.
"""

from __future__ import annotations

import os
import re
from typing import Callable

from .enrichment import Enricher
from .extractor import IOC, extract_from_files
from .report import build_rows

# progress(done, total, message) — called as enrichment proceeds.
ProgressFn = Callable[[int, int, str], None]

# File-hash type by hex length, used for direct --hash lookups.
_HEX_RE = re.compile(r"^[a-f0-9]+$")
_HASH_TYPE_BY_LEN = {32: "md5", 40: "sha1", 64: "sha256"}


def hashes_to_iocs(values: list[str], source: str = "manual") -> list[IOC]:
    """Turn raw hash strings into IOC objects (md5/sha1/sha256 by length).

    Lets the scanner / a user feed hashes straight in without wrapping them in a
    log file. Raises ``ValueError`` on anything that isn't a valid hex hash.
    """
    iocs: list[IOC] = []
    seen: set[str] = set()
    for raw in values:
        v = raw.strip().lower()
        if not v or v in seen:
            continue
        if not _HEX_RE.match(v) or len(v) not in _HASH_TYPE_BY_LEN:
            raise ValueError(raw)
        seen.add(v)
        ioc = IOC(value=v, type=_HASH_TYPE_BY_LEN[len(v)], count=1)
        ioc.sources.add(source)
        iocs.append(ioc)
    return iocs


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
    return analyse_iocs(
        iocs,
        enrich=enrich,
        vt_key=vt_key,
        abuse_key=abuse_key,
        pause=pause,
        progress=progress,
        usage_out=usage_out,
    )


def analyse_iocs(
    iocs: list[IOC],
    enrich: bool = True,
    vt_key: str | None = None,
    abuse_key: str | None = None,
    pause: float = 0.0,
    progress: ProgressFn | None = None,
    usage_out: dict | None = None,
) -> list[dict]:
    """Enrich an already-built IOC list and return report rows.

    The second half of :func:`analyse`, split out so callers that already have
    IOCs (e.g. a list of file hashes from the YARA scanner) reuse the exact same
    enrich -> rows pipeline.
    """
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
