"""Command-line entry point for the IOC enrichment tool."""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv
from rich.console import Console

from . import __version__
from .engine import analyse, analyse_iocs, collect_files, hashes_to_iocs
from .report import export_csv, export_json, render_console


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="Parse a log file, extract IOCs, and enrich them via "
        "VirusTotal and AbuseIPDB.",
    )
    p.add_argument(
        "logfiles",
        nargs="*",
        help="one or more log/text files to analyse",
    )
    p.add_argument(
        "--dir",
        metavar="PATH",
        help="analyse every file in this folder (combined with any listed files)",
    )
    p.add_argument(
        "--recursive",
        action="store_true",
        help="with --dir, also descend into subfolders",
    )
    p.add_argument(
        "--hash",
        nargs="+",
        metavar="HASH",
        dest="hashes",
        help="check one or more file hashes (md5/sha1/sha256) directly against "
        "VirusTotal - no log file needed (e.g. paste hashes from the YARA scanner)",
    )
    p.add_argument(
        "--no-enrich",
        action="store_true",
        help="extract only; skip all threat-intel API calls",
    )
    p.add_argument(
        "--include-private-ips",
        action="store_true",
        help="also report RFC1918 / loopback / reserved IPs (off by default)",
    )
    p.add_argument("--json", metavar="PATH", help="write results to a JSON file")
    p.add_argument("--csv", metavar="PATH", help="write results to a CSV file")
    p.add_argument(
        "--pause",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="delay between API calls to respect free-tier rate limits "
        "(e.g. 15 for VirusTotal's 4 req/min)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Ensure the rich table renders on legacy Windows code pages.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    console = Console()

    load_dotenv()
    vt_key = os.getenv("VIRUSTOTAL_API_KEY") or None
    abuse_key = os.getenv("ABUSEIPDB_API_KEY") or None

    # --- Direct hash-check mode (no log file) ---------------------------------
    if args.hashes:
        try:
            iocs = hashes_to_iocs(args.hashes)
        except ValueError as bad:
            console.print(
                f"[bold red]error:[/] not a valid md5/sha1/sha256 hash: {bad}"
            )
            return 1
        if not args.no_enrich and not vt_key:
            console.print(
                "[yellow]No VirusTotal key set (.env) — can't check hashes. "
                "Copy .env.example to .env and add VIRUSTOTAL_API_KEY.[/]"
            )
        console.print(f"[cyan]Checking[/] {len(iocs)} hash(es) against VirusTotal ...")
        with console.status("Looking up ..."):
            rows = analyse_iocs(
                iocs, enrich=not args.no_enrich, vt_key=vt_key,
                abuse_key=abuse_key, pause=args.pause,
            )
        render_console(rows, console)
        if args.json:
            export_json(rows, args.json)
            console.print(f"[green]Wrote[/] {args.json}")
        if args.csv:
            export_csv(rows, args.csv)
            console.print(f"[green]Wrote[/] {args.csv}")
        return 0

    try:
        files = collect_files(args.logfiles, folder=args.dir, recursive=args.recursive)
    except FileNotFoundError as exc:
        console.print(f"[bold red]error:[/] file not found: {exc}")
        return 1
    except NotADirectoryError as exc:
        console.print(f"[bold red]error:[/] not a folder: {exc}")
        return 1
    if not files:
        console.print("[bold red]error:[/] no input files. Pass file paths, --dir PATH, or --hash HASH.")
        return 1

    label = files[0] if len(files) == 1 else f"{len(files)} files"
    console.print(f"[cyan]Parsing[/] {label} ...")
    if not args.no_enrich and not vt_key and not abuse_key:
        console.print(
            "[yellow]No API keys set (.env) — running in extract-only mode. "
            "Copy .env.example to .env to enable enrichment.[/]"
        )

    with console.status("Analysing ..."):
        rows = analyse(
            files,
            enrich=not args.no_enrich,
            vt_key=vt_key,
            abuse_key=abuse_key,
            pause=args.pause,
            include_private_ips=args.include_private_ips,
        )

    if not rows:
        console.print("[yellow]No IOCs found.[/]")
        return 0
    render_console(rows, console)

    if args.json:
        export_json(rows, args.json)
        console.print(f"[green]Wrote[/] {args.json}")
    if args.csv:
        export_csv(rows, args.csv)
        console.print(f"[green]Wrote[/] {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
