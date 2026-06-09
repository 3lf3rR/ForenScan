#!/usr/bin/env python3
"""
  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  ForenScan — Digital Forensics Tool
  File Analysis & Metadata Extraction
  Usage:
    python main.py --file <path>                     Analyze a single file
    python main.py --dir  <path>                     Scan all files in a directory
    python main.py --file <path> --verify <hash>     Verify file integrity
"""

import os
import sys
import json
import click
from colorama import init, Fore, Style

from analyzer.hashing import compute_hashes, verify_hash
from analyzer.filetype import detect_filetype
from analyzer.metadata import extract_metadata
from analyzer.reporter import build_report, output_json, output_text

init(autoreset=True)

VERSION = "1.0.0"


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  █████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
  ██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """ + Style.RESET_ALL)
    print(Fore.WHITE + Style.BRIGHT + "  Digital Forensics Tool — File Analysis & Metadata Extraction")
    print(Fore.CYAN + f"  Version {VERSION}  |  github.com/YOUR_USERNAME/ForenScan\n")
    print(Fore.WHITE + "  " + "─" * 74 + "\n")


def print_step(msg, quiet):
    if not quiet:
        print(Fore.CYAN + f"  ›  {msg}")


def print_ok(msg, quiet):
    if not quiet:
        print(Fore.GREEN + f"  ✓  {msg}")


def print_err(msg):
    print(Fore.RED + Style.BRIGHT + f"\n  ✗  ERROR: {msg}\n")


def analyze_file(filepath, analyst, report_format, output, verify_hash_val, algorithm, quiet):
    """Run full forensic analysis on a single file."""
    if not os.path.isfile(filepath):
        print_err(f"File not found: {filepath}")
        return None

    if not quiet:
        print(Fore.YELLOW + Style.BRIGHT + f"\n  TARGET  →  {os.path.abspath(filepath)}")
        print(Fore.WHITE + "  " + "─" * 74)

    # Step 1: Hashes
    print_step("Computing cryptographic hashes...", quiet)
    hashes = compute_hashes(filepath)
    print_ok(f"MD5     {hashes.get('md5', 'N/A')}", quiet)
    print_ok(f"SHA-1   {hashes.get('sha1', 'N/A')}", quiet)
    print_ok(f"SHA-256 {hashes.get('sha256', 'N/A')}", quiet)

    # Step 2: File type
    print_step("Detecting true file type via magic bytes...", quiet)
    filetype = detect_filetype(filepath)
    print_ok(f"Type    {filetype.get('true_mime', 'N/A')}  ({filetype.get('true_description', '')})", quiet)

    if filetype.get("spoofing_alert"):
        print(Fore.RED + Style.BRIGHT +
              f"  ⚠   SPOOFING ALERT — Extension '{filetype.get('file_extension')}' "
              f"does not match true type '{filetype.get('true_mime')}'")

    # Step 3: Metadata
    print_step("Extracting metadata...", quiet)
    mime = filetype.get("true_mime", "application/octet-stream")
    metadata = extract_metadata(filepath, mime)
    print_ok("Metadata extracted", quiet)

    if metadata.get("timestamp_anomaly") and not quiet:
        print(Fore.YELLOW + f"  ⚠   {metadata['timestamp_anomaly']}")

    # Step 4: Build report
    report = build_report(filepath, hashes, filetype, metadata, analyst=analyst)

    # Step 5: Hash verification (optional)
    if verify_hash_val:
        print_step(f"Verifying {algorithm.upper()} hash...", quiet)
        match = verify_hash(filepath, verify_hash_val, algorithm)
        report["hash_verification"] = {
            "algorithm": algorithm,
            "expected": verify_hash_val,
            "match": match,
            "result": "PASS ✓" if match else "FAIL ✗ — File may have been tampered with!",
        }
        if not quiet:
            if match:
                print(Fore.GREEN + Style.BRIGHT + "  ✓   Hash verification PASSED — file is intact.")
            else:
                print(Fore.RED + Style.BRIGHT + "  ✗   Hash verification FAILED — file may have been tampered with!")

    # Step 6: Output report
    if not quiet:
        print(Fore.WHITE + "\n  " + "─" * 74)
        print(Fore.CYAN + Style.BRIGHT + "  FORENSIC REPORT\n")

    if report_format == "json":
        content = output_json(report, output)
    else:
        content = output_text(report, output)

    print(content)

    # Risk level banner
    risk = report.get("risk_level", "CLEAN")
    risk_color = {
        "CLEAN": Fore.GREEN,
        "LOW":   Fore.YELLOW,
        "MEDIUM": Fore.YELLOW,
        "HIGH":  Fore.RED,
    }.get(risk, Fore.WHITE)

    if not quiet:
        print(Fore.WHITE + "  " + "─" * 74)
        flag_count = len(report["flags"])
        if flag_count:
            print(risk_color + Style.BRIGHT +
                  f"  RISK LEVEL: {risk}  —  {flag_count} flag(s) detected.")
            for flag in report["flags"]:
                print(risk_color + f"     ⚠  {flag}")
        else:
            print(Fore.GREEN + Style.BRIGHT + "  RISK LEVEL: CLEAN  —  No anomalies detected.")
        print(Fore.WHITE + "  " + "─" * 74 + "\n")

    if output and not quiet:
        print(Fore.CYAN + f"  Report saved → {output}\n")

    return report


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--file", "-f", "filepath", default=None,
              help="Path to a single file to analyze.")
@click.option("--dir",  "-d", "dirpath",  default=None,
              help="Path to a directory to scan (recursive).")
@click.option("--analyst", "-a", default="Unknown", show_default=True,
              help="Analyst name embedded in the report.")
@click.option("--report", "-r", "report_format", default="text",
              type=click.Choice(["text", "json"]), show_default=True,
              help="Output format.")
@click.option("--output", "-o", default=None,
              help="Save report to this file path.")
@click.option("--verify", "-v", "verify_hash_val", default=None,
              help="Known-good hash to verify the file against.")
@click.option("--algorithm", default="sha256",
              type=click.Choice(["md5", "sha1", "sha256"]), show_default=True,
              help="Hash algorithm used with --verify.")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and progress — print report only.")
def cli(filepath, dirpath, analyst, report_format, output,
        verify_hash_val, algorithm, quiet):
    """
    \b
    ForenScan — Digital Forensics CLI Tool
    Analyze files for metadata, hashes, type spoofing, and anomalies.

    \b
    Examples:
      python main.py --file photo.jpg
      python main.py --file doc.pdf --analyst "Jane" --report json
      python main.py --file evidence.zip --verify "abc123" --algorithm sha256
      python main.py --dir ./evidence/ --output report.json
    """
    if not quiet:
        print_banner()

    if not filepath and not dirpath:
        print_err("No target provided. Use --file or --dir.\nRun with --help for full usage.")
        sys.exit(1)

    if filepath and dirpath:
        print_err("Use either --file or --dir, not both.")
        sys.exit(1)

    # ── Single file mode ──────────────────────────────────────────────────────
    if filepath:
        analyze_file(filepath, analyst, report_format, output,
                     verify_hash_val, algorithm, quiet)

    # ── Directory scan mode ───────────────────────────────────────────────────
    elif dirpath:
        if not os.path.isdir(dirpath):
            print_err(f"Directory not found: {dirpath}")
            sys.exit(1)

        files = [
            os.path.join(root, name)
            for root, _, filenames in os.walk(dirpath)
            for name in filenames
        ]

        if not files:
            print(Fore.YELLOW + "  No files found in directory.")
            sys.exit(0)

        print(Fore.CYAN + Style.BRIGHT + f"  Scanning {len(files)} file(s) in {dirpath} ...\n")

        all_reports = []
        high_risk   = []

        for fp in files:
            report = analyze_file(fp, analyst, report_format, None,
                                  None, algorithm, quiet=True)
            if report:
                all_reports.append(report)
                if report.get("risk_level") in ("HIGH", "MEDIUM"):
                    high_risk.append(report)

        # Summary
        print(Fore.WHITE + "  " + "─" * 74)
        print(Fore.CYAN + Style.BRIGHT + "  DIRECTORY SCAN SUMMARY")
        print(Fore.WHITE + "  " + "─" * 74)
        print(f"  Files scanned    : {len(all_reports)}")
        print(f"  Flagged (H/M)    : {len(high_risk)}")
        print(f"  Clean            : {len(all_reports) - len(high_risk)}")

        if high_risk:
            print(Fore.RED + Style.BRIGHT + "\n  ⚠  Flagged Files:")
            for r in high_risk:
                flags_str = " | ".join(r["flags"])
                print(Fore.RED +
                      f"     [{r['risk_level']:6}]  {r['report_meta']['filename']}")
                print(Fore.YELLOW + f"              {flags_str}")
        else:
            print(Fore.GREEN + Style.BRIGHT + "\n  ✓  All files clean — no anomalies detected.")

        print(Fore.WHITE + "  " + "─" * 74 + "\n")

        if output:
            with open(output, "w") as f:
                json.dump(all_reports, f, indent=2, default=str)
            print(Fore.CYAN + f"  Combined report saved → {output}\n")


if __name__ == "__main__":
    cli()
