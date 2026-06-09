#!/usr/bin/env python3
"""
ForenScan - File Analysis & Metadata Extraction Tool
Usage:
  python main.py --file <path>            Analyze a single file
  python main.py --dir <path>             Scan all files in a directory
  python main.py --file <path> --verify <hash>   Verify against known hash
"""

import os
import sys
import click
from colorama import init, Fore, Style

from analyzer.hashing import compute_hashes, verify_hash
from analyzer.filetype import detect_filetype
from analyzer.metadata import extract_metadata
from analyzer.reporter import build_report, output_json, output_text

init(autoreset=True)  # Initialize colorama for cross-platform color support


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
  ___                       _          CLI
 | __| ___  _ _  ___ _ _  _| |__  ___
 | _| / _ \| '_|/ -_) ' \(_-< / /_(_-<
 |_|  \___/|_|  \___|_||_/__/_\_\/__/
    """ + Style.RESET_ALL)
    print(Fore.WHITE + "  Digital Forensics Tool — File Analysis & Metadata Extraction\n")


def analyze_file(filepath, analyst, report_format, output, verify_hash_val, algorithm, quiet):
    """Run full forensic analysis on a single file."""
    if not os.path.isfile(filepath):
        print(Fore.RED + f"  [ERROR] File not found: {filepath}")
        return None

    if not quiet:
        print(Fore.YELLOW + f"\n  Analyzing: {filepath}")

    # Step 1: Hashes
    hashes = compute_hashes(filepath)
    if not quiet:
        print(Fore.GREEN + "  ✓ Hashes computed")

    # Step 2: File type
    filetype = detect_filetype(filepath)
    if not quiet:
        print(Fore.GREEN + "  ✓ File type detected")

    # Step 3: Metadata
    mime = filetype.get("true_mime", "application/octet-stream")
    metadata = extract_metadata(filepath, mime)
    if not quiet:
        print(Fore.GREEN + "  ✓ Metadata extracted")

    # Step 4: Build report
    report = build_report(filepath, hashes, filetype, metadata, analyst=analyst)

    # Step 5: Hash verification (optional)
    if verify_hash_val:
        match = verify_hash(filepath, verify_hash_val, algorithm)
        report["hash_verification"] = {
            "algorithm": algorithm,
            "expected": verify_hash_val,
            "match": match,
            "result": "PASS ✓" if match else "FAIL ✗ — File may have been tampered with!",
        }
        if not quiet:
            color = Fore.GREEN if match else Fore.RED
            print(color + f"  Hash verification: {'PASS' if match else 'FAIL'}")

    # Step 6: Output
    if report_format == "json":
        content = output_json(report, output)
    else:
        content = output_text(report, output)

    if not quiet or not output:
        # Color risk level in output
        risk = report.get("risk_level", "CLEAN")
        risk_color = {
            "CLEAN": Fore.GREEN,
            "LOW": Fore.YELLOW,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED,
        }.get(risk, Fore.WHITE)

        print(content if report_format == "text" else "")
        if report_format == "json":
            print(content)

        if report["flags"]:
            print(risk_color + f"\n  RISK LEVEL: {risk} — {len(report['flags'])} flag(s) found.")
        else:
            print(Fore.GREEN + "\n  RISK LEVEL: CLEAN — No anomalies detected.")

    if output and not quiet:
        print(Fore.CYAN + f"\n  Report saved to: {output}")

    return report


@click.command()
@click.option("--file", "-f", "filepath", default=None, help="Path to a single file to analyze.")
@click.option("--dir", "-d", "dirpath", default=None, help="Path to a directory to scan recursively.")
@click.option("--analyst", "-a", default="Unknown", show_default=True, help="Analyst name for the report.")
@click.option("--report", "-r", "report_format", default="text", type=click.Choice(["text", "json"]), show_default=True, help="Output format.")
@click.option("--output", "-o", default=None, help="Save report to this file path.")
@click.option("--verify", "-v", "verify_hash_val", default=None, help="Known-good hash to verify the file against.")
@click.option("--algorithm", default="sha256", type=click.Choice(["md5", "sha1", "sha256"]), show_default=True, help="Hash algorithm for --verify.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output; only print the report.")
def cli(filepath, dirpath, analyst, report_format, output, verify_hash_val, algorithm, quiet):
    """ForenScan — Analyze files for metadata, hashes, and anomalies."""
    if not quiet:
        print_banner()

    if not filepath and not dirpath:
        print(Fore.RED + "  [ERROR] Provide --file or --dir. Use --help for usage.")
        sys.exit(1)

    if filepath and dirpath:
        print(Fore.RED + "  [ERROR] Use either --file or --dir, not both.")
        sys.exit(1)

    if filepath:
        analyze_file(filepath, analyst, report_format, output, verify_hash_val, algorithm, quiet)

    elif dirpath:
        if not os.path.isdir(dirpath):
            print(Fore.RED + f"  [ERROR] Directory not found: {dirpath}")
            sys.exit(1)

        files = []
        for root, _, filenames in os.walk(dirpath):
            for name in filenames:
                files.append(os.path.join(root, name))

        if not files:
            print(Fore.YELLOW + "  No files found in directory.")
            sys.exit(0)

        print(Fore.CYAN + f"  Found {len(files)} file(s) to analyze...\n")
        all_reports = []
        high_risk = []

        for fp in files:
            report = analyze_file(fp, analyst, report_format, None, None, algorithm, quiet=True)
            if report:
                all_reports.append(report)
                if report.get("risk_level") in ("HIGH", "MEDIUM"):
                    high_risk.append(report)

        # Directory summary
        print(Fore.CYAN + Style.BRIGHT + "\n  === DIRECTORY SCAN SUMMARY ===")
        print(f"  Files analyzed : {len(all_reports)}")
        print(f"  High/Medium risk: {len(high_risk)}")

        if high_risk:
            print(Fore.RED + "\n  ⚠  Flagged files:")
            for r in high_risk:
                print(Fore.RED + f"     {r['report_meta']['filename']} — {r['risk_level']} — {'; '.join(r['flags'])}")
        else:
            print(Fore.GREEN + "  ✓  No high-risk files found.")

        # Save combined report if --output specified
        if output:
            import json
            with open(output, "w") as f:
                json.dump(all_reports, f, indent=2, default=str)
            print(Fore.CYAN + f"\n  Combined report saved to: {output}")


if __name__ == "__main__":
    cli()
