"""ComputerCheck (SelfCheck / Mode B) engine entrypoint.

Runs the read-only macOS checks and prints a v2 findings payload as JSON to
stdout. The Tauri shell invokes this, captures stdout, stores the result in the
encrypted local history, and renders the friendly report.

Unlike the USB tool's runner.py, this does NOT write report files or open a
browser. The app owns presentation and persistence. JSON on stdout is the only
contract.

Usage:
    python3 -m engine.selfcheck [--org-code CODE] [--device-pseudonym ID]
                                [--device-label NAME] [--pretty]

Design notes:
- Read-only. The checks never modify the audited machine.
- IoC / spyware findings are emitted here in full; SPLITTING them out of the
  routine export is the app's job (Phase 2), not the engine's. The engine is
  honest and complete; the export layer decides what leaves the device.
- Exit code is 0 even when checks fail to run; failures surface as ERROR
  findings, never as a crash. A non-zero exit means the engine itself broke.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .core import ScanContext, Scanner, summarize, Status


def _register_macos_checks(scanner: Scanner, only: str = "") -> None:
    from .checks_macos import cat01_updates, cat02_malware

    wanted = {c.strip() for c in only.split(",") if c.strip()} if only else None
    available = [
        ("CAT-1: OS & Updates", cat01_updates.run),
        ("CAT-2: Malware & Persistence", cat02_malware.run),
    ]
    for name, fn in available:
        cat_id = name.split(":")[0].strip()
        if wanted and cat_id not in wanted:
            continue
        scanner.register(name, fn)


def _register_windows_checks(scanner: Scanner, only: str = "") -> None:
    from .checks_windows import cat01_updates, cat02_malware

    wanted = {c.strip() for c in only.split(",") if c.strip()} if only else None
    available = [
        ("CAT-1: OS & Updates", cat01_updates.run),
        ("CAT-2: Malware & Persistence", cat02_malware.run),
    ]
    for name, fn in available:
        cat_id = name.split(":")[0].strip()
        if wanted and cat_id not in wanted:
            continue
        scanner.register(name, fn)


def build_payload(ctx: ScanContext, findings: list, summary: dict) -> dict:
    """Assemble the schema v2 payload. Backward compatible superset of v1."""
    return {
        "schema": "securityscan.findings/2",
        "tool": "computer-check",
        "tool_version": __version__,
        "scan": {
            "id": ctx.scan_id,
            "started_at": ctx.started_at,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ctx.started_at)),
            "hostname": ctx.hostname,
            "device_label": ctx.device_label,
            "os_name": ctx.os_name,
            "os_version": ctx.os_version,
            "arch": ctx.arch,
            "tags": list(ctx.tags),
            # v2 / Mode B additions:
            "app_mode": ctx.app_mode,
            "org_code": ctx.org_code,
            "device_pseudonym": ctx.device_pseudonym,
        },
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="computer-check",
        description="ComputerCheck v%s — read-only self-assessment for your own Mac." % __version__,
    )
    parser.add_argument("--org-code", default="", help="Organization enrollment code (optional).")
    parser.add_argument("--device-pseudonym", default="",
                        help="Stable random per-install id. The app generates and persists this.")
    parser.add_argument("--device-label", default="", help="Human label for this device.")
    parser.add_argument("--only", default="", help="Comma-separated categories (e.g. 'CAT-1').")
    parser.add_argument("--pretty", action="store_true", help="Indent the JSON output.")
    args = parser.parse_args(argv)

    ctx = ScanContext.detect(
        app_mode="self-check",
        org_code=args.org_code,
        device_pseudonym=args.device_pseudonym,
        device_label=args.device_label,
    )

    scanner = Scanner(ctx)
    if ctx.os_name == "macOS":
        _register_macos_checks(scanner, only=args.only)
    elif ctx.os_name == "Windows":
        _register_windows_checks(scanner, only=args.only)
    else:
        err = {
            "schema": "securityscan.findings/2",
            "tool": "computer-check",
            "tool_version": __version__,
            "error": f"ComputerCheck v{__version__} supports macOS and Windows. Detected: {ctx.os_name}.",
        }
        json.dump(err, sys.stdout)
        return 2
    findings = scanner.run()
    summary = summarize(findings)

    payload = build_payload(ctx, findings, summary)
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
