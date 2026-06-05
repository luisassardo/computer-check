"""ComputerCheck ingest (operator-side, offline).

Turns a folder of user-submitted `.age` exports into a single self-contained
HTML dashboard for the C-LAB think-tank: per-organization cohorts, per-device
score trends (by pseudonym), and the most common failing checks across the fleet.

This runs on Luis's machine only. It needs the C-LAB PRIVATE age key to decrypt.
Nothing here is part of the shipped app.

Usage:
    python3 cc_ingest.py --in ./inbox --identity ~/clab-identity.txt --out dashboard.html

Inputs in --in may be `.age` (encrypted exports) and/or `.json` (already-decrypted
payloads, e.g. for testing). Decryption uses the `age` CLI if present, else the
`pyrage` Python module (`pip install pyrage`).

Privacy: the dashboard shows org codes and device pseudonyms only — never real
names. It deliberately does NOT render the `evidence` field (which can contain
usernames/paths); it shows finding titles, status and severity for aggregate
analysis.
"""
from __future__ import annotations

import argparse
import html
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path


# --------------------------------------------------------------------------
# Decryption
# --------------------------------------------------------------------------

def _decrypt_with_age_cli(path: Path, identity: Path) -> bytes:
    r = subprocess.run(
        ["age", "-d", "-i", str(identity), str(path)],
        capture_output=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"age CLI failed on {path.name}: {r.stderr.decode(errors='replace')[:300]}")
    return r.stdout


def _decrypt_with_pyrage(path: Path, identity: Path) -> bytes:
    import pyrage  # type: ignore
    ident_text = identity.read_text(encoding="utf-8")
    # the identity file may have comment lines; take the AGE-SECRET-KEY line
    secret = next((ln.strip() for ln in ident_text.splitlines()
                   if ln.strip().startswith("AGE-SECRET-KEY-")), "")
    if not secret:
        raise RuntimeError(f"no AGE-SECRET-KEY found in {identity}")
    ident = pyrage.x25519.Identity.from_str(secret)
    return pyrage.decrypt(path.read_bytes(), [ident])


def decrypt_age(path: Path, identity: Path | None) -> bytes:
    if identity is None:
        raise RuntimeError("an --identity (age private key) is required to read .age files")
    if shutil.which("age"):
        return _decrypt_with_age_cli(path, identity)
    try:
        return _decrypt_with_pyrage(path, identity)
    except ImportError:
        raise RuntimeError(
            "cannot decrypt: install the `age` CLI (brew install age) or `pip install pyrage`."
        )


def load_payloads(in_dir: Path, identity: Path | None, keep_json: Path | None) -> list[dict]:
    payloads: list[dict] = []
    for f in sorted(in_dir.iterdir()):
        if f.is_dir():
            continue
        try:
            if f.suffix == ".age":
                raw = decrypt_age(f, identity)
            elif f.suffix == ".json":
                raw = f.read_bytes()
            else:
                continue
            data = json.loads(raw)
        except Exception as e:
            print(f"[ingest] skipped {f.name}: {e}", file=sys.stderr)
            continue
        if data.get("schema", "").startswith("securityscan.findings/"):
            payloads.append(data)
            if keep_json and f.suffix == ".age":
                keep_json.mkdir(parents=True, exist_ok=True)
                (keep_json / (f.stem + ".json")).write_bytes(raw)
        else:
            print(f"[ingest] skipped {f.name}: not a findings payload", file=sys.stderr)
    return payloads


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

def aggregate(payloads: list[dict]) -> dict:
    devices: dict[str, dict] = {}
    for p in payloads:
        s = p.get("scan", {})
        summ = p.get("summary", {})
        pid = s.get("device_pseudonym") or "unknown"
        rec = devices.setdefault(pid, {
            "org": s.get("org_code") or "(none)",
            "os": s.get("os_name") or "?",
            "scans": [],
        })
        rec["org"] = s.get("org_code") or rec["org"]
        rec["os"] = s.get("os_name") or rec["os"]
        rec["scans"].append({
            "ts": float(s.get("started_at") or 0),
            "iso": s.get("started_at_iso") or "",
            "score": int(summ.get("score") or 0),
            "by_status": summ.get("by_status", {}),
            "fails": [f for f in p.get("findings", []) if f.get("status") == "FAIL"],
        })
    for rec in devices.values():
        rec["scans"].sort(key=lambda x: x["ts"])
        rec["latest"] = rec["scans"][-1]

    # Org cohorts
    orgs: dict[str, dict] = {}
    for pid, rec in devices.items():
        o = orgs.setdefault(rec["org"], {"devices": set(), "scans": 0, "latest_scores": []})
        o["devices"].add(pid)
        o["scans"] += len(rec["scans"])
        o["latest_scores"].append(rec["latest"]["score"])

    # Fleet-wide most common failing checks (counted once per device, latest scan)
    fail_counts: dict[tuple, dict] = {}
    for rec in devices.values():
        seen = set()
        for f in rec["latest"]["fails"]:
            key = (f.get("id", ""), f.get("title", ""), f.get("severity", "INFO"), rec["os"])
            if key in seen:
                continue
            seen.add(key)
            entry = fail_counts.setdefault(key, {"id": key[0], "title": key[1], "severity": key[2], "os": key[3], "count": 0})
            entry["count"] += 1

    n_devices = len(devices)
    return {
        "devices": devices,
        "orgs": orgs,
        "fail_counts": sorted(fail_counts.values(), key=lambda e: (-e["count"], e["title"])),
        "n_devices": n_devices,
        "n_orgs": len(orgs),
        "n_scans": sum(len(r["scans"]) for r in devices.values()),
        "avg_latest": round(sum(r["latest"]["score"] for r in devices.values()) / n_devices) if n_devices else 0,
    }


# --------------------------------------------------------------------------
# HTML rendering (self-contained, ARGUS cyan)
# --------------------------------------------------------------------------

def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _ring_color(score: int) -> str:
    if score >= 80:
        return "#5be3c3"
    if score >= 55:
        return "#e3c45b"
    return "#e3735b"


def _sparkline(scores: list[int]) -> str:
    if not scores:
        return ""
    W, H = 120, 28
    n = len(scores)
    def x(i): return 2 + (0 if n == 1 else i / (n - 1) * (W - 4))
    def y(v): return H - 2 - (v / 100) * (H - 4)
    pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(scores))
    last = scores[-1]
    dot = f'<circle cx="{x(n-1):.1f}" cy="{y(last):.1f}" r="2.5" fill="{_ring_color(last)}"/>'
    return (f'<svg viewBox="0 0 {W} {H}" width="{W}" height="{H}" preserveAspectRatio="none">'
            f'<polyline points="{pts}" fill="none" stroke="#5be3c3" stroke-width="1.5"/>{dot}</svg>')


def _fmt_date(iso: str, ts: float) -> str:
    try:
        t = time.localtime(ts) if ts else time.strptime(iso[:10], "%Y-%m-%d")
        return time.strftime("%Y-%m-%d", t)
    except Exception:
        return iso[:10]


def render_html(stats: dict, generated_iso: str) -> str:
    kpi = lambda v, l, c="#e8edf1": (
        f'<div class="kpi"><div class="kpi-v" style="color:{c}">{_esc(v)}</div>'
        f'<div class="kpi-l">{_esc(l)}</div></div>'
    )
    kpis = (
        kpi(stats["n_devices"], "Devices", "#5be3c3")
        + kpi(stats["n_orgs"], "Organizations", "#5be3c3")
        + kpi(stats["n_scans"], "Scans", "#5be3c3")
        + kpi(stats["avg_latest"], "Avg latest score", _ring_color(stats["avg_latest"]))
    )

    # Org cohort rows
    org_rows = ""
    for org, o in sorted(stats["orgs"].items(), key=lambda kv: -len(kv[1]["devices"])):
        avg = round(sum(o["latest_scores"]) / len(o["latest_scores"])) if o["latest_scores"] else 0
        org_rows += (
            f'<tr><td>{_esc(org)}</td><td class="num">{len(o["devices"])}</td>'
            f'<td class="num">{o["scans"]}</td>'
            f'<td class="num" style="color:{_ring_color(avg)}">{avg}</td></tr>'
        )

    # Fleet failure rows
    n = stats["n_devices"] or 1
    fail_rows = ""
    for e in stats["fail_counts"][:25]:
        pct = round(e["count"] / n * 100)
        fail_rows += (
            f'<tr><td><span class="sev sev-{_esc(e["severity"])}">{_esc(e["severity"])}</span></td>'
            f'<td>{_esc(e["title"])}</td><td class="mono dim">{_esc(e["os"])}</td>'
            f'<td class="num">{e["count"]}</td>'
            f'<td class="num"><div class="bar"><i style="width:{pct}%"></i></div>{pct}%</td></tr>'
        )
    if not fail_rows:
        fail_rows = '<tr><td colspan="5" class="dim">No failing checks across the fleet.</td></tr>'

    # Per-device rows
    dev_rows = ""
    for pid, rec in sorted(stats["devices"].items(), key=lambda kv: kv[1]["latest"]["ts"], reverse=True):
        scores = [s["score"] for s in rec["scans"]]
        latest = rec["latest"]
        nfail = sum(1 for f in latest["fails"])
        dev_rows += (
            f'<tr><td class="mono">{_esc(pid[:12])}…</td><td>{_esc(rec["org"])}</td>'
            f'<td class="mono dim">{_esc(rec["os"])}</td>'
            f'<td class="num" style="color:{_ring_color(latest["score"])}">{latest["score"]}</td>'
            f'<td>{_sparkline(scores)}</td>'
            f'<td class="num">{nfail}</td>'
            f'<td class="mono dim">{_esc(_fmt_date(latest["iso"], latest["ts"]))}</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ComputerCheck · C-LAB ingest dashboard</title>
<style>
  :root{{--bg:#0b0f12;--bg2:#12181d;--line:#222b33;--fg:#e8edf1;--fg2:#cdd5dd;--dim:#6b7785;--accent:#5be3c3}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,Segoe UI,system-ui,sans-serif;padding:32px;line-height:1.5}}
  .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
  .dim{{color:var(--dim)}}
  h1{{font-size:22px;letter-spacing:-.02em;margin:0 0 2px}}
  .sub{{color:var(--dim);font-family:ui-monospace,monospace;font-size:12px;margin-bottom:24px}}
  .wrap{{max-width:1080px;margin:0 auto}}
  .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px}}
  .kpi{{border:1px solid var(--line);border-radius:10px;background:var(--bg2);padding:16px;text-align:center}}
  .kpi-v{{font-family:ui-monospace,monospace;font-weight:600;font-size:30px;line-height:1}}
  .kpi-l{{font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);margin-top:8px}}
  h2{{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);border-bottom:1px solid var(--line);padding-bottom:8px;margin:32px 0 12px;font-family:ui-monospace,monospace}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th{{text-align:left;font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);padding:8px 10px;border-bottom:1px solid var(--line)}}
  td{{padding:9px 10px;border-bottom:1px solid #1a2127;vertical-align:middle}}
  td.num{{text-align:right;font-family:ui-monospace,monospace}}
  .sev{{font-family:ui-monospace,monospace;font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid currentColor}}
  .sev-CRITICAL{{color:#e3735b}}.sev-HIGH{{color:#e08a4a}}.sev-MEDIUM{{color:#e3c45b}}.sev-LOW,.sev-INFO{{color:#8893a0}}
  .bar{{display:inline-block;width:80px;height:6px;background:#1b2227;border-radius:3px;overflow:hidden;vertical-align:middle;margin-right:8px}}
  .bar i{{display:block;height:100%;background:var(--accent)}}
  .note{{color:var(--dim);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}}
</style></head>
<body><div class="wrap">
  <h1>ComputerCheck · C-LAB ingest</h1>
  <div class="sub">Generated {_esc(generated_iso)} · org codes + device pseudonyms only, no identities · evidence omitted</div>

  <div class="kpis">{kpis}</div>

  <h2>Organizations</h2>
  <table><thead><tr><th>Org code</th><th class="num">Devices</th><th class="num">Scans</th><th class="num">Avg latest score</th></tr></thead>
  <tbody>{org_rows}</tbody></table>

  <h2>Most common failing checks (latest scan per device)</h2>
  <table><thead><tr><th>Severity</th><th>Check</th><th>OS</th><th class="num">Devices</th><th class="num">% of fleet</th></tr></thead>
  <tbody>{fail_rows}</tbody></table>

  <h2>Devices</h2>
  <table><thead><tr><th>Pseudonym</th><th>Org</th><th>OS</th><th class="num">Latest</th><th>Trend</th><th class="num">Open fails</th><th>Last scan</th></tr></thead>
  <tbody>{dev_rows}</tbody></table>

  <div class="note">ComputerCheck ingest · IoC/spyware findings arrive via the separate urgent channel and are handled out-of-band, not aggregated here.</div>
</div></body></html>
"""


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cc_ingest", description="Decrypt + aggregate ComputerCheck exports.")
    ap.add_argument("--in", dest="in_dir", required=True, help="Folder of .age and/or .json exports.")
    ap.add_argument("--identity", default="", help="age private key file (needed for .age).")
    ap.add_argument("--out", default="dashboard.html", help="Output HTML path.")
    ap.add_argument("--keep-json", default="", help="Optional folder to write decrypted .json copies.")
    args = ap.parse_args(argv)

    in_dir = Path(args.in_dir).expanduser()
    if not in_dir.is_dir():
        print(f"--in not a folder: {in_dir}", file=sys.stderr)
        return 2
    identity = Path(args.identity).expanduser() if args.identity else None
    keep = Path(args.keep_json).expanduser() if args.keep_json else None

    payloads = load_payloads(in_dir, identity, keep)
    if not payloads:
        print("No valid payloads found.", file=sys.stderr)
        return 1

    stats = aggregate(payloads)
    out = Path(args.out).expanduser()
    out.write_text(render_html(stats, time.strftime("%Y-%m-%d %H:%M")), encoding="utf-8")
    print(f"[ingest] {len(payloads)} payloads · {stats['n_devices']} devices · "
          f"{stats['n_orgs']} orgs → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
