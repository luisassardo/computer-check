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
    """Walk the inbox recursively (so you can dump files anywhere under it) and
    dedupe by (device_pseudonym, scan_id) — so a scan submitted twice, or an OS
    `…(1).age` duplicate, is counted once. Genuine rescans of a device keep their
    own scan_id and remain as the time series. Filenames are otherwise ignored;
    aggregation keys on the payload contents.
    """
    payloads: list[dict] = []
    seen: set[tuple[str, str]] = set()
    dupes = 0
    for f in sorted(in_dir.rglob("*")):
        if not f.is_file() or f.suffix not in (".age", ".json"):
            continue
        try:
            raw = decrypt_age(f, identity) if f.suffix == ".age" else f.read_bytes()
            data = json.loads(raw)
        except Exception as e:
            print(f"[ingest] skipped {f.name}: {e}", file=sys.stderr)
            continue
        if not data.get("schema", "").startswith("securityscan.findings/"):
            print(f"[ingest] skipped {f.name}: not a findings payload", file=sys.stderr)
            continue
        s = data.get("scan", {})
        key = (s.get("device_pseudonym") or "?", s.get("id") or "?")
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        payloads.append(data)
        if keep_json and f.suffix == ".age":
            keep_json.mkdir(parents=True, exist_ok=True)
            name = f"{(s.get('device_pseudonym') or 'device')[:8]}-{s.get('id') or 'scan'}.json"
            (keep_json / name).write_bytes(raw)
    if dupes:
        print(f"[ingest] skipped {dupes} duplicate scan(s) (same device + scan id)", file=sys.stderr)
    return payloads


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

# Vector-ID prefixes -> human attack-surface names (Luis's Marco de Seguridad).
VECTOR_SURFACE = {
    "F": "Physical access", "N": "Network", "W": "Web / browser",
    "E": "Email / messaging", "M": "Malware / persistence", "O": "OS / kernel",
    "A": "Auth / credentials", "C": "Cloud / supply chain", "H": "Firmware / hardware",
}


def _month_key(ts: float, iso: str) -> str:
    try:
        t = time.localtime(ts) if ts else time.strptime(iso[:7], "%Y-%m")
        return time.strftime("%Y-%m", t)
    except Exception:
        return (iso or "")[:7] or "?"


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

    # --- failure patterns, counted once per device on its latest scan ---
    # Sets of device-pseudonyms auto-dedupe, so each device counts once per key.
    check_meta: dict[str, dict] = {}          # id -> {title, severity, category}
    fleet_check: dict[str, set] = {}          # id -> {pids failing}
    org_check: dict[str, dict] = {}           # org -> id -> {pids}
    cat_devices: dict[str, set] = {}          # category -> {pids with >=1 fail there}
    surface_devices: dict[str, set] = {}      # attack-surface -> {pids}
    org_surface: dict[str, dict] = {}         # org -> surface -> {pids}
    sev_devices: dict[str, set] = {s: set() for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    for pid, rec in devices.items():
        org = rec["org"]
        for f in rec["latest"]["fails"]:
            fid = f.get("id", ""); sev = f.get("severity", "INFO"); cat = f.get("category", "?")
            check_meta.setdefault(fid, {"title": f.get("title", ""), "severity": sev, "category": cat})
            fleet_check.setdefault(fid, set()).add(pid)
            org_check.setdefault(org, {}).setdefault(fid, set()).add(pid)
            cat_devices.setdefault(cat, set()).add(pid)
            sev_devices.setdefault(sev, set()).add(pid)
            for vid in (f.get("vector_ids") or []):
                surf = VECTOR_SURFACE.get(str(vid)[:1], "Other")
                surface_devices.setdefault(surf, set()).add(pid)
                org_surface.setdefault(org, {}).setdefault(surf, set()).add(pid)

    # --- per-organization profiles ---
    orgs: dict[str, dict] = {}
    for pid, rec in devices.items():
        o = orgs.setdefault(rec["org"], {"pids": [], "scores": [], "os": {}, "month_scores": {}})
        o["pids"].append(pid)
        o["scores"].append(rec["latest"]["score"])
        o["os"][rec["os"]] = o["os"].get(rec["os"], 0) + 1
        for sc in rec["scans"]:
            o["month_scores"].setdefault(_month_key(sc["ts"], sc["iso"]), []).append(sc["score"])
    for org, o in orgs.items():
        o["n_devices"] = len(o["pids"])
        o["n_scans"] = sum(len(devices[p]["scans"]) for p in o["pids"])
        o["avg"] = round(sum(o["scores"]) / len(o["scores"])) if o["scores"] else 0
        o["trend"] = [round(sum(v) / len(v)) for _, v in sorted(o["month_scores"].items())]
        ocs = org_check.get(org, {})
        top = sorted(ocs.items(), key=lambda kv: -len(kv[1]))
        o["top_check"] = (check_meta[top[0][0]]["title"], len(top[0][1])) if top else ("", 0)

    n_devices = len(devices)
    nd = n_devices or 1

    fleet_fail = sorted(
        ({"id": fid, "title": check_meta[fid]["title"], "severity": check_meta[fid]["severity"],
          "category": check_meta[fid]["category"], "count": len(pids)}
         for fid, pids in fleet_check.items()),
        key=lambda e: (-e["count"], e["title"]),
    )
    cat_weak = sorted(((c, len(s)) for c, s in cat_devices.items()), key=lambda kv: -kv[1])
    surf_weak = sorted(((s, len(p)) for s, p in surface_devices.items()), key=lambda kv: -kv[1])

    # fleet score trend (all scans binned by month)
    fleet_month: dict[str, list] = {}
    for rec in devices.values():
        for sc in rec["scans"]:
            fleet_month.setdefault(_month_key(sc["ts"], sc["iso"]), []).append(sc["score"])
    fleet_trend = [(m, round(sum(v) / len(v)), len(v)) for m, v in sorted(fleet_month.items())]

    # org x top-check matrix (% of each org's devices failing each top check)
    heat_checks = fleet_fail[:8]
    heat = {}  # org -> [pct per heat_check]
    for org, o in orgs.items():
        ocs = org_check.get(org, {})
        heat[org] = [round(len(ocs.get(c["id"], set())) / (o["n_devices"] or 1) * 100) for c in heat_checks]

    # --- auto-insights ---
    insights: list[str] = []
    if fleet_fail:
        e = fleet_fail[0]
        insights.append(f"{round(e['count'] / nd * 100)}% of all devices fail “{e['title']}” — the most common issue fleet-wide.")
    if cat_weak:
        c, cnt = cat_weak[0]
        insights.append(f"{round(cnt / nd * 100)}% of devices have at least one issue in {c}.")
    n_crit = len(sev_devices["CRITICAL"])
    if n_crit:
        insights.append(f"{n_crit} device(s) ({round(n_crit / nd * 100)}%) have at least one CRITICAL issue.")
    weak_orgs = [org for org, o in orgs.items() if o["avg"] < 55]
    if weak_orgs:
        insights.append(f"{len(weak_orgs)} of {len(orgs)} organization(s) average below 55 and need attention: {', '.join(sorted(weak_orgs))}.")
    combos = []
    for org, ocs in org_check.items():
        ndo = orgs[org]["n_devices"]
        if ndo < 2:
            continue
        for fid, pids in ocs.items():
            pct = len(pids) / ndo
            if pct >= 0.6:
                combos.append((pct, org, check_meta[fid]["title"]))
    for pct, org, title in sorted(combos, reverse=True)[:3]:
        insights.append(f"{org}: {round(pct * 100)}% of devices fail “{title}” (a cluster worth a targeted fix).")

    return {
        "devices": devices,
        "orgs": orgs,
        "org_check": {o: {f: len(p) for f, p in d.items()} for o, d in org_check.items()},
        "fleet_fail": fleet_fail,
        "cat_weak": cat_weak,
        "surf_weak": surf_weak,
        "fleet_trend": fleet_trend,
        "heat_checks": heat_checks,
        "heat": heat,
        "insights": insights,
        "sev_devices": {k: len(v) for k, v in sev_devices.items()},
        "n_devices": n_devices,
        "n_orgs": len(orgs),
        "n_scans": sum(len(r["scans"]) for r in devices.values()),
        "avg_latest": round(sum(r["latest"]["score"] for r in devices.values()) / nd) if n_devices else 0,
        "n_crit_devices": n_crit,
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


def _line_svg(points: list[tuple], w: int = 580, h: int = 130) -> str:
    """points = [(label, value), ...] with value in 0..100."""
    if len(points) < 2:
        return ""
    padL, padR, padT, padB = 26, 10, 12, 20
    iw, ih = w - padL - padR, h - padT - padB
    n = len(points)
    xs = lambda i: padL + i / (n - 1) * iw
    ys = lambda v: padT + ih - (v / 100) * ih
    pts = [(xs(i), ys(v)) for i, (_, v) in enumerate(points)]
    line = " ".join(("M" if i == 0 else "L") + f"{x:.1f} {y:.1f}" for i, (x, y) in enumerate(pts))
    area = f"M{xs(0):.1f} {ys(0):.1f} " + " ".join(f"L{x:.1f} {y:.1f}" for x, y in pts) + f" L{xs(n-1):.1f} {ys(0):.1f} Z"
    grid = "".join(
        f'<line x1="{padL}" y1="{ys(g):.1f}" x2="{w-padR}" y2="{ys(g):.1f}" stroke="#1a2127"/>'
        f'<text x="{padL-5}" y="{ys(g)+3:.1f}" fill="#6b7785" font-size="9" text-anchor="end" font-family="monospace">{g}</text>'
        for g in (0, 50, 100))
    dots = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{_ring_color(points[i][1])}"/>' for i, (x, y) in enumerate(pts))
    labels = "".join(
        f'<text x="{xs(i):.1f}" y="{h-6}" fill="#6b7785" font-size="9" text-anchor="middle" font-family="monospace">{_esc(points[i][0])}</text>'
        for i in range(n) if n <= 14 or i % max(1, n // 12) == 0)
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" style="max-width:{w}px">'
            f'<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="#5be3c3" stop-opacity=".28"/><stop offset="1" stop-color="#5be3c3" stop-opacity="0"/></linearGradient></defs>'
            f'{grid}<path d="{area}" fill="url(#g)"/><path d="{line}" fill="none" stroke="#5be3c3" stroke-width="2"/>{dots}{labels}</svg>')


def _heat_bg(pct: int) -> str:
    return f"rgba(227,115,91,{pct / 100 * 0.82:.2f})" if pct else "transparent"


def render_html(stats: dict, generated_iso: str) -> str:
    nd = stats["n_devices"] or 1
    kpi = lambda v, l, c="#5be3c3": (
        f'<div class="kpi"><div class="kpi-v" style="color:{c}">{_esc(v)}</div>'
        f'<div class="kpi-l">{_esc(l)}</div></div>'
    )
    crit_pct = round(stats["n_crit_devices"] / nd * 100)
    kpis = (
        kpi(stats["n_devices"], "Devices")
        + kpi(stats["n_orgs"], "Organizations")
        + kpi(stats["n_scans"], "Scans")
        + kpi(stats["avg_latest"], "Avg score", _ring_color(stats["avg_latest"]))
        + kpi(f"{crit_pct}%", "Devices w/ critical", "#e3735b" if crit_pct else "#5be3c3")
    )

    insights = "".join(f"<li>{_esc(t)}</li>" for t in stats["insights"]) or "<li class='dim'>Not enough data yet for insights.</li>"

    trend = ""
    if len(stats["fleet_trend"]) >= 2:
        pts = [(m[5:], avg) for m, avg, _ in stats["fleet_trend"]]
        trend = f'<h2>Fleet score over time</h2><div class="card">{_line_svg(pts)}</div>'

    # weakest attack-surfaces + categories (horizontal bars)
    def bars(items):
        out = ""
        for label, cnt in items[:8]:
            pct = round(cnt / nd * 100)
            out += (f'<div class="hbar"><span class="hl">{_esc(label)}</span>'
                    f'<span class="ht"><i style="width:{pct}%"></i></span>'
                    f'<span class="hp">{pct}%</span></div>')
        return out or '<div class="dim">None.</div>'
    surf_bars = bars(stats["surf_weak"])
    cat_bars = bars(stats["cat_weak"])

    # organization cards
    cards = ""
    for org, o in sorted(stats["orgs"].items(), key=lambda kv: (kv[1]["avg"], -kv[1]["n_devices"])):
        osmix = " · ".join(f"{_esc(k)} {v}" for k, v in sorted(o["os"].items(), key=lambda kv: -kv[1]))
        tc, tcn = o["top_check"]
        topline = (f'<div class="cardtop dim">Top issue: <b style="color:#e08a4a">{_esc(tc)}</b> '
                   f'({tcn}/{o["n_devices"]})</div>') if tc else ""
        cards += (
            f'<div class="orgcard"><div class="oc-head"><span class="oc-name">{_esc(org)}</span>'
            f'<span class="oc-score" style="color:{_ring_color(o["avg"])}">{o["avg"]}</span></div>'
            f'<div class="oc-meta mono dim">{o["n_devices"]} device(s) · {o["n_scans"]} scan(s) · {osmix}</div>'
            f'<div class="oc-spark">{_sparkline(o["trend"]) if len(o["trend"])>1 else ""}</div>'
            f'{topline}</div>'
        )

    # org x top-check heatmap
    hc = stats["heat_checks"]
    if hc:
        head = "".join(
            f'<th class="hcol" title="{_esc(c["title"])} ({_esc(c["severity"])})">'
            f'<span class="sev sev-{_esc(c["severity"])}">{i+1}</span></th>'
            for i, c in enumerate(hc))
        rows = ""
        for org, o in sorted(stats["orgs"].items(), key=lambda kv: -kv[1]["n_devices"]):
            cells = "".join(
                f'<td class="heat" style="background:{_heat_bg(p)}">{(str(p)+"%") if p else "·"}</td>'
                for p in stats["heat"].get(org, []))
            rows += f'<tr><td class="hname">{_esc(org)}</td>{cells}</tr>'
        legend = "".join(f'<li><b>{i+1}.</b> {_esc(c["title"])} '
                         f'<span class="sev sev-{_esc(c["severity"])}">{_esc(c["severity"])}</span></li>'
                         for i, c in enumerate(hc))
        heatmap = (f'<h2>Where each organization is failing (% of org’s devices)</h2>'
                   f'<table class="heatmap"><thead><tr><th>Organization</th>{head}</tr></thead>'
                   f'<tbody>{rows}</tbody></table><ol class="legend">{legend}</ol>')
    else:
        heatmap = ""

    # fleet failing-check table
    fail_rows = ""
    for e in stats["fleet_fail"][:25]:
        pct = round(e["count"] / nd * 100)
        fail_rows += (
            f'<tr><td><span class="sev sev-{_esc(e["severity"])}">{_esc(e["severity"])}</span></td>'
            f'<td>{_esc(e["title"])}</td><td class="mono dim">{_esc(e["category"])}</td>'
            f'<td class="num">{e["count"]}</td>'
            f'<td class="num"><div class="bar"><i style="width:{pct}%"></i></div>{pct}%</td></tr>'
        )
    if not fail_rows:
        fail_rows = '<tr><td colspan="5" class="dim">No failing checks across the fleet.</td></tr>'

    # per-device table
    dev_rows = ""
    for pid, rec in sorted(stats["devices"].items(), key=lambda kv: kv[1]["latest"]["ts"], reverse=True):
        scores = [s["score"] for s in rec["scans"]]
        latest = rec["latest"]
        dev_rows += (
            f'<tr><td class="mono">{_esc(pid[:12])}…</td><td>{_esc(rec["org"])}</td>'
            f'<td class="mono dim">{_esc(rec["os"])}</td>'
            f'<td class="num" style="color:{_ring_color(latest["score"])}">{latest["score"]}</td>'
            f'<td>{_sparkline(scores)}</td>'
            f'<td class="num">{len(latest["fails"])}</td>'
            f'<td class="mono dim">{_esc(_fmt_date(latest["iso"], latest["ts"]))}</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ComputerCheck · C-LAB ingest dashboard</title>
<style>
  :root{{--bg:#0b0f12;--bg2:#12181d;--line:#222b33;--fg:#e8edf1;--fg2:#cdd5dd;--dim:#6b7785;--accent:#5be3c3}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,Segoe UI,system-ui,sans-serif;padding:32px;line-height:1.5}}
  .mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}} .dim{{color:var(--dim)}}
  h1{{font-size:22px;letter-spacing:-.02em;margin:0 0 2px}}
  .sub{{color:var(--dim);font-family:ui-monospace,monospace;font-size:12px;margin-bottom:24px}}
  .wrap{{max-width:1100px;margin:0 auto}}
  .kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:8px}}
  .kpi{{border:1px solid var(--line);border-radius:10px;background:var(--bg2);padding:16px;text-align:center}}
  .kpi-v{{font-family:ui-monospace,monospace;font-weight:600;font-size:28px;line-height:1}}
  .kpi-l{{font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);margin-top:8px}}
  h2{{font-size:13px;letter-spacing:.1em;text-transform:uppercase;color:var(--dim);border-bottom:1px solid var(--line);padding-bottom:8px;margin:32px 0 12px;font-family:ui-monospace,monospace}}
  .card{{border:1px solid var(--line);border-radius:10px;background:var(--bg2);padding:16px}}
  .insights{{margin:0;padding:0;list-style:none;display:grid;gap:9px}}
  .insights li{{display:flex;gap:10px;font-size:14px;line-height:1.45;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;background:var(--bg2);padding:11px 14px}}
  .insights li::before{{content:"▸";color:var(--accent)}}
  .two{{display:grid;grid-template-columns:1fr 1fr;gap:16px}} @media(max-width:760px){{.two{{grid-template-columns:1fr}}}}
  .hbar{{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}}
  .hbar .hl{{flex:0 0 150px;color:var(--fg2)}} .hbar .hp{{flex:0 0 38px;text-align:right;font-family:monospace;font-size:12px;color:var(--dim)}}
  .hbar .ht{{flex:1;height:8px;background:#1b2227;border-radius:4px;overflow:hidden}} .hbar .ht i{{display:block;height:100%;background:linear-gradient(90deg,#5be3c3,#e3c45b)}}
  .orgs{{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:14px}}
  .orgcard{{border:1px solid var(--line);border-radius:10px;background:var(--bg2);padding:15px}}
  .oc-head{{display:flex;align-items:baseline;justify-content:space-between}}
  .oc-name{{font-weight:600;font-size:15px}} .oc-score{{font-family:monospace;font-weight:600;font-size:24px}}
  .oc-meta{{margin:4px 0 8px}} .oc-spark{{min-height:28px}} .cardtop{{font-size:12px;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th{{text-align:left;font-family:ui-monospace,monospace;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);padding:8px 10px;border-bottom:1px solid var(--line)}}
  td{{padding:9px 10px;border-bottom:1px solid #1a2127;vertical-align:middle}} td.num{{text-align:right;font-family:ui-monospace,monospace}}
  .sev{{font-family:ui-monospace,monospace;font-size:10px;padding:2px 7px;border-radius:3px;border:1px solid currentColor}}
  .sev-CRITICAL{{color:#e3735b}}.sev-HIGH{{color:#e08a4a}}.sev-MEDIUM{{color:#e3c45b}}.sev-LOW,.sev-INFO{{color:#8893a0}}
  .bar{{display:inline-block;width:80px;height:6px;background:#1b2227;border-radius:3px;overflow:hidden;vertical-align:middle;margin-right:8px}} .bar i{{display:block;height:100%;background:var(--accent)}}
  .heatmap th.hcol{{text-align:center;width:46px}} .heatmap td.heat{{text-align:center;font-family:monospace;font-size:11px;border:1px solid #11171b}}
  .heatmap td.hname{{font-size:13px}} .legend{{font-size:12px;color:var(--fg2);margin:10px 0 0;padding-left:18px;columns:2;gap:18px}} .legend li{{margin:3px 0}}
  .note{{color:var(--dim);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:14px}}
</style></head>
<body><div class="wrap">
  <h1>ComputerCheck · C-LAB ingest</h1>
  <div class="sub">Generated {_esc(generated_iso)} · org codes + device pseudonyms only, no identities · evidence omitted</div>

  <div class="kpis">{kpis}</div>

  <h2>What stands out</h2>
  <ul class="insights">{insights}</ul>

  {trend}

  <h2>Where the fleet is weakest</h2>
  <div class="two">
    <div class="card"><div class="dim mono" style="margin-bottom:10px">BY ATTACK SURFACE · % of devices affected</div>{surf_bars}</div>
    <div class="card"><div class="dim mono" style="margin-bottom:10px">BY CATEGORY · % of devices affected</div>{cat_bars}</div>
  </div>

  <h2>Organizations</h2>
  <div class="orgs">{cards}</div>

  {heatmap}

  <h2>Most common failing checks (latest scan per device)</h2>
  <table><thead><tr><th>Severity</th><th>Check</th><th>Category</th><th class="num">Devices</th><th class="num">% of fleet</th></tr></thead>
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
