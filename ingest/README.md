# ComputerCheck ingest (operator-side)

Turns the `.age` exports users send into a single self-contained HTML dashboard:
per-organization cohorts, per-device score trends (by pseudonym), and the most
common failing checks across the fleet.

**This runs on your machine only and needs the C-LAB PRIVATE age key.** It is not
part of the shipped app, and it should stay offline. The dashboard shows org codes
and device pseudonyms only — never real names — and never renders the `evidence`
field.

## Requirements

- Python 3.
- A decryptor for `.age` files (only needed for encrypted inputs):
  - the `age` CLI (`brew install age`), OR
  - `pip install pyrage`.
- Your C-LAB private key file (the `AGE-SECRET-KEY-...` that matches the public
  key baked into the app's `CLAB_AGE_RECIPIENT`).

## Use

```sh
python3 cc_ingest.py \
  --in ./inbox \
  --identity ~/clab-identity.txt \
  --out dashboard.html
```

- `--in` — a folder of submitted `.age` files (and/or already-decrypted `.json`).
- `--identity` — your age private key file.
- `--out` — the dashboard to write (default `dashboard.html`).
- `--keep-json` — optional folder to also save the decrypted `.json` copies.

Open `dashboard.html` in a browser. Re-run whenever new exports arrive.

## What the dashboard shows

Built for understanding patterns across organizations, not just listing devices:

- **KPIs** — devices, organizations, scans, average score, % of devices with a
  CRITICAL issue.
- **What stands out** — auto-generated insight bullets (the most common fleet
  issue, weakest category, orgs averaging below 55, and per-org failure clusters
  like "BETA: 100% of devices fail Lockdown Mode").
- **Fleet score over time** — average score binned by month across all scans.
- **Where the fleet is weakest** — % of devices affected, broken down by attack
  surface (from the Marco's vector IDs: Web, OS, Malware, Network, …) and by
  category.
- **Organizations** — one card per org (weakest first) with its average score,
  score trend, device count, OS mix, and its single most common issue.
- **Where each organization is failing** — an org × top-check heatmap: each cell
  is the % of that org's devices failing that check, so you can see at a glance
  that different orgs have different failure *profiles*.
- **Most common failing checks** and a **per-device** table round it out.

All of this is computed from the latest scan per device (deduped), counting each
device once. Device pseudonyms and org codes only — no identities; evidence is
never shown. IoC/spyware findings are not aggregated here (they come via the
separate urgent channel).

## Collecting files (manual workflow)

Users send their `.age` file however they choose (Proton, Signal, email). Drop
everything into your `--in` folder — **structure doesn't matter**:

- The tool **recurses** into subfolders, so you can sort by month/org or just
  dump files in. e.g. `inbox/2026-06/`, `inbox/org-a/`, whatever.
- The app names exports `ComputerCheck-<ORG>-<YYYYMMDD>-<pseudonym8>.age`, so
  files from different devices won't collide. If two files still end up with the
  same name (e.g. saved from the same email twice), keep them in separate
  subfolders — the tool reads both.
- **Deduplication** is by `(device pseudonym, scan id)`: the same scan submitted
  twice is counted once; a real rescan of a device keeps its own id and shows up
  in that device's trend. Filenames are never used to identify scans.

## Notes

- Inputs can mix `.age` and `.json`, so you can test the aggregation with plain
  JSON payloads (no key needed) before wiring up real submissions.
- "Most common failing checks" counts each device once, using its latest scan.
- IoC/spyware findings are excluded from routine exports and arrive via the
  separate urgent channel; they are handled out-of-band, not aggregated here.
- Where the database eventually lives (this HTML, SQLite, D1, Airtable) is still
  open — this tool is the simplest first form. See ../PLAN.md.
