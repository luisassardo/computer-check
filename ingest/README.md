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

## Notes

- Inputs can mix `.age` and `.json`, so you can test the aggregation with plain
  JSON payloads (no key needed) before wiring up real submissions.
- "Most common failing checks" counts each device once, using its latest scan.
- IoC/spyware findings are excluded from routine exports and arrive via the
  separate urgent channel; they are handled out-of-band, not aggregated here.
- Where the database eventually lives (this HTML, SQLite, D1, Airtable) is still
  open — this tool is the simplest first form. See ../PLAN.md.
