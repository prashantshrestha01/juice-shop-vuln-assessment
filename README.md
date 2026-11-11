# juice-shop-vuln-assessment

A local-lab OWASP Top 10 checklist and findings-report generator for OWASP Juice Shop.

## ⚠️ Scope warning — local lab only

**This tool never scans, probes, or attacks any host. It sends no HTTP requests,
no payloads, and no exploits anywhere.** It only renders a readable Markdown
report from findings *you* record by hand while testing your own local Juice Shop
instance on your own machine.

Never use this checklist or this tool against a real or third-party site. If the
target is not your own local lab, stop. The same warning appears in the CLI help
(`python3 report_generator.py --help`) and at the top of every generated report.

## What it does

- **OWASP Top 10 checklist** (`checklist.md`, machine-readable `checklist.json`):
  all ten 2021 categories (A01 Broken Access Control through A10 SSRF), each with
  test ideas to try in the local lab and evidence fields to fill in
  (steps, observed result, severity, status).
- **Report generator** (`report_generator.py`): takes a findings file — JSON, or
  a small YAML-lite subset (a list of scalar mappings, no external library needed)
  — validates it, counts findings by severity (Critical / High / Medium / Low /
  Info), sorts Critical-first, attaches a generic remediation note per OWASP
  category, and writes a Markdown report.
- **Validation, not silent guessing:** a findings file missing `title`,
  `category`, or `severity`, using an unknown severity, or containing malformed
  JSON is rejected with a clear error instead of producing a half-empty report.

## How to run it

No installation needed — Python 3 standard library only.

```bash
# 1. Print the checklist
python3 report_generator.py --list-checklist

# 2. Generate a report from the sample findings (fictional local-lab data)
python3 report_generator.py sample_findings.json -o sample_report.md

# 3. Or print the report to stdout
python3 report_generator.py sample_findings.json

# 4. YAML-lite also works
python3 report_generator.py sample_findings.yaml -o yaml_report.md
```

A findings file is a list of objects (or `{"findings": [...], ...}`), each with:

```json
{
  "id": "JS-001",
  "title": "Reflected input in local product search",
  "category": "A03:2021-Injection",
  "severity": "High",
  "description": "What was observed, in your own words.",
  "evidence": "Steps to reproduce in the local lab; redact anything sensitive.",
  "remediation": "Optional override; otherwise the built-in category note is used."
}
```

Severity is case-insensitive (`high`, `HIGH`, and `High` all work) and is
normalised in the report. An `id` is auto-assigned (`F-001`, …) when omitted.

The sample report in this repo (`sample_report.md`) was generated from
`sample_findings.json` with:

```bash
python3 report_generator.py sample_findings.json -o sample_report.md --date 2026-10-30
```

It contains 4 fictional findings: 1 Critical, 1 High, 1 Medium, 1 Low, 0 Info.

## Running Juice Shop locally via Docker

These steps run Juice Shop only on your own machine. They are the standard
upstream local setup — check the official Juice Shop docs for the current image
tag if this ever drifts.

```bash
# Pull and run the official image locally (port 3000 on your machine only)
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop

# Then open http://localhost:3000 in your browser.
# Stop it with Ctrl+C in the terminal running the container.
```

Tips from building this project:

- Keep the lab disposable: `docker run --rm` means stopping the container
  throws the instance away, so local test accounts and data never leak anywhere.
- Record findings as you go, not from memory at the end — the evidence field in
  the findings file is where the reproduction steps belong, while they are fresh.
- A report with zero findings does not mean "secure"; the generator says so
  explicitly in that case. It only means nothing was recorded.

## Dependencies

`requirements.txt` lists **no runtime dependencies** — the tool is standard
library only (`argparse`, `json`, `collections`, `pathlib`), so it runs anywhere
Python 3 is installed. The test suite likewise uses stdlib `unittest`, not pytest.
PyYAML is deliberately *not* required: the YAML-lite subset (simple scalar
mappings) is parsed by a small built-in parser, and JSON is recommended for
anything richer. That is the whole justification: fewer dependencies, fewer
surprises, and nothing to install before a reviewer can run it.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

17 tests, all passing at last run: severity counting (including zero counts and
totals), report generation (counts, titles, Critical-first ordering, remediation
notes, empty-report wording, severity normalisation, all-ten checklist coverage),
and rejection/validation of malformed findings (missing title/severity, invalid
severity, non-object findings, non-list input, missing `findings` key, malformed
JSON, plus YAML-lite parsing).

## What was learned

- Building the report around a strict validator changed the tool's character:
  rejecting bad input loudly is more useful than rendering a confident-looking
  report from a typo'd severity.
- The checklist is the real product, not the renderer. A renderer can format any
  list; a good checklist decides what gets tested, what evidence counts, and
  what "done" means per category — so the evidence fields are per-category, not
  generic.
- Keeping the scope boundary in three places (README, CLI help/epilog, and every
  generated report header) matters for a security tool: the warning has to travel
  with the output, not just live on the front page.
- Stdlib-only was the right call here. The feature set (parse, validate, count,
  render Markdown) needs nothing else, and it keeps the setup story to one line:
  have Python 3, run the script.

## Project layout

```
report_generator.py    CLI + validation + Markdown rendering (stdlib only)
checklist.md           Human-readable OWASP Top 10 checklist
checklist.json         Machine-readable checklist (also via --list-checklist)
sample_findings.json   Fictional local-lab findings (run it immediately)
sample_findings.yaml   Same idea in YAML-lite form
sample_report.md       Report generated from sample_findings.json
tests/                 unittest suite (17 tests)
requirements.txt       No runtime dependencies (see above)
```

No real personal data, no secrets, and no credentials appear anywhere in this
project. Sample findings are fictional and describe only a local Docker lab.

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/prashant-me/)*
