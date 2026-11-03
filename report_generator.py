#!/usr/bin/env python3
"""OWASP Juice Shop vulnerability-assessment report generator.

LOCAL LAB ONLY -- SCOPE WARNING:
    This tool does NOT scan, probe, or attack any host. It does NOT send
    HTTP requests, payloads, or exploits anywhere. It only renders a
    readable Markdown report from findings *you* recorded by hand while
    testing your own local OWASP Juice Shop instance (e.g. http://localhost:3000
    via Docker on your own machine).

    Never point this tool, or the checklist it ships with, at a real or
    third-party site. If a target is not your own local lab, stop.

Usage:
    python3 report_generator.py findings.json -o report.md
    python3 report_generator.py findings.json --checklist
    python3 report_generator.py --list-checklist

Findings format (JSON):
    [
      {
        "id": "JS-001",
        "title": "Reflected XSS in product search",
        "category": "A03:2021-Injection",
        "severity": "High",
        "description": "What was observed, in your own words.",
        "evidence": "Steps to reproduce in the local lab; no real credentials.",
        "remediation": "Optional override; otherwise the built-in note is used."
      }
    ]
    A top-level object {"findings": [...], "target": "...", "date": "..."}
    is also accepted.

    A YAML-lite file (.yaml / .yml) is also accepted: a simple list of
    mappings with scalar values, e.g.
        - id: JS-001
          title: Example finding
          category: A03:2021-Injection
          severity: High
          description: Observed locally.
    No external YAML library is required for this subset.

Standard library only.
"""

import argparse
import json
import sys
from collections import Counter, OrderedDict
from pathlib import Path

SCOPE_WARNING = (
    "LOCAL LAB ONLY: This tool never scans, probes, or attacks any host. "
    "It only renders reports from findings you recorded in your own local "
    "Juice Shop instance. Never use it against a real or third-party site."
)

VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_ORDER = {name: i for i, name in enumerate(VALID_SEVERITIES)}
REQUIRED_FIELDS = ("title", "category", "severity")

# Generic, public OWASP remediation guidance -- no payloads, no exploit code.
REMEDIATION_NOTES = {
    "A01": "Enforce access control server-side on every request; deny by default; test object-level and function-level checks.",
    "A02": "Use strong, current cryptography; protect data in transit and at rest; never store secrets or sensitive data in plaintext.",
    "A03": "Use parameterised queries / safe APIs; validate and encode all untrusted input; never build queries or commands from raw input.",
    "A04": "Apply secure design patterns and threat modelling early; add limits, quotas, and safe defaults for business-logic flows.",
    "A05": "Harden defaults; disable unused features; keep error messages generic; review headers, CORS, and debug settings.",
    "A06": "Inventory components; patch promptly; remove unused dependencies; monitor advisories for the exact versions in use.",
    "A07": "Use strong, modern authentication; protect sessions; enforce MFA where available; rate-limit login and recovery flows.",
    "A08": "Verify integrity of code, updates, and data; pin dependencies; avoid unsigned or untrusted deserialisation and updates.",
    "A09": "Log security-relevant events centrally; monitor and alert on them; protect logs from tampering; define an incident response path.",
    "A10": "Validate and allow-list outbound URLs server-side; block private/internal ranges; never pass raw user input as a fetch target.",
}


def _normalise_severity(value):
    """Return the canonical severity, or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError(f"severity must be a string, got {type(value).__name__}")
    cleaned = value.strip().capitalize()
    # Handle e.g. "HIGH" -> "High"; "critical" -> "Critical"
    for valid in VALID_SEVERITIES:
        if cleaned.lower() == valid.lower():
            return valid
    raise ValueError(
        f"invalid severity {value!r}; must be one of {', '.join(VALID_SEVERITIES)}"
    )


def _remediation_for(finding):
    if finding.get("remediation"):
        return str(finding["remediation"])
    category = str(finding.get("category", ""))
    prefix = category.split(":")[0].strip()  # e.g. "A03" from "A03:2021-Injection"
    return REMEDIATION_NOTES.get(
        prefix, "Review the relevant OWASP guidance and apply defence in depth."
    )


def validate_findings(data):
    """Validate raw loaded data and return a normalised list of findings.

    Raises ValueError (or TypeError for a wrong top-level type) on any
    malformed input. Normalisation: severity case is canonicalised and
    an ``id`` is auto-assigned (F-001, ...) when missing.
    """
    if isinstance(data, dict):
        if "findings" not in data:
            raise ValueError("object findings file must contain a 'findings' key")
        findings = data["findings"]
    else:
        findings = data
    if not isinstance(findings, list):
        raise TypeError("findings must be a list of objects")
    normalised = []
    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"finding #{i + 1} must be an object, got {type(item).__name__}")
        for field in REQUIRED_FIELDS:
            if field not in item or item[field] in (None, ""):
                raise ValueError(f"finding #{i + 1} is missing required field {field!r}")
        if not isinstance(item["title"], str) or not isinstance(item["category"], str):
            raise ValueError(f"finding #{i + 1}: 'title' and 'category' must be strings")
        clean = dict(item)
        clean["severity"] = _normalise_severity(item["severity"])
        clean.setdefault("id", f"F-{i + 1:03d}")
        clean.setdefault("description", "")
        clean.setdefault("evidence", "")
        normalised.append(clean)
    return normalised


def count_severities(findings):
    """Return an OrderedDict of severity -> count, including zeroes."""
    counts = Counter(f["severity"] for f in findings)
    return OrderedDict((sev, counts.get(sev, 0)) for sev in VALID_SEVERITIES)


def parse_yaml_lite(text):
    """Parse the small YAML subset described in the module docstring.

    Supports a top-level list of mappings with scalar ``key: value`` pairs,
    and an optional ``findings:`` wrapper. Anything more complex raises
    ValueError -- use JSON for richer data.
    """
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        raise ValueError("empty YAML-lite file")
    items = []
    current = None
    in_findings = False
    for raw in lines:
        stripped = raw.strip()
        if stripped == "findings:":
            in_findings = True
            continue
        if stripped.startswith("- "):
            if current is not None:
                items.append(current)
            current = {}
            stripped = stripped[2:].strip()
            if not stripped:
                continue
        if current is None:
            # A stray top-level scalar (e.g. target:/date:) is ignored here;
            # metadata is not required for a report.
            if ":" in stripped and not in_findings:
                continue
            raise ValueError(f"unsupported YAML-lite line: {raw!r}")
        if ":" not in stripped:
            raise ValueError(f"unsupported YAML-lite line: {raw!r}")
        key, _, value = stripped.partition(":")
        value = value.strip().strip('"').strip("'")
        current[key.strip()] = value
    if current is not None:
        items.append(current)
    if not items:
        raise ValueError("no findings parsed from YAML-lite file")
    return items


def load_findings(path):
    """Load and validate a findings file (JSON, or YAML-lite for .yaml/.yml)."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"findings file not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            data = parse_yaml_lite(text)
        except ValueError as exc:
            raise ValueError(f"invalid YAML-lite findings file: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON findings file: {exc}") from exc
    return validate_findings(data)


def generate_markdown(findings, target="Local OWASP Juice Shop (localhost lab)", date=""):
    """Render findings as a Markdown report string."""
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    counts = count_severities(findings)
    total = len(findings)
    lines = []
    lines.append("# Juice Shop Vulnerability Assessment Report")
    lines.append("")
    lines.append(f"> **Scope warning:** {SCOPE_WARNING}")
    lines.append("")
    lines.append(f"- **Target:** {target}")
    if date:
        lines.append(f"- **Date:** {date}")
    lines.append(f"- **Total findings:** {total}")
    lines.append("")
    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in counts.items():
        lines.append(f"| {sev} | {count} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")
    if total == 0:
        lines.append("No findings recorded. This does not mean the lab is secure --")
        lines.append("it only means nothing was recorded in this findings file.")
        lines.append("")
        return "\n".join(lines)
    lines.append("## Findings")
    lines.append("")
    for f in findings:
        lines.append(f"### {f['id']}: {f['title']}")
        lines.append("")
        lines.append(f"- **Severity:** {f['severity']}")
        lines.append(f"- **Category:** {f['category']}")
        if f.get("description"):
            lines.append("")
            lines.append(f['description'])
        if f.get("evidence"):
            lines.append("")
            lines.append(f"**Evidence / reproduction (local lab only):** {f['evidence']}")
        lines.append("")
        lines.append(f"**Remediation:** {_remediation_for(f)}")
        lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "Findings above are only as good as the manual testing behind them. "
        "Re-test after each fix in the same local lab before closing a finding, "
        "and keep raw evidence (screenshots, redacted notes) alongside this report."
    )
    lines.append("")
    return "\n".join(lines)


def load_checklist(path=None):
    """Load checklist.json next to this script (or at an explicit path)."""
    if path is None:
        path = Path(__file__).with_name("checklist.json")
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Render a Markdown report from locally recorded Juice Shop findings.",
        epilog=f"SCOPE WARNING: {SCOPE_WARNING}",
    )
    parser.add_argument("findings", nargs="?", help="Findings file (JSON or YAML-lite)")
    parser.add_argument("-o", "--output", help="Write the Markdown report to this file (default: stdout)")
    parser.add_argument("--target", default="Local OWASP Juice Shop (localhost lab)",
                        help="Target label for the report (local lab only)")
    parser.add_argument("--date", default="", help="Assessment date label, e.g. 2026-10-30")
    parser.add_argument("--list-checklist", action="store_true",
                        help="Print the OWASP Top 10 checklist and exit")
    args = parser.parse_args(argv)

    if args.list_checklist:
        checklist = load_checklist()
        for entry in checklist:
            print(f"{entry['id']} {entry['category']}")
            for idea in entry.get("test_ideas", []):
                print(f"  - {idea}")
        return 0

    if not args.findings:
        parser.error("a findings file is required (or use --list-checklist)")

    try:
        findings = load_findings(args.findings)
    except (ValueError, TypeError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    report = generate_markdown(findings, target=args.target, date=args.date)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Wrote {args.output} ({len(findings)} findings)")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
