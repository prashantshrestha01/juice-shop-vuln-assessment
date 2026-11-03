# Juice Shop Vulnerability Assessment Report

> **Scope warning:** LOCAL LAB ONLY: This tool never scans, probes, or attacks any host. It only renders reports from findings you recorded in your own local Juice Shop instance. Never use it against a real or third-party site.

- **Target:** Local OWASP Juice Shop (localhost lab)
- **Date:** 2026-10-30
- **Total findings:** 4

## Severity summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |
| **Total** | **4** |

## Findings

### JS-002: Fictional example: another user's basket accessible by ID change

- **Severity:** Critical
- **Category:** A01:2021-Broken Access Control

Fictional local-lab observation: changing the basket ID in a request returned a different local test account's basket.

**Evidence / reproduction (local lab only):** In the local Docker lab only: logged in as local test user A, changed the basket ID to user B's, and saw B's items. Both accounts are local test accounts.

**Remediation:** Enforce access control server-side on every request; deny by default; test object-level and function-level checks.

### JS-001: Fictional example: reflected input in local product search

- **Severity:** High
- **Category:** A03:2021-Injection

Fictional local-lab observation: search input was reflected in the results page without encoding in the local instance.

**Evidence / reproduction (local lab only):** In the local Docker lab only: searched for a test string containing markup characters and observed it rendered in the results page. No real site involved.

**Remediation:** Use parameterised queries / safe APIs; validate and encode all untrusted input; never build queries or commands from raw input.

### JS-004: Fictional example: failed logins produce no visible log entry

- **Severity:** Medium
- **Category:** A09:2021-Security Logging and Monitoring Failures

Fictional local-lab observation: repeated failed local logins produced no security log entry visible in the local setup.

**Evidence / reproduction (local lab only):** In the local Docker lab only: attempted several failed logins with a local test account and checked the local logs.

**Remediation:** Log security-relevant events centrally; monitor and alert on them; protect logs from tampering; define an incident response path.

### JS-003: Fictional example: verbose error page on local login

- **Severity:** Low
- **Category:** A05:2021-Security Misconfiguration

Fictional local-lab observation: a malformed local login request returned a verbose error page with stack details.

**Evidence / reproduction (local lab only):** In the local Docker lab only: submitted a malformed login form and recorded the verbose error response. Details redacted.

**Remediation:** Harden defaults; disable unused features; keep error messages generic; review headers, CORS, and debug settings.

## Notes

Findings above are only as good as the manual testing behind them. Re-test after each fix in the same local lab before closing a finding, and keep raw evidence (screenshots, redacted notes) alongside this report.
