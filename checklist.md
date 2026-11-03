# OWASP Top 10 Checklist — Local Juice Shop Lab Only

> **Scope warning:** Use this checklist only against your own local OWASP Juice Shop
> instance (Docker on your own machine, e.g. http://localhost:3000). Never test a
> real or third-party site with it. This project contains no scanner, no payloads,
> and no exploitation code — it is a checklist plus a report renderer for findings
> you record by hand.

For each category: run the test ideas in your local lab, fill in the evidence
fields, assign a severity (Critical / High / Medium / Low / Info), and set a
status (Open / In progress / Fixed / Not applicable). Then add the finding to
your findings JSON file and regenerate the report with `report_generator.py`.

The machine-readable version is `checklist.json`; print it any time with:

```bash
python3 report_generator.py --list-checklist
```

## A01:2021 — Broken Access Control
- Test ideas: access another local test user's basket/order as a different logged-in local account; request admin-only pages as a regular local user; change an ID in a request and see if another account's data is returned.
- Evidence fields: steps, accounts used (local test accounts only), expected vs actual result, severity, status.

## A02:2021 — Cryptographic Failures
- Test ideas: check whether the local instance serves plain HTTP and what login/checkout forms submit; look for sensitive data in responses, local storage, or client-side code in the local lab.
- Evidence fields: steps, where data was observed, data type (redacted), severity, status.

## A03:2021 — Injection
- Test ideas: try ordinary special characters in local search/login inputs and observe error handling; check whether input is reflected unsanitised in a page in the local lab; note database/command error messages returned locally.
- Evidence fields: input field, input used, response observed, severity, status.

## A04:2021 — Insecure Design
- Test ideas: walk checkout/password-reset end to end and note missing limits, checks, or confirmations; try skipping or replaying a step in the local lab; check for rate limits on sensitive flows.
- Evidence fields: flow tested, steps, missing control, severity, status.

## A05:2021 — Security Misconfiguration
- Test ideas: review response headers, error pages, and defaults of the local instance; check for debug endpoints, verbose errors, or unused features left enabled.
- Evidence fields: setting/endpoint, observed value (redacted), severity, status.

## A06:2021 — Vulnerable and Outdated Components
- Test ideas: list the local instance's version and client-side libraries as reported by the app; compare against public advisories; note whether the Docker image is current or an old pinned release.
- Evidence fields: component, version observed, advisory reference, severity, status.

## A07:2021 — Identification and Authentication Failures
- Test ideas: test local login for account enumeration via differing errors; check session logout, expiry, and old-token reuse in the local lab; note weak/default local test credentials.
- Evidence fields: flow tested, steps, response observed, severity, status.

## A08:2021 — Software and Data Integrity Failures
- Test ideas: check how the local instance verifies updates/plugins/uploads, if applicable; note whether unsigned or untrusted content can be loaded locally.
- Evidence fields: mechanism tested, steps, observed behaviour, severity, status.

## A09:2021 — Security Logging and Monitoring Failures
- Test ideas: trigger failed logins and suspicious actions locally and check what is logged; check whether logs are viewable, tamper-evident, or alerted on.
- Evidence fields: event triggered, log observed (or absence), severity, status.

## A10:2021 — Server-Side Request Forgery (SSRF)
- Test ideas: find any feature that fetches a URL/image server-side; test it only with local, safe destinations you control; note whether private/internal addresses are blocked.
- Evidence fields: feature tested, destination used (local only), response observed, severity, status.
