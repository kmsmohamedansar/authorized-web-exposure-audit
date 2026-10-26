---
name: authorized-web-exposure-audit
description: Perform an authorized, non-invasive website exposure review of public pages, API documentation, client-side JavaScript, headers, and indexable document references. Use for defensive audits with explicit organizational authorization and an approved scope, or for localhost/deliberately vulnerable labs; never use it to bypass access controls, enumerate private records, or scan an unapproved production target.
---

# Authorized Web Exposure Audit

Use this skill to identify accidental public exposure while minimizing traffic and avoiding access to private data. Treat “publicly reachable” as an observation, not proof that publication was unintended.

## Authorization gate

1. Start with the included localhost fixture unless the user supplies explicit organizational authorization and an approved written scope.
2. For every non-loopback target, require a scope JSON matching [references/scope-format.md](references/scope-format.md). The user must identify the authorizing organization/person, exact hosts and paths, exclusions, validity dates, and limits. A user saying “my company” is not sufficient.
3. If authorization or scope is missing, expired, ambiguous, or inconsistent with the target, do not send network traffic. Offer a dry-run plan or the localhost demo instead.
4. Reconfirm scope immediately before any live run. Do not infer permission for related domains, subdomains, IPs, CDNs, third-party services, or production systems.

## Hard boundaries

- Make unauthenticated `GET` requests only to the seed URL and the small fixed set of public metadata/documentation paths implemented by the helper. It may fetch same-origin JavaScript explicitly referenced by those pages.
- Stay on the exact approved host, port, scheme, and path prefixes. Do not follow an out-of-scope redirect.
- Do not log in, submit forms, mutate state, guess identifiers, fuzz parameters, brute force paths, test credentials/tokens, bypass controls, alter headers to impersonate a user, or exploit a finding.
- Do not fetch discovered API endpoints, document links, sitemap entries, source maps, private-looking URLs, or customer/user records. Report references only.
- Never reproduce suspected secrets. The helper emits only type, location, redacted preview, and a short SHA-256 fingerprint.
- Do not use browser caches, employee sessions, internal credentials, leaked credentials, or privileged network access unless a separately approved engagement explicitly requires them; this skill does not provide that mode.
- Do not upload captured content to third-party services. Keep outputs in the approved local workspace and apply the organization’s retention rules.

## Run workflow

1. Read [references/setup-and-examples.md](references/setup-and-examples.md) for installation, the localhost demonstration, and dry-run commands.
2. For a non-local target, read [references/scope-format.md](references/scope-format.md), inspect the scope file, and compare its exact target to the command.
3. Run `scripts/audit_site.py` with `--dry-run` first. Show the request plan, effective rate, exclusions, and stop conditions to the user.
4. After confirmation, run without `--dry-run`. Defaults are 1 request/second and 30 requests; never exceed the lower of the scope limits or helper hard caps (2 requests/second, 100 requests).
5. Review the JSON and Markdown outputs. Separate verified observations from inference. Do not label a public endpoint reference, permissive header, or token-like string as exploitable without evidence.
6. Use [references/findings-template.md](references/findings-template.md) to refine actionable findings and document false positives, evidence minimization, and remediation.

## Checks and interpretation

- Public API documentation: check only the fixed common documentation paths and links present in retrieved public pages. A `200` response is evidence of public availability, not improper exposure by itself.
- JavaScript: extract same-origin script URLs, endpoint-like references, public document references, and high-confidence secret patterns. Do not fetch endpoint references or source maps.
- Public documents: record links from fetched public content and sitemap/robots metadata. Do not download them. Flag possible indexing only when the evidence supports it.
- Headers: record security and caching headers and identify obvious risky combinations such as wildcard CORS with credentials. Missing headers are generally hardening observations, not data exposure.
- Access control: limit conclusions to obvious unauthenticated availability observed on approved public paths. Never attempt bypasses or request private records to “confirm” impact.

## Stop conditions

Stop immediately if any request leaves scope, a login/session is encountered, a response appears to contain personal/customer data, a write action may occur, rate limiting or blocking appears, the site becomes unstable, the organization asks to stop, authorization changes, or the request/error ceiling is reached. Preserve only minimal metadata, record the reason, and do not retry automatically. Escalate a suspected active secret or sensitive-data exposure through the responsible disclosure workflow below without testing it.

## Responsible disclosure

1. Minimize evidence: URL, timestamp, response status/headers, a redacted description, and fingerprint are normally enough.
2. Notify the named security contact in the scope file. For third-party discoveries, use `security.txt`, the vendor’s vulnerability disclosure program, or a recognized coordinator; do not publish first.
3. State that no secret was used and no private records were accessed. Include reproduction steps that remain within the approved public scope.
4. Recommend containment (remove public access, rotate suspected secrets, invalidate caches, review access logs) without changing the target yourself.
5. Agree on retest authorization and timing. A remediation request does not automatically authorize a retest.
