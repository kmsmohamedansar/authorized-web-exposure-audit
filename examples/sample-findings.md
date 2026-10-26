# Sanitized Example Findings

This stable example summarizes a run against the included localhost fixture. All values are fake, and no external system was contacted.

## Run summary

- Target: `http://127.0.0.1:8765/`
- Authorization: Localhost fixture
- Requests: 9
- Request rate: 1 per second
- Stop reason: Planned requests completed
- Response bodies retained: No
- Explicitly not tested: authentication, bypasses, private records, credential validity, or state-changing actions

## F-001: Suspected secret-like value in public client content

- Status: Needs owner validation
- Severity: High
- Confidence: Medium
- Category: Client-side secret
- Source: `/assets/app.js`
- Evidence: Redacted preview `DEM…89`; SHA-256 fingerprint prefix `b1fcc40c7281`
- Impact: A real embedded credential could permit unauthorized use of its associated service.
- Caveat: The value was not printed, validated, or used. The fixture value is intentionally fake.
- Remediation: Remove secrets from client builds, rotate any real exposed value, and keep privileged credentials server-side.

## F-002: Wildcard CORS with credentials

- Status: Confirmed fixture misconfiguration
- Severity: Medium
- Confidence: High
- Category: Headers
- Source: `/`
- Evidence: `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- Impact: Browsers normally reject this exact combination, but it indicates unsafe CORS policy design.
- Remediation: Permit only explicitly trusted origins and review whether credentialed cross-origin requests are necessary.

## F-003: API documentation is publicly reachable

- Status: Needs owner validation
- Severity: Informational
- Confidence: High
- Category: API documentation
- Source: `/openapi.json`
- Evidence: Unauthenticated HTTP 200 response with an OpenAPI document
- Caveat: Public API documentation may be intentional.
- Remediation: Confirm intended publication; otherwise require appropriate access control and remove cached public copies.

## F-004: Public content references API-style paths

- Status: Observation
- Severity: Informational
- Confidence: High
- Category: Endpoint reference
- Source: `/assets/app.js`
- Evidence: References to `/api/v1/catalog` and `/graphql`
- Caveat: The referenced endpoints were not requested, and endpoint visibility alone is not a vulnerability.

## F-005: Publicly referenced document

- Status: Needs owner validation
- Severity: Informational
- Confidence: High
- Category: Public document
- Source: `/` and `/sitemap.xml`
- Evidence: Reference to `/public/quarterly-plan.pdf`
- Caveat: The document was not downloaded.
- Remediation: Confirm intended publication and remove unintended references from public pages, sitemaps, caches, and storage policies.

