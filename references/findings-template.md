# Structured findings template

Use one record per distinct issue. Keep observations that are not clearly actionable in an appendix rather than inflating severity.

```markdown
## [ID] Concise finding title

- Status: Confirmed | Needs owner validation | False positive
- Severity: Informational | Low | Medium | High | Critical
- Confidence: Low | Medium | High
- Asset and scope: `https://approved.example/path`
- Observed at: `YYYY-MM-DDThh:mm:ssZ`
- Category: API documentation | Client-side secret | Endpoint reference | Public document | Headers | Access control
- Evidence: Minimal redacted description, HTTP status, relevant header names, and fingerprint; no live secret or private record
- Expected state: Why the organization expected the asset not to be public
- Actual state: What an unauthenticated public request revealed
- Impact: Plausible consequence, clearly separated from untested hypotheses
- Reproduction: Safe steps within the approved public scope; no authentication bypass or secret use
- Remediation: Specific containment and durable fix
- Validation plan: Separate, newly authorized retest steps
- Owner: Team or contact
- Disclosure timeline: First observed, reported, acknowledged, fixed, retested
```

## Run summary

```markdown
- Authorization reference:
- Approved target(s):
- Exclusions:
- Window:
- Effective limits:
- Requests made / errors:
- Stop reason:
- Data-handling note:
- Confirmed findings by severity:
- Unverified observations:
- Explicitly not tested: authentication, authorization bypass, private records, credential validity, state-changing actions
```

Severity should reflect demonstrated exposure and organizational context. A client-side identifier intended for public use, an endpoint path, a missing hardening header, or public API documentation is not automatically a vulnerability. For a suspected active secret, recommend immediate rotation and owner-side validation; do not test the credential.
