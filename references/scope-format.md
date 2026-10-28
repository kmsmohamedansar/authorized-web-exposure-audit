# Approved scope format

For a non-loopback target, the helper requires a JSON file supplied by the organization. It is a guardrail and audit record, not a substitute for a contract or legal approval.

```json
{
  "authorization_confirmed": true,
  "organization": "Example Corp",
  "authorized_by": "security-team@example.com / ticket SEC-1234",
  "valid_from": "2026-10-20",
  "expires": "2026-11-03",
  "targets": [
    {
      "scheme": "https",
      "host": "audit.example.com",
      "port": 443,
      "allowed_path_prefixes": ["/"],
      "excluded_path_prefixes": ["/account", "/admin", "/customers", "/checkout"]
    }
  ],
  "max_requests": 30,
  "max_requests_per_second": 1,
  "security_contact": "security@example.com",
  "notes": "Unauthenticated public-surface review only; change ticket SEC-1234."
}
```

Requirements:

- Use exact hostnames; wildcards and CIDR ranges are rejected.
- List every scheme and non-default port as its own target entry.
- Dates are inclusive ISO `YYYY-MM-DD` dates. The helper uses the local system date and rejects not-yet-valid or expired files.
- Allowed prefixes must begin with `/`. Exclusions override allowances.
- `authorization_confirmed` must be `true`, and the organization, authorizer, contact, and validity fields must be non-empty.
- Limits may be stricter than the helper defaults, never looser than its hard caps.
- `max_requests` must be a whole number. The request rate must be a finite number; booleans are not valid for limits or ports.
- The helper does not verify that the named authorizer has legal authority. The human operator must do so before approving a live run.

Keep the approved scope file with the engagement record. Do not commit internal contacts, tickets, or target details to a public repository.

