# Changelog

## 1.0.1

- Reject boolean and fractional request limits, non-finite rates, and boolean ports in scope files before making requests.
- Add regression tests for malformed limits and confirm the command exits before creating a report.

## 1.0.0

- Initial versioned release with scope-aware public-surface checks, conservative path handling, redaction, stop conditions, and local safety tests.
