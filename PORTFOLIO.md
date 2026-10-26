# Portfolio Case Study: Authorized Web Exposure Audit

## Project summary

I built an authorization-first website exposure audit skill for Codex and Claude Code. The project identifies accidental exposure signals on a narrowly bounded public web surface while explicitly avoiding authentication bypasses, private-record access, credential testing, and exploit attempts.

## Problem

Public websites and web applications can unintentionally reveal API documentation, internal endpoint names, secret-like build artifacts, downloadable documents, or unsafe response-header configurations. Traditional security scanners may be too broad or aggressive for an early defensive review, and an AI agent needs unambiguous rules around authorization and evidence handling.

## Approach

- Designed a portable `SKILL.md` workflow with an authorization gate and responsible-disclosure process.
- Implemented exact host, port, scheme, path, exclusion, and date validation for approved scopes.
- Created a Python standard-library audit helper with hard traffic and response-size ceilings.
- Restricted discovery to fixed public paths and same-origin scripts referenced by retrieved pages.
- Added secret redaction using non-reversible short fingerprints rather than retaining values.
- Generated structured JSON and human-readable Markdown findings.
- Built a deliberately vulnerable localhost fixture for repeatable demonstrations without contacting external systems.

## Architecture

The workflow separates decision-making from deterministic enforcement:

1. The skill validates the user’s authority and engagement boundaries.
2. The scope file expresses the exact machine-checkable target and limits.
3. A dry run shows the complete initial request plan without network traffic.
4. The helper enforces limits and stop conditions during execution.
5. The reporting layer minimizes evidence and distinguishes observations from verified risk.

## Demonstrated result

The localhost validation completed nine bounded requests and generated seven findings across five categories:

- API documentation
- Client-side secret pattern
- Endpoint reference
- Public document reference
- Response headers

The validation also confirmed that the linked demonstration document was not downloaded and the fake secret was never reproduced in the reports.

## Engineering decisions

- **Standard library only:** reduces installation and supply-chain overhead.
- **No redirect following:** prevents an approved URL from silently moving traffic outside scope.
- **No endpoint fetching:** endpoint references are useful inventory signals but automatically requesting them could expose records or trigger application behavior.
- **Fail closed:** invalid, expired, missing, or mismatched production scope results in zero traffic.
- **Evidence minimization:** response bodies remain in memory only long enough for bounded analysis and are not written to disk.

## Skills demonstrated

Python, secure-by-design tooling, threat modeling, authorization controls, defensive web analysis, privacy-aware reporting, CLI design, structured data, documentation, and cross-agent skill packaging.

## Future improvements

- Add deterministic unit tests for scope parsing and redaction.
- Support organization-defined secret detectors without exposing matched values.
- Add signed scope manifests for mature internal security programs.
- Provide a local dashboard that reads the JSON report without transmitting data.

