# Setup and examples

The helper uses Python 3.9+ and the standard library only.

## Install as a skill

Copy or symlink the whole `authorized-web-exposure-audit` folder:

- Codex: `$CODEX_HOME/skills/authorized-web-exposure-audit`, or `~/.codex/skills/authorized-web-exposure-audit` when `CODEX_HOME` is unset.
- Claude Code: `.claude/skills/authorized-web-exposure-audit` inside a project, or `~/.claude/skills/authorized-web-exposure-audit` for the user.

Restart the relevant client if it does not notice the skill automatically. Keep `SKILL.md`, `scripts/`, and `references/` together.

## Local demonstration

From the skill directory, start the deliberately vulnerable fixture in one terminal:

```bash
python3 scripts/demo_server.py --port 8765
```

Preview the exact requests without network traffic:

```bash
python3 scripts/audit_site.py http://127.0.0.1:8765/ --dry-run --output-dir demo-output
```

Run the localhost-only audit:

```bash
python3 scripts/audit_site.py http://127.0.0.1:8765/ --output-dir demo-output
```

Expected categories include a publicly reachable OpenAPI document, endpoint-like strings in a same-origin JavaScript bundle, a redacted demo token candidate, a linked public document reference, and header observations. The fixture contains fake data only.

## Authorized non-local dry run

Create an approved scope file using [scope-format.md](scope-format.md), then preview:

```bash
python3 scripts/audit_site.py https://audit.example.com/ \
  --scope approved-scope.json \
  --dry-run \
  --output-dir audit-output
```

After a human confirms that the printed target and limits match the approval, repeat without `--dry-run`. The helper clamps command-line limits to the stricter scope value.

Useful options:

```text
--max-requests 30       Total request ceiling (hard cap: 100)
--rate 1                Requests per second (hard cap: 2)
--timeout 10            Per-request timeout seconds (hard cap: 20)
--public-path /about    Add an exact, approved public path to inspect
```

`--public-path` is rejected when it falls outside an allowed prefix or inside an exclusion. Do not use it for private, user-specific, authenticated, state-changing, or identifier-bearing routes.

## Outputs

- `findings.json`: machine-readable run metadata, stopped reason, observations, and findings.
- `findings.md`: concise human review copy.

The helper never stores response bodies. Review outputs before sharing because URLs and header values can still be sensitive in context.

