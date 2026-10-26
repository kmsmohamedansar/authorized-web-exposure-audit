# Contributing

Contributions that improve safety, scope enforcement, reporting clarity, portability, or test coverage are welcome.

## Ground rules

- Test changes only against the included localhost fixture or another system you are explicitly authorized to assess.
- Never include live credentials, proprietary data, customer records, internal target details, or unredacted response bodies.
- Preserve fail-closed scope validation and the default traffic ceilings.
- Do not add authentication bypasses, credential validation, identifier guessing, fuzzing, exploit execution, stealth, or detection-evasion features.
- Keep runtime dependencies minimal and justify any new dependency.

## Before submitting a change

1. Run the skill validator.
2. Run a dry run against the localhost fixture.
3. Run the complete localhost audit.
4. Confirm that reports contain no raw fake secret and that linked documents were not requested.
5. Explain any change to network behavior, scope rules, findings, or retained data.

Keep pull requests focused. Security-sensitive changes should describe their safety properties and failure modes, not only their intended behavior.

