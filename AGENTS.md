## Secrets and credentials policy

- Never inspect, open, print, or copy `.env`, credential files, private keys, access tokens, refresh tokens, or other secret-bearing files.
- Use `.env.example`, configuration types, and documented variable names to understand required configuration.
- Never request actual secret values in prompts or responses.
- Never print environment variables, authentication headers, tokens, client secrets, or complete authentication responses.
- Use fake credentials and mocked HTTP responses for unit tests.
- Do not run commands that dump the environment or expose secret values.
- Do not transmit credentials to external services or include them in commits, logs, test fixtures, or generated reports.
- If a task requires real credentials or access to a live external system, stop and request explicit authorization for a human-controlled integration test.
- If a secret is discovered unexpectedly, do not reproduce it; report the exposure without including the value.

These instructions do not replace filesystem permissions, execution restrictions, or secret-management controls.

## Git workflow

- Never work directly on `main`.
- Before making changes, verify the current branch.
- If the current branch is `main`, stop and ask the human to create a feature branch.
- Do not commit, push, merge, or delete branches without explicit authorization.
- Keep changes scoped to the assigned task.
- Inspect the diff and report the files changed before finishing.

## Testing and verification

- Run the relevant tests, lint, and build checks for each change.
- Report the actual result of every check. Never claim success without running it.
- Do not disable, skip, or weaken tests just to make CI pass.
- Use mocked external API responses for unit tests.
- Request authorization before accessing live external systems.

## Salesforce access

- Use the Salesforce Developer Edition org for development and testing.
- Request only the Salesforce permissions required for the assigned task.
- Never use production credentials or production data for this project.
- Do not perform writes against Salesforce unless the task explicitly authorizes them.
- Keep Salesforce credentials outside source control and out of agent-visible files whenever possible.
