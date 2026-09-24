# Agent Vault Usage Rules

- Prefer `uv run agent-vault run NAME -- COMMAND ...` when a task needs a secret.
- Discover available resources with `uv run agent-vault entry list` and inspect variable names with `uv run agent-vault entry show ENTRY_ID`.
- Do not call `uv run agent-vault get NAME --reveal` unless the user explicitly asks or environment injection cannot solve the task.
- Never paste revealed secrets into chat, logs, docs, tests, or commit messages.
- Commands launched through `run` must not print sensitive environment variable values.
- Use `uv run agent-vault doctor` for diagnostics; it does not print secret values.
- For this development PC's authorized remote access, use `uv run --no-sync python -m agent_vault.client --profile codex ...`. Its API Key is in a dedicated OS keyring slot, separate from vault content and other Agent profiles; never print or copy the key into chat.
- Use the `skills categories|list|info|download|upload` subcommands of that client for Skill sharing. Ordinary `pull` affects local vault data, so inspect intended sync scope before using it on a populated vault.

## Development and release cadence

- For routine small changes, update and verify the source code, then make a normal Git commit. Keep source-code commits separate from deployment and releases.
- Do not automatically deploy to or restart the public server for routine changes. Deploy only when the user explicitly requests it, even if the change has already been committed or pushed.
- Do not automatically build client/server packages, create release tags, or publish a GitHub Release. Wait for the user's explicit request after enough changes have accumulated.
- In handoffs, state separately whether the code was committed/pushed, deployed to the server, and packaged/released. Never imply one of these happened because another did.
