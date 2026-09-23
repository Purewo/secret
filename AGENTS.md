# Agent Vault Usage Rules

- Prefer `uv run agent-vault run NAME -- COMMAND ...` when a task needs a secret.
- Discover available resources with `uv run agent-vault entry list` and inspect variable names with `uv run agent-vault entry show ENTRY_ID`.
- Do not call `uv run agent-vault get NAME --reveal` unless the user explicitly asks or environment injection cannot solve the task.
- Never paste revealed secrets into chat, logs, docs, tests, or commit messages.
- Commands launched through `run` must not print sensitive environment variable values.
- Use `uv run agent-vault doctor` for diagnostics; it does not print secret values.
- For this development PC's authorized remote access, use `uv run --no-sync python -m agent_vault.client --profile codex ...`. Its API Key is in a dedicated OS keyring slot, separate from vault content and other Agent profiles; never print or copy the key into chat.
- Use the `skills categories|list|info|download|upload` subcommands of that client for Skill sharing. Ordinary `pull` affects local vault data, so inspect intended sync scope before using it on a populated vault.
