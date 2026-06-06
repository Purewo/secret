# Agent Vault Usage Rules

- Prefer `uv run agent-vault run NAME -- COMMAND ...` when a task needs a secret.
- Do not call `uv run agent-vault get NAME --reveal` unless the user explicitly asks or environment injection cannot solve the task.
- Never paste revealed secrets into chat, logs, docs, tests, or commit messages.
- Commands launched through `run` must not print sensitive environment variable values.
- Use `uv run agent-vault doctor` for diagnostics; it does not print secret values.
