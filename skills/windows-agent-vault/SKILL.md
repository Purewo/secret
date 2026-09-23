---
name: windows-agent-vault
description: Use the local Agent Vault for passwords, API keys, server credentials, accounts, tokens, and other sensitive data without exposing plaintext. Trigger when the user mentions the secret vault, stored credentials, saved servers/accounts, or asks an agent to use a secret by variable name.
---

# Windows Agent Vault

This skill ships with the Agent Vault repository. The encrypted vault lives outside the repository in the user's Agent Vault data directory; its data key is stored in the operating system credential store when available.

Run the bundled wrapper from the repository checkout:

```powershell
& "<repo>\skills\windows-agent-vault\scripts\agent-vault.ps1" entry list
```

The wrapper resolves the repository root from its own location and invokes the local `agent-vault` command through `uv`.

## Discovery

Use the least revealing command that answers the request:

```powershell
agent-vault entry list
agent-vault entry show ENTRY_ID
agent-vault list
agent-vault get VARIABLE_NAME
```

These commands show metadata and variable names. They do not reveal secret values.

## Store and organize

```powershell
agent-vault entry set ENTRY_ID --description "public description" --tag server
agent-vault set VARIABLE_NAME --note "public note" --tag server
agent-vault entry assign ENTRY_ID VARIABLE_NAME
```

Use `--value-stdin` only when real stdin provides the value. Never paste a revealed secret into chat, logs, documentation, tests, or commits.

## Consume secrets

Prefer environment injection:

```powershell
agent-vault run VARIABLE_NAME -- COMMAND ARGUMENTS
```

The child process receives the variable without the vault CLI printing its value. Do not echo or serialize the injected environment variable.

For SSH, inspect the entry metadata first, validate the host key, and use the SSH workflow with `agent-vault run`.

## Security rules

- Do not use `get --reveal` unless the user explicitly requests plaintext or injection cannot complete the task.
- Keep credentials in the operating system vault or keyring, never in repository files.
- Treat entry descriptions, tags, variable names, and notes as public metadata.
- Use `agent-vault doctor` for diagnostics; it does not print secret values.
