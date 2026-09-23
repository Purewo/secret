Agent Vault v0.4.0 · Windows x64

agent-vault.exe          Local encrypted vault CLI
agent-vault-client.exe   Sync and on-demand Skill client
agent-vault-web.exe      Web management service (default port 2001)

Examples:
  agent-vault.exe init
  agent-vault-client.exe configure --base-url https://your-vault.example --api-key-stdin
  agent-vault-client.exe pull
  agent-vault-client.exe skills categories
  agent-vault-client.exe skills list --category documents
  agent-vault-client.exe skills download SKILL_ID --out .\skill.zip
  agent-vault-web.exe --open

The executables use the current Windows user's Agent Vault data directory and
Windows Credential Manager. Keep this folder and its API keys private.
