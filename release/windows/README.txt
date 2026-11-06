Agent Vault v0.5.0 · Windows x64

agent-vault.exe          Local encrypted vault CLI
agent-vault-client.exe   Sync, shared Skills, and private Agent backup spaces
agent-vault-web.exe      Web management service (default port 2005)

Examples:
  agent-vault.exe init
  agent-vault-client.exe configure --base-url https://your-vault.example --api-key-stdin
  agent-vault-client.exe pull
  agent-vault-client.exe skills categories
  agent-vault-client.exe skills list --category documents
  agent-vault-client.exe skills download SKILL_ID --out .\skill.zip
  agent-vault-client.exe --profile codex skills upload .\skill.zip --name "My Skill" --description "Reusable instructions" --version 1.0.0
  agent-vault-client.exe --profile lobster backups space
  agent-vault-client.exe --profile lobster backups upload .\memory.zip --name "Memory" --partition memory --version 2026.11.6
  agent-vault-client.exe --profile lobster backups upload .\skills.zip --name "Skills" --partition skills --version 2026.11.6
  agent-vault-client.exe --profile lobster backups upload .\workspace.zip --name "Workspace" --partition other --version 2026.11.6
  agent-vault-web.exe --open

The executables use the current Windows user's Agent Vault data directory and
Windows Credential Manager. Keep this folder and its API keys private.

Every Agent backup belongs to the profile's authenticated API key. Other keys
cannot access it. Existing unbound backups require administrator binding once.
