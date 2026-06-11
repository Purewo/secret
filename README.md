# Agent Vault

一个给 Codex / Claude 使用的小型本地保险库。它把敏感值加密保存在当前用户的数据目录，默认只通过变量名注入子进程环境变量，避免把密码、token、账号信息反复暴露在聊天上下文里。

## 安装与初始化

```powershell
uv sync --dev --python 3.12
uv run agent-vault init
```

Linux 上也可以直接用 `uv` 安装发布版 wheel：

```bash
uv tool install https://github.com/Purewo/secret/releases/download/v0.2.0/agent_vault-0.2.0-py3-none-any.whl
agent-vault init
```

最低支持 Python 3.10。

默认 vault 文件位置：

```text
Windows: %LOCALAPPDATA%\AgentVault\vault.enc
Linux:   ~/.local/share/AgentVault/vault.enc
```

Windows 上加密用的数据密钥保存在 Windows Credential Manager 中，不写入项目目录。

在 Linux/macOS 上会优先使用系统 keyring；如果无桌面/无 keyring 后端不可用，会退回到本地 `vault.key` 文件。该文件默认位于同一个用户数据目录，Linux 权限会设置为 `0600`，目录为 `0700`。这比系统 keyring 弱一些，但能在服务器环境直接使用。

## 基本用法

保存秘密值：

```powershell
"your-secret-value" | uv run agent-vault set server_password --value-stdin --tag server --note "SSH password"
```

查看变量名和元信息，不显示明文：

```powershell
uv run agent-vault list
uv run agent-vault get server_password
```

创建一个带公开简介的条目。条目可以是服务器、账号、API、网站或任意资源：

```powershell
uv run agent-vault entry set japan_server --description "日本三网优化服务器" --tag server --tag japan
```

把已有变量归到条目，不读取或重写秘密值：

```powershell
uv run agent-vault entry assign japan_server server_ip server_user server_password
```

列出所有条目，或查看条目关联的变量名：

```powershell
uv run agent-vault entry list
uv run agent-vault entry show japan_server
```

条目简介、标签和变量名默认可见，方便 Codex / Claude 查询；变量值仍不会显示。

给命令注入环境变量，不由 `agent-vault` 输出明文：

```powershell
uv run agent-vault run server_password -- powershell -NoProfile -Command "$env:server_password.Length"
```

注意：`run` 只能保证 `agent-vault` 自己不打印明文。如果后面的子命令主动输出环境变量，明文仍会出现在终端和聊天上下文里。

特殊情况下显式输出明文：

```powershell
uv run agent-vault get server_password --reveal
```

删除秘密：

```powershell
uv run agent-vault delete server_password --yes
```

诊断本机状态，不输出任何秘密值：

```powershell
uv run agent-vault doctor
```

## 给代理的规则

- 优先使用 `agent-vault run NAME -- COMMAND ...`。
- 需要查找可用资源时，先使用 `agent-vault entry list` 和 `agent-vault entry show ENTRY_ID`。
- 不要使用 `get --reveal`，除非用户明确要求或当前任务无法通过环境变量注入完成。
- 不要把 `get --reveal` 的输出粘贴进聊天、日志、README、测试快照或提交信息。
- 使用 `run` 时，子命令也不应打印敏感环境变量本身。
- 变量名必须匹配 `[A-Za-z_][A-Za-z0-9_]*`，例如 `server_password`、`github_token`。
- Windows 环境变量大小写不敏感，因此不允许同时保存 `server_password` 和 `SERVER_PASSWORD`。

## 测试

```powershell
uv run pytest
```
