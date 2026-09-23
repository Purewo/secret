# Agent Vault

一个给 Codex / Claude 使用的小型本地保险库。它把敏感值加密保存在当前用户的数据目录，默认只通过变量名注入子进程环境变量，避免把密码、token、账号信息反复暴露在聊天上下文里。

## 安装与初始化

```powershell
uv sync --dev --python 3.12
uv run agent-vault init
```

## Web 管理台

启动只监听本机的 Web 管理台：

```powershell
uv run --no-sync python -m agent_vault.web --open
```

重新执行过 `uv sync` 或安装发布版后，也可以使用更短的 `agent-vault-web --open`。

默认地址为 `http://127.0.0.1:2001`，初始账号为 `admin`，初始密码为 `123456`。

登录后进入侧栏「设置」，输入当前密码、新密码和确认密码即可修改密码（8–256 个字符）。修改后所有 Web 会话失效，需使用新密码重新登录；API Key 不受影响。

Web 密码以加盐 PBKDF2-SHA256 哈希单独保存在数据目录的 `web_auth.json`，不进入内容库或同步数据，服务重启后继续生效。下面的环境变量用于指定用户名和首次启动的初始密码；已有密码文件时，密码环境变量不会覆盖已保存的密码。不要把正式密码写进仓库：

```powershell
$env:AGENT_VAULT_WEB_USERNAME = "your-admin-name"
$env:AGENT_VAULT_WEB_PASSWORD = "your-strong-password"
uv run --no-sync python -m agent_vault.web --open
```

Web 页面默认只读取秘密变量的名称、标签和公开备注。登录后可以打开资源详情，并对单个变量执行明确的“显示”或“复制”操作；页面不会批量加载明文，详情关闭后会清空已显示内容。新秘密通过本机 HTTP 请求提交后直接交给现有加密存储层。默认服务仅绑定 `127.0.0.1`；不要在使用初始密码时改为公网监听地址。

资源还支持一级分类：新建分类（如“服务器”“游戏”）后，可以在资源页按分类筛选，也可以在“整理分类”中勾选多个资源批量移动。内置“其他”是默认分类，历史资源和未指定分类的新资源都会显示在这里；标签仍然用于更细粒度的搜索。

## API Key 与远程 Agent

管理台的“API 密钥”页面可以为受信任的 Agent 创建 API Key。新 Key 默认没有任何内容权限，管理员需要在“权限管理”中选择开放的分类和能力：只读，或可读 + 新增；删除权限是独立开关，默认关闭。管理员可以随时通过小眼睛查看、复制或撤销。

API Key 使用标准 Bearer 认证：

```text
Authorization: Bearer avk_...
```

内容接口（例如 `/api/snapshot`、`/api/entries`、`/api/secrets`、`/api/categories`）接受 Bearer Key；API Key 管理接口只接受管理员浏览器会话，不会因为某个 Agent 拿到内容权限就能枚举或创建其他 Key。Bearer Key 只能看到被授权分类，不能跨分类读取；删除秘密还需要单独的删除权限。

本地同步客户端目前先以 CLI 形式提供：

```powershell
uv run --no-sync python -m agent_vault.client configure --base-url https://your-vault.example --api-key-stdin
uv run --no-sync python -m agent_vault.client pull
uv run --no-sync python -m agent_vault.client push-entry japan_server
```

客户端把 Base URL 写入本地 Client 配置，把 API Key 写入独立系统 keyring；本地拉取后的数据由本地保险柜负责读取和环境变量注入。同步失败时会返回服务端的具体原因，例如分类无权限、写入权限不足或版本冲突。

存储上，内容数据使用 SQLite `vault.db`，秘密值仍由 Fernet 加密；API Key 使用独立的 `ApiKeys/api_keys.db` 和独立系统 keyring 密钥，绝不写入内容数据库。首次启动 SQLite 后会从旧 `vault.enc` 自动迁移，旧文件会保留作为迁移来源。

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
