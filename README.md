# Agent Vault

一个给 Codex / Claude 使用的小型本地保险库。它把敏感值加密保存在当前用户的数据目录，默认只通过变量名注入子进程环境变量，避免把密码、token、账号信息反复暴露在聊天上下文里。

## 安装与初始化

客户端和服务端目前共用同一个 Python 发布包。安装后可以按需要使用 `agent-vault-web` 启动管理服务，或使用 `agent-vault-client` 进行离线同步；两者使用同一套存储与 API Key 权限模型。

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

默认地址为 `http://127.0.0.1:2005`，与自建服务器上的应用监听端口一致；公网入口仍是 Nginx 的 `https://pioneer.fan:85`。初始账号为 `admin`，初始密码为 `123456`。

登录后进入侧栏「个人中心」的「登录安全」，输入当前密码、新密码和确认密码即可修改密码（8–256 个字符）。修改后所有 Web 会话失效，需使用新密码重新登录；API Key 不受影响。

Web 密码以加盐 PBKDF2-SHA256 哈希单独保存在数据目录的 `web_auth.json`，不进入内容库或同步数据，服务重启后继续生效。下面的环境变量用于指定用户名和首次启动的初始密码；已有密码文件时，密码环境变量不会覆盖已保存的密码。不要把正式密码写进仓库：

```powershell
$env:AGENT_VAULT_WEB_USERNAME = "your-admin-name"
$env:AGENT_VAULT_WEB_PASSWORD = "your-strong-password"
uv run --no-sync python -m agent_vault.web --open
```

Web 页面默认只读取秘密变量的名称、标签和公开备注。登录后可以打开资源详情，并对单个变量执行明确的“显示”或“复制”操作；页面不会批量加载明文，详情关闭后会清空已显示内容。新秘密通过本机 HTTP 请求提交后直接交给现有加密存储层。默认服务仅绑定 `127.0.0.1`；不要在使用初始密码时改为公网监听地址。

资源还支持一级分类：新建分类（如“服务器”“游戏”）后，可以在资源页按分类筛选，也可以在“整理分类”中勾选多个资源批量移动。内置“其他”是默认分类，历史资源和未指定分类的新资源都会显示在这里；标签仍然用于更细粒度的搜索。

## API Key 与远程 Agent

管理台「个人中心」的「API 密钥」页签可以为受信任的 Agent 创建 API Key。新 Key 默认没有任何权限，管理员需要在“权限管理”中分别开放秘密内容分类和 Skill 分类。秘密内容可只读、可新增，删除权限独立配置；Skill 读取和上传也按分类分别配置。管理员可以随时通过小眼睛查看、复制或撤销。

API Key 使用标准 Bearer 认证：

```text
Authorization: Bearer avk_...
```

浏览器管理接口（例如 `/api/snapshot` 和 `/api/api-keys`）只接受管理员会话；Agent 通过 `/api/v1/sync/*` 和 `/api/v1/skills/*` 使用 Bearer Key。Key 只能访问被授权分类，不能枚举或创建其他 Key。

本地同步客户端目前先以 CLI 形式提供：

```powershell
uv run --no-sync python -m agent_vault.client configure --base-url https://your-vault.example --api-key-stdin
uv run --no-sync python -m agent_vault.client pull
uv run --no-sync python -m agent_vault.client push-entry japan_server
```

客户端把 Base URL 写入本地 Client 配置，把 API Key 写入独立系统 keyring；本地拉取后的数据由本地保险柜负责读取和环境变量注入。同步失败时会返回服务端的具体原因，例如分类无权限、写入权限不足或版本冲突。

多 Agent 在同一台电脑上使用时，为每个 Agent 配置独立客户端 profile，避免覆盖彼此的 API Key。例如：

```powershell
agent-vault-client --profile codex configure --base-url https://pioneer.fan:85 --api-key-stdin
agent-vault-client --profile codex pull
```

默认 profile 与旧版客户端完全兼容；命名 profile 的配置在 `Client/profiles/PROFILE/sync.json`，密钥使用单独的系统 keyring 槽位。普通 `pull` 仍是主动操作，不会在后台自动覆盖本地数据。

## Skill 仓库

Web 管理台的「Skill 仓库」页面可以新建分类并上传 Skill ZIP。每个 Skill 需要名称、简介和版本号；ZIP 的根目录或单一顶层目录必须包含非空 `SKILL.md`。同一个 Skill 可追加版本，旧版本保持可下载。服务端保存上传时间、下载次数、包大小、SHA-256 和运行环境提示；ZIP 上传上限为 25 MB，解压后上限为 100 MB。脚本文件会触发环境依赖提示，也可以在上传时手动指定。

Skill 的元数据保存在独立的 `Skills/skills.db`，原包保存在 `Skills/packages/`。它们不写入保险柜内容数据库，也不随 `agent-vault-client pull` 同步。管理员可在 API Key 权限管理中按分类分别授权读取和上传；默认两者都不开放。已有 Skill 的新版本只能追加到原分类，Agent 不能借上传移动 Skill 分类。

Agent 使用 Bearer API Key 分步查询和下载：

```text
GET /api/v1/skills/categories
GET /api/v1/skills?category=documents
GET /api/v1/skills/{skill_id}
GET /api/v1/skills/{skill_id}/versions/{version}/download
POST /api/v1/skills/upload?name=...&description=...&version=...&category=...
```

详情返回 `download_url` 相对路径。下载时仍需发送 `Authorization: Bearer ...`，不要把 API Key 拼进下载 URL。浏览器管理员会话可直接从 Skill 详情下载 ZIP。

已配置的本地客户端也可以按需浏览或下载，下载时会验证 SHA-256；Skill 包不会在普通 `pull` 中自动同步：

```powershell
agent-vault-client skills categories
agent-vault-client skills list --category documents
agent-vault-client skills info SKILL_ID
agent-vault-client skills download SKILL_ID --version 1.0.0 --out .\my-skill.zip
agent-vault-client --profile codex skills upload .\my-skill.zip --name "My Skill" --description "简介" --version 1.0.0 --category __other__
```

存储上，内容数据使用 SQLite `vault.db`，秘密值仍由 Fernet 加密；API Key 使用独立的 `ApiKeys/api_keys.db` 和独立系统 keyring 密钥，绝不写入内容数据库。首次启动 SQLite 后会从旧 `vault.enc` 自动迁移，旧文件会保留作为迁移来源。

Linux 上也可以直接用 `uv` 安装最新发布版 wheel：

```bash
uv tool install https://github.com/Purewo/secret/releases/download/v0.4.2/agent_vault-0.4.2-py3-none-any.whl
agent-vault init
```

`v0.4.2` 发布包同时包含命令行保险柜、Web 管理台和本地同步客户端，服务端部署与客户端安装使用同一个 wheel；服务端只需额外配置 systemd 或其他进程托管方式。

面向 Codex / Claude 的 Windows Agent Vault Skill 也随 Release 提供，下载 `agent-vault-windows-skill-0.4.2.zip` 后，将其中的 `windows-agent-vault` 目录放入对应的 skills 目录即可。Skill 只包含调用规则和无凭据脚本，不包含任何本机保险柜数据。

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
