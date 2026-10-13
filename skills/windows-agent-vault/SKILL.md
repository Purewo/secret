---
name: windows-agent-vault
description: 使用本地 Agent Vault 安全管理密码、API Key、服务器凭据、账号、Token 等敏感数据，避免暴露明文。用户提到保险柜、已保存的凭据、服务器或账号，或要求 Agent 通过变量名使用秘密时使用。
---

# Windows Agent Vault

本 Skill 随 Agent Vault 仓库提供。加密保险柜保存在仓库之外的用户 Agent Vault 数据目录中；操作系统凭据库可用时，数据密钥由该凭据库保管。

在仓库检出目录中运行附带的封装脚本：

```powershell
& "<repo>\skills\windows-agent-vault\scripts\agent-vault.ps1" entry list
```

封装脚本根据自身位置定位仓库根目录，再通过 `uv` 调用本地 `agent-vault` 命令。

## 查找资源

优先使用能够满足需求、披露信息最少的命令：

```powershell
agent-vault entry list
agent-vault entry show ENTRY_ID
agent-vault list
agent-vault get VARIABLE_NAME
```

以上命令只显示元数据和变量名，不显示秘密值。

## 保存与整理

```powershell
agent-vault entry set ENTRY_ID --description "public description" --tag server
agent-vault set VARIABLE_NAME --note "public note" --tag server
agent-vault entry assign ENTRY_ID VARIABLE_NAME
```

只有标准输入确实提供了秘密值时，才使用 `--value-stdin`。切勿将已读取的秘密明文粘贴到聊天、日志、文档、测试或提交记录中。

## 使用秘密

优先通过环境变量注入：

```powershell
agent-vault run VARIABLE_NAME -- COMMAND ARGUMENTS
```

子进程会收到对应的环境变量，保险柜 CLI 不会打印变量值。子进程也不得回显或序列化这些注入的环境变量。

连接已保存的 SSH 服务器前，先检查条目元数据。如果本机已安装 `ssh-remote` Skill，优先使用其按条目 ID 连接的辅助工具：它只在进程内读取选定的 SSH 变量，并在身份认证前验证主机密钥。否则，通过 `agent-vault run` 注入选定的变量，并使用已验证主机密钥的 SSH 流程。

## 云端 Skill 库

本地同步客户端配置好 Base URL 和 API Key 后，可按需查询有权访问的 Skill：

```powershell
agent-vault-client skills categories
agent-vault-client skills list --category CATEGORY_ID
agent-vault-client skills info SKILL_ID
agent-vault-client skills download SKILL_ID --version VERSION --out .\skill.zip
agent-vault-client --profile codex skills upload .\skill.zip --name "My Skill" --description "中文简介" --version 1.0.0 --category __other__
agent-vault-client --profile codex skills update SKILL_ID --description "通过保险柜安全管理远程服务。"
```

普通 `pull` 命令不会下载 Skill 包。下载命令会校验包的 SHA-256。安装或执行下载的 Skill 前，应先检查 `SKILL.md` 和环境依赖说明。

云端 Skill 简介默认使用中文。只修改名称或简介时，使用 `skills update`，无需重新上传 ZIP 或新增版本。此操作需要该 Skill 所属分类的上传权限，仅有读取权限不够。上传新版本时，提供的名称和简介也会更新，未提供的字段保持原值。Agent 不能通过更新操作将 Skill 移动到其他分类。

## 安全规则

- 除非用户明确要求查看明文，或环境变量注入无法完成任务，否则不要使用 `get --reveal`。
- 凭据应保存在操作系统保险柜或 keyring 中，不要写入仓库文件。
- 条目描述、标签、变量名和备注均视为公开元数据，不得包含秘密值。
- 使用 `agent-vault doctor` 进行诊断；它不会打印秘密值。
