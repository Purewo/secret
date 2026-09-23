param([string]$Version = "0.4.1")

$ErrorActionPreference = "Stop"
$project = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$src = (Resolve-Path (Join-Path $project "src")).Path
$assets = (Resolve-Path (Join-Path $src "agent_vault\web_static")).Path
$output = Join-Path $project "build_windows\dist"
$work = Join-Path $project "build_windows\work"
$spec = Join-Path $project "build_windows\spec"
New-Item -ItemType Directory -Force -Path $output, $work, $spec | Out-Null

$common = @("--clean", "--noconfirm", "--onefile", "--paths", $src, "--distpath", $output, "--workpath", $work, "--specpath", $spec)
$pythonDeps = @("--from", "pyinstaller", "--with", "cryptography", "--with", "filelock", "--with", "keyring", "--with", "platformdirs")

& uvx @pythonDeps pyinstaller @common --name agent-vault (Join-Path $PSScriptRoot "agent_vault_cli.py")
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }
& uvx @pythonDeps pyinstaller @common --name agent-vault-client (Join-Path $PSScriptRoot "agent_vault_client.py")
if ($LASTEXITCODE -ne 0) { throw "Client build failed" }
& uvx @pythonDeps pyinstaller @common --hidden-import agent_vault.web_static --add-data "$assets;agent_vault/web_static" --name agent-vault-web (Join-Path $PSScriptRoot "agent_vault_web.py")
if ($LASTEXITCODE -ne 0) { throw "Web build failed" }

Copy-Item (Join-Path $PSScriptRoot "README.txt") (Join-Path $output "README.txt") -Force
$archive = Join-Path $project "dist\agent-vault-windows-x64-$Version.zip"
Compress-Archive -Path (Join-Path $output "*") -DestinationPath $archive -Force
Write-Output $archive
