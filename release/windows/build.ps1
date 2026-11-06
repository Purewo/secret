param([ValidatePattern('^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$')][string]$Version = "0.5.0")

$ErrorActionPreference = "Stop"
$project = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$src = (Resolve-Path (Join-Path $project "src")).Path
$assets = (Resolve-Path (Join-Path $src "agent_vault\web_static")).Path
$output = Join-Path $project "build_windows\$Version\dist"
$work = Join-Path $project "build_windows\$Version\work"
$spec = Join-Path $project "build_windows\$Version\spec"
New-Item -ItemType Directory -Force -Path $output, $work, $spec | Out-Null

$common = @("--clean", "--noconfirm", "--onefile", "--paths", $src, "--distpath", $output, "--workpath", $work, "--specpath", $spec)
$pythonDeps = @("--from", "pyinstaller", "--with", "cryptography", "--with", "filelock", "--with", "keyring", "--with", "platformdirs")

function Invoke-StandaloneBuild {
    param([string]$Name, [string]$EntryPoint, [string[]]$ExtraArgs = @())
    # Windows PowerShell classifies native progress on stderr as an error.
    # Keep progress nonterminating and use the process exit code for failure.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & uvx @pythonDeps pyinstaller @common @ExtraArgs --name $Name $EntryPoint
        $buildExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($buildExitCode -ne 0) { throw "$Name build failed (exit $buildExitCode)" }
}

Invoke-StandaloneBuild -Name agent-vault -EntryPoint (Join-Path $PSScriptRoot "agent_vault_cli.py")
Invoke-StandaloneBuild -Name agent-vault-client -EntryPoint (Join-Path $PSScriptRoot "agent_vault_client.py")
Invoke-StandaloneBuild -Name agent-vault-web -EntryPoint (Join-Path $PSScriptRoot "agent_vault_web.py") -ExtraArgs @("--hidden-import", "agent_vault.web_static", "--add-data", "$assets;agent_vault/web_static")

Copy-Item (Join-Path $PSScriptRoot "README.txt") (Join-Path $output "README.txt") -Force
$archive = Join-Path $project "dist\agent-vault-windows-x64-$Version.zip"
Compress-Archive -Path (Join-Path $output "*") -DestinationPath $archive -Force
Write-Output $archive
