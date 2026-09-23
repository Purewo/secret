param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$VaultArgs
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path

if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "pyproject.toml"))) {
    throw "Agent Vault project not found: $ProjectRoot"
}

$uv = Get-Command uv -ErrorAction Stop
& $uv.Source run --project $ProjectRoot agent-vault @VaultArgs
exit $LASTEXITCODE
