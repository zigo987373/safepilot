[CmdletBinding()]
param(
    [string]$EnvFile = ".env",
    [string]$SecretsDir = "./secrets",
    [string]$ComposeOverride = "./docker-compose.secrets.generated.yml",
    [switch]$NoGenerateMasterKey,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @"
Usage: scripts/sync-secrets-from-env.ps1 [options]

Translate known secret env vars from a .env file into file-based secrets.
Also generates a docker compose override that wires additional *_FILE vars + secrets.

Options:
  -EnvFile PATH            Source env file (default: .env)
  -SecretsDir PATH         Output secret directory (default: ./secrets)
  -ComposeOverride PATH    Generated compose override file (default: ./docker-compose.secrets.generated.yml)
  -NoGenerateMasterKey     Do not generate secrets/master_key when ORCH_MASTER_KEY is missing
  -Help                    Show help

Notes:
  - The parser is safe-by-default: it does not execute .env content.
  - Supports KEY=VALUE, optional export, comments, single/double quoted values.
"@
}

function Parse-EnvValue {
    param(
        [string]$Raw,
        [int]$LineNumber
    )

    $value = $Raw.TrimStart()

    if ($value.StartsWith('"')) {
        if ($value -match '^"(.*)"\s*$') {
            return [Regex]::Unescape($Matches[1])
        }
        throw "warn: skipping unparsable quoted value at line $LineNumber"
    }

    if ($value.StartsWith("'")) {
        if ($value -match "^'(.*)'\s*$") {
            return $Matches[1]
        }
        throw "warn: skipping unparsable single-quoted value at line $LineNumber"
    }

    $value = [Regex]::Replace($value, '\s+#.*$', '')
    return $value.TrimEnd()
}

function Parse-EnvFile {
    param([string]$Path)

    $parsed = @{}
    $lineNo = 0

    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        $lineNo += 1
        $trimmed = $line.TrimStart()

        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith('#')) { continue }

        if ($trimmed.StartsWith('export ')) {
            $trimmed = $trimmed.Substring(7).TrimStart()
        }

        if ($trimmed -notmatch '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            Write-Warning "skipping unsupported line $lineNo in $Path"
            continue
        }

        $key = $Matches[1]
        $rhs = $Matches[2]

        try {
            $value = Parse-EnvValue -Raw $rhs -LineNumber $lineNo
            $parsed[$key] = $value
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }

    return $parsed
}

function Set-StrictPermissions {
    param([string]$Path)

    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)

        foreach ($rule in @($acl.Access)) {
            $null = $acl.RemoveAccessRule($rule)
        }

        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $accessType = [System.Security.AccessControl.AccessControlType]::Allow

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid,
            $rights,
            $inheritance,
            $propagation,
            $accessType
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
        return
    }

    & chmod 600 -- $Path
}

function Ensure-SecretsDirectory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }

    if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) {
        & chmod 700 -- $Path
    }
}

function Write-SecretFile {
    param(
        [string]$Directory,
        [string]$FileName,
        [string]$Value
    )

    $path = Join-Path $Directory $FileName
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, $Value, $encoding)
    Set-StrictPermissions -Path $path
}

function Generate-MasterKey {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes)
}

function Get-ValueOrEmpty {
    param(
        [hashtable]$Map,
        [string]$Key
    )

    if ($Map.ContainsKey($Key)) {
        return [string]$Map[$Key]
    }

    return ""
}

if ($Help) {
    Show-Usage
    exit 0
}

if (-not (Test-Path -LiteralPath $EnvFile)) {
    throw "error: env file not found: $EnvFile"
}

$parsed = Parse-EnvFile -Path $EnvFile
Ensure-SecretsDirectory -Path $SecretsDir

$mappings = @(
    @{ EnvKey = 'BOT_TOKEN'; FileEnvKey = 'BOT_TOKEN_FILE'; SecretFile = 'bot_token'; IsBase = $true },
    @{ EnvKey = 'TELEGRAM_BOT_TOKEN'; FileEnvKey = 'TELEGRAM_BOT_TOKEN_FILE'; SecretFile = 'telegram_bot_token'; IsBase = $false },
    @{ EnvKey = 'OPENAI_API_KEY'; FileEnvKey = 'OPENAI_API_KEY_FILE'; SecretFile = 'openai_key'; IsBase = $true },
    @{ EnvKey = 'ANTHROPIC_API_KEY'; FileEnvKey = 'ANTHROPIC_API_KEY_FILE'; SecretFile = 'anthropic_key'; IsBase = $false },
    @{ EnvKey = 'ORCH_MASTER_KEY'; FileEnvKey = 'ORCH_MASTER_KEY_FILE'; SecretFile = 'master_key'; IsBase = $true },
    @{ EnvKey = 'BRAVE_API_KEY'; FileEnvKey = 'BRAVE_API_KEY_FILE'; SecretFile = 'brave_api_key'; IsBase = $false },
    @{ EnvKey = 'OPENWEATHER_API_KEY'; FileEnvKey = 'OPENWEATHER_API_KEY_FILE'; SecretFile = 'openweather_api_key'; IsBase = $false },
    @{ EnvKey = 'GITHUB_TOKEN'; FileEnvKey = 'GITHUB_TOKEN_FILE'; SecretFile = 'github_token'; IsBase = $false },
    @{ EnvKey = 'GITHUB_TOKEN_READ'; FileEnvKey = 'GITHUB_TOKEN_READ_FILE'; SecretFile = 'github_token_read'; IsBase = $false },
    @{ EnvKey = 'GITHUB_TOKEN_WRITE'; FileEnvKey = 'GITHUB_TOKEN_WRITE_FILE'; SecretFile = 'github_token_write'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_TOKEN'; FileEnvKey = 'SLACK_BOT_TOKEN_FILE'; SecretFile = 'slack_bot_token'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_TOKEN_READ'; FileEnvKey = 'SLACK_BOT_TOKEN_READ_FILE'; SecretFile = 'slack_bot_token_read'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_TOKEN_WRITE'; FileEnvKey = 'SLACK_BOT_TOKEN_WRITE_FILE'; SecretFile = 'slack_bot_token_write'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_API_TOKEN'; FileEnvKey = 'SLACK_BOT_API_TOKEN_FILE'; SecretFile = 'slack_bot_api_token'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_API_TOKEN_READ'; FileEnvKey = 'SLACK_BOT_API_TOKEN_READ_FILE'; SecretFile = 'slack_bot_api_token_read'; IsBase = $false },
    @{ EnvKey = 'SLACK_BOT_API_TOKEN_WRITE'; FileEnvKey = 'SLACK_BOT_API_TOKEN_WRITE_FILE'; SecretFile = 'slack_bot_api_token_write'; IsBase = $false },
    @{ EnvKey = 'NOTION_API_KEY'; FileEnvKey = 'NOTION_API_KEY_FILE'; SecretFile = 'notion_api_key'; IsBase = $false },
    @{ EnvKey = 'NOTION_API_KEY_READ'; FileEnvKey = 'NOTION_API_KEY_READ_FILE'; SecretFile = 'notion_api_key_read'; IsBase = $false },
    @{ EnvKey = 'NOTION_API_KEY_WRITE'; FileEnvKey = 'NOTION_API_KEY_WRITE_FILE'; SecretFile = 'notion_api_key_write'; IsBase = $false },
    @{ EnvKey = 'NOTION_BOT_API_TOKEN'; FileEnvKey = 'NOTION_BOT_API_TOKEN_FILE'; SecretFile = 'notion_bot_api_token'; IsBase = $false },
    @{ EnvKey = 'NOTION_BOT_API_TOKEN_READ'; FileEnvKey = 'NOTION_BOT_API_TOKEN_READ_FILE'; SecretFile = 'notion_bot_api_token_read'; IsBase = $false },
    @{ EnvKey = 'NOTION_BOT_API_TOKEN_WRITE'; FileEnvKey = 'NOTION_BOT_API_TOKEN_WRITE_FILE'; SecretFile = 'notion_bot_api_token_write'; IsBase = $false },
    @{ EnvKey = 'LINEAR_API_KEY'; FileEnvKey = 'LINEAR_API_KEY_FILE'; SecretFile = 'linear_api_key'; IsBase = $false },
    @{ EnvKey = 'LINEAR_API_KEY_READ'; FileEnvKey = 'LINEAR_API_KEY_READ_FILE'; SecretFile = 'linear_api_key_read'; IsBase = $false },
    @{ EnvKey = 'LINEAR_API_KEY_WRITE'; FileEnvKey = 'LINEAR_API_KEY_WRITE_FILE'; SecretFile = 'linear_api_key_write'; IsBase = $false },
    @{ EnvKey = 'DISCORD_BOT_TOKEN'; FileEnvKey = 'DISCORD_BOT_TOKEN_FILE'; SecretFile = 'discord_bot_token'; IsBase = $false },
    @{ EnvKey = 'DISCORD_BOT_TOKEN_READ'; FileEnvKey = 'DISCORD_BOT_TOKEN_READ_FILE'; SecretFile = 'discord_bot_token_read'; IsBase = $false },
    @{ EnvKey = 'DISCORD_BOT_TOKEN_WRITE'; FileEnvKey = 'DISCORD_BOT_TOKEN_WRITE_FILE'; SecretFile = 'discord_bot_token_write'; IsBase = $false },
    @{ EnvKey = 'X_API_BEARER_TOKEN'; FileEnvKey = 'X_API_BEARER_TOKEN_FILE'; SecretFile = 'x_api_bearer_token'; IsBase = $false },
    @{ EnvKey = 'X_API_BEARER_TOKEN_READ'; FileEnvKey = 'X_API_BEARER_TOKEN_READ_FILE'; SecretFile = 'x_api_bearer_token_read'; IsBase = $false },
    @{ EnvKey = 'X_API_BEARER_TOKEN_WRITE'; FileEnvKey = 'X_API_BEARER_TOKEN_WRITE_FILE'; SecretFile = 'x_api_bearer_token_write'; IsBase = $false },
    @{ EnvKey = 'TODOIST_API_KEY'; FileEnvKey = 'TODOIST_API_KEY_FILE'; SecretFile = 'todoist_api_key'; IsBase = $false },
    @{ EnvKey = 'TODOIST_API_KEY_READ'; FileEnvKey = 'TODOIST_API_KEY_READ_FILE'; SecretFile = 'todoist_api_key_read'; IsBase = $false },
    @{ EnvKey = 'TODOIST_API_KEY_WRITE'; FileEnvKey = 'TODOIST_API_KEY_WRITE_FILE'; SecretFile = 'todoist_api_key_write'; IsBase = $false },
    @{ EnvKey = 'JIRA_API_TOKEN'; FileEnvKey = 'JIRA_API_TOKEN_FILE'; SecretFile = 'jira_api_token'; IsBase = $false },
    @{ EnvKey = 'JIRA_API_TOKEN_READ'; FileEnvKey = 'JIRA_API_TOKEN_READ_FILE'; SecretFile = 'jira_api_token_read'; IsBase = $false },
    @{ EnvKey = 'JIRA_API_TOKEN_WRITE'; FileEnvKey = 'JIRA_API_TOKEN_WRITE_FILE'; SecretFile = 'jira_api_token_write'; IsBase = $false }
)

$botToken = Get-ValueOrEmpty -Map $parsed -Key 'BOT_TOKEN'
if ([string]::IsNullOrEmpty($botToken)) {
    $botToken = Get-ValueOrEmpty -Map $parsed -Key 'TELEGRAM_BOT_TOKEN'
}
if ([string]::IsNullOrEmpty($botToken)) {
    throw "error: missing BOT_TOKEN (or TELEGRAM_BOT_TOKEN) in $EnvFile"
}
Write-SecretFile -Directory $SecretsDir -FileName 'bot_token' -Value $botToken

$openai = Get-ValueOrEmpty -Map $parsed -Key 'OPENAI_API_KEY'
if ([string]::IsNullOrEmpty($openai)) {
    throw "error: missing OPENAI_API_KEY in $EnvFile (required by current docker-compose.yml)"
}
Write-SecretFile -Directory $SecretsDir -FileName 'openai_key' -Value $openai

$masterKey = Get-ValueOrEmpty -Map $parsed -Key 'ORCH_MASTER_KEY'
$masterKeyPath = Join-Path $SecretsDir 'master_key'
if (-not [string]::IsNullOrEmpty($masterKey)) {
    Write-SecretFile -Directory $SecretsDir -FileName 'master_key' -Value $masterKey
}
elseif (-not (Test-Path -LiteralPath $masterKeyPath)) {
    if ($NoGenerateMasterKey) {
        throw "error: missing ORCH_MASTER_KEY and $masterKeyPath not found"
    }

    $generated = Generate-MasterKey
    Write-SecretFile -Directory $SecretsDir -FileName 'master_key' -Value $generated
}

$extraEnvLines = New-Object System.Collections.Generic.List[string]
$extraSecretRefs = New-Object System.Collections.Generic.List[string]
$extraSecretDefs = New-Object System.Collections.Generic.List[string]

foreach ($map in $mappings) {
    $value = Get-ValueOrEmpty -Map $parsed -Key $map.EnvKey
    if ([string]::IsNullOrEmpty($value)) {
        continue
    }

    Write-SecretFile -Directory $SecretsDir -FileName $map.SecretFile -Value $value

    if (-not $map.IsBase) {
        $extraEnvLines.Add("      $($map.FileEnvKey): /run/secrets/$($map.SecretFile)")
        $extraSecretRefs.Add("      - $($map.SecretFile)")
        $extraSecretDefs.Add("  $($map.SecretFile):")
        $extraSecretDefs.Add("    file: $SecretsDir/$($map.SecretFile)")
    }
}

$output = New-Object System.Collections.Generic.List[string]
$output.Add("# Generated by scripts/sync-secrets-from-env.ps1")
$output.Add("# Do not put secret values here; this file only references /run/secrets/*")
$output.Add("services:")
$output.Add("  safepilot:")

if ($extraEnvLines.Count -gt 0) {
    $output.Add("    environment:")
    foreach ($line in $extraEnvLines) {
        $output.Add($line)
    }
}

if ($extraSecretRefs.Count -gt 0) {
    $output.Add("    secrets:")
    foreach ($line in $extraSecretRefs) {
        $output.Add($line)
    }
}

if ($extraSecretDefs.Count -gt 0) {
    $output.Add("secrets:")
    foreach ($line in $extraSecretDefs) {
        $output.Add($line)
    }
}

$encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($ComposeOverride, $output, $encoding)
Set-StrictPermissions -Path $ComposeOverride

Write-Host "Wrote secrets to: $SecretsDir"
Write-Host "Wrote compose override: $ComposeOverride"
Write-Host "Next: docker compose -f docker-compose.yml -f $ComposeOverride up -d"
