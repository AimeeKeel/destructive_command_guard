#!/usr/bin/env pwsh
# Tests Configure-ClaudeHook (and the shared matcher-aware hook merge) from
# install.ps1 by dot-sourcing it with -LoadFunctionsOnly (so the install body
# does not run). Runnable on any OS with PowerShell. Covers: create, merge with a
# coexisting Bash-only hook, legacy/wrong-matcher migration, idempotency,
# UTF-8-no-BOM, refuse-invalid-JSON, skip, and CLAUDE_CONFIG_DIR install/uninstall
# and predecessor migration. The functions take a -HomeDir
# param so a temp home can be injected ($HOME is read-only in PowerShell).

param([string]$InstallScript = '')

$ErrorActionPreference = 'Stop'
$savedClaudeConfigDir = $env:CLAUDE_CONFIG_DIR
$env:CLAUDE_CONFIG_DIR = $null

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$installPs1 = if ($InstallScript) { $InstallScript } else { Join-Path $repoRoot 'install.ps1' }
. $installPs1 -LoadFunctionsOnly

$script:failures = 0
function Check([bool]$cond, [string]$msg) {
    if ($cond) { Write-Host "  ok: $msg" } else { Write-Host "  FAIL: $msg" -ForegroundColor Red; $script:failures++ }
}
function New-TempHome {
    $h = Join-Path ([System.IO.Path]::GetTempPath()) ("dcg_claude_test_" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $h | Out-Null
    $h
}
function Test-NoBom([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    -not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

$dcgPath = 'C:\Users\me\.local\bin\dcg.exe'
try {
    $env:CLAUDE_CONFIG_DIR = $null

# --- Test 1: create + idempotent + no BOM ---
Write-Host "Test 1: create / idempotent / no-BOM"
$h1 = New-TempHome
try {
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status -eq 'created') "first run returns 'created' (got '$status')"
    $settings = Join-Path $h1 '.claude/settings.json'
    Check (Test-Path $settings) "settings.json created"
    Check (Test-NoBom $settings) "file has no UTF-8 BOM"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "matcher covers Bash, PowerShell, and Monitor scripts"
    Check ($p.hooks.PreToolUse[0].hooks[0].command -eq "& '$dcgPath'") "dcg command uses a PowerShell-safe absolute path"
    Check ($p.hooks.PreToolUse[0].hooks[0].shell -eq 'powershell') "hook shell is explicitly PowerShell"
    Check (Test-DcgHookCommand $p.hooks.PreToolUse[0].hooks[0]) "wrapped command is recognized as dcg"
    $before = Get-Content -Raw $settings
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h1
    Check ($status2 -eq 'already') "second run returns 'already' (got '$status2')"
    Check ((Get-Content -Raw $settings) -eq $before) "current settings stay byte-for-byte unchanged"
} finally { Remove-Item -Recurse -Force $h1 -ErrorAction SilentlyContinue }

# --- Test 2: preserve a coexisting Bash-only hook without widening it ---
Write-Host "Test 2: preserve coexisting Bash-only hooks"
$h2 = New-TempHome
try {
    $cdir = Join-Path $h2 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse  = @([ordered]@{ matcher = 'Bash'; hooks = @([ordered]@{ type = 'command'; command = 'other-tool' }) })
            PostToolUse = @([ordered]@{ matcher = 'Write'; hooks = @([ordered]@{ type = 'command'; command = 'formatter' }) })
        }
        otherSetting = 'keep-me'
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h2
    Check ($status -eq 'merged') "returns 'merged' (got '$status')"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $shells = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Bash|PowerShell|Monitor' })[0]
    $bash = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Bash' })[0]
    Check ($shells.hooks[0].command -eq "& '$dcgPath'") "dcg hoisted first in combined shell matcher"
    Check ((@($bash.hooks | ForEach-Object { $_.command })) -contains 'other-tool') "coexisting Bash hook preserved under Bash only"
    Check (-not ((@($shells.hooks | ForEach-Object { $_.command })) -contains 'other-tool')) "Bash-only hook was not widened to PowerShell or Monitor"
    Check ($p.hooks.PostToolUse[0].hooks[0].command -eq 'formatter') "PostToolUse preserved"
    Check ($p.otherSetting -eq 'keep-me') "unrelated root setting preserved"
    Check (Test-NoBom (Join-Path $cdir 'settings.json')) "merged file has no BOM"
} finally { Remove-Item -Recurse -Force $h2 -ErrorAction SilentlyContinue }

# --- Test 3: migrate legacy dcg entry without duplicating or losing siblings ---
Write-Host "Test 3: migrate both legacy shell matchers (#226, #529)"
foreach ($legacyMatcher in @('Bash', 'Bash|PowerShell')) {
    $h3 = New-TempHome
    try {
        $cdir = Join-Path $h3 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
        $settings = Join-Path $cdir 'settings.json'
        $existing = [ordered]@{
            hooks = [ordered]@{
                PreToolUse = @([ordered]@{
                    matcher = $legacyMatcher
                    hooks = @(
                        [ordered]@{ type = 'command'; command = $dcgPath },
                        [ordered]@{ type = 'command'; command = 'keep-original-scope'; timeout = 7 }
                    )
                    customField = 'keep-metadata'
                })
            }
        }
        $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
        $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h3
        Check ($status -eq 'merged') "$legacyMatcher install returns 'merged' (got '$status')"
        $p = Get-Content -Raw $settings | ConvertFrom-Json
        $allDcg = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
        $legacy = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq $legacyMatcher })[0]
        Check ($allDcg.Count -eq 1) "exactly one dcg hook remains after $legacyMatcher migration"
        Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "migrated matcher includes Monitor"
        Check ($legacy.hooks[0].command -eq 'keep-original-scope') "legacy sibling stays under $legacyMatcher"
        Check ($legacy.hooks[0].timeout -eq 7) "legacy sibling hook metadata preserved"
        Check ($legacy.customField -eq 'keep-metadata') "legacy entry metadata preserved"
        $before = Get-Content -Raw $settings
        $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h3
        Check ($status2 -eq 'already') "migrated $legacyMatcher registration is idempotent"
        Check ((Get-Content -Raw $settings) -eq $before) "migrated settings stay byte-for-byte unchanged"
    } finally { Remove-Item -Recurse -Force $h3 -ErrorAction SilentlyContinue }
}

# --- Test 4: refuse invalid JSON (leave untouched) ---
Write-Host "Test 4: refuse invalid JSON"
$h4 = New-TempHome
try {
    $cdir = Join-Path $h4 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    Set-Content -Path (Join-Path $cdir 'settings.json') -Value '{ not valid json'
    $threw = $false
    try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h4 } catch { $threw = $true }
    Check $threw "throws on invalid JSON"
    Check ((Get-Content -Raw (Join-Path $cdir 'settings.json')).Trim() -eq '{ not valid json') "invalid JSON left unchanged"
} finally { Remove-Item -Recurse -Force $h4 -ErrorAction SilentlyContinue }

# --- Test 5: skip when not detected and not forced ---
# Clear PATH so `claude` is not discoverable (this CI/dev box may have it on PATH);
# with ~/.claude absent and no -Force the result must be 'skipped'.
Write-Host "Test 5: skip when ~/.claude absent and not -Force"
$h5 = New-TempHome
$savedPath = $env:PATH
try {
    $env:PATH = ''
    $status = Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h5
    Check ($status -eq 'skipped') "returns 'skipped' (got '$status')"
} finally { $env:PATH = $savedPath; Remove-Item -Recurse -Force $h5 -ErrorAction SilentlyContinue }

# --- Test 6: escaped apostrophes round-trip and extra async metadata is repaired ---
Write-Host "Test 6: escaped apostrophe path / reject async hook"
$h6 = New-TempHome
try {
    $apostrophePath = "C:\Users\O'Brien\.local\bin\dcg.exe"
    $escapedPath = $apostrophePath.Replace("'", "''")
    $cdir = Join-Path $h6 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @([ordered]@{
                matcher = 'Bash|PowerShell|Monitor'
                hooks = @([ordered]@{
                    type = 'command'
                    command = "& '$escapedPath'"
                    shell = 'powershell'
                    async = $true
                })
            })
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $cdir 'settings.json')
    Check (Test-DcgHookCommand $existing.hooks.PreToolUse[0].hooks[0]) "escaped apostrophe command is recognized"
    $status = Configure-ClaudeHook -DcgPath $apostrophePath -Force -HomeDir $h6
    Check ($status -eq 'merged') "async dcg hook is replaced instead of accepted as current"
    $p = Get-Content -Raw (Join-Path $cdir 'settings.json') | ConvertFrom-Json
    $hook = $p.hooks.PreToolUse[0].hooks[0]
    Check ($hook.command -eq "& '$escapedPath'") "escaped path survives JSON round-trip"
    Check ($null -eq $hook.PSObject.Properties['async']) "blocking hook has no async metadata"
    $status2 = Configure-ClaudeHook -DcgPath $apostrophePath -Force -HomeDir $h6
    Check ($status2 -eq 'already') "repaired escaped-path hook is idempotent"
} finally { Remove-Item -Recurse -Force $h6 -ErrorAction SilentlyContinue }

# --- Test 7: malformed scalar inner hooks are rejected without mutation ---
Write-Host "Test 7: reject scalar inner hooks"
$h7 = New-TempHome
try {
    $cdir = Join-Path $h7 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $original = '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell","hooks":{"type":"command","command":"dcg"}}]}}'
    Set-Content -Path $settings -Value $original -NoNewline
    $threw = $false
    try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h7 } catch { $threw = $true }
    Check $threw "throws on scalar matcher hooks"
    Check ((Get-Content -Raw $settings) -eq $original) "malformed settings are left byte-for-byte unchanged"
} finally { Remove-Item -Recurse -Force $h7 -ErrorAction SilentlyContinue }

# --- Test 8: repair dcg installed beneath an unrelated matcher ---
Write-Host "Test 8: repair wrong-matcher dcg hook"
$h8 = New-TempHome
try {
    $cdir = Join-Path $h8 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @(
                [ordered]@{
                    matcher = 'Write'
                    hooks = @(
                        [ordered]@{ type = 'command'; command = $dcgPath },
                        [ordered]@{ type = 'command'; command = 'keep-write-hook' }
                    )
                }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h8
    Check ($status -eq 'merged') "wrong-matcher install returns 'merged' (got '$status')"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $allDcg = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
    $write = @($p.hooks.PreToolUse | Where-Object { $_.matcher -eq 'Write' })[0]
    Check ($allDcg.Count -eq 1) "exactly one dcg hook remains after wrong-matcher repair"
    Check ($p.hooks.PreToolUse[0].matcher -eq 'Bash|PowerShell|Monitor') "repaired hook uses canonical matcher"
    Check ($write.hooks[0].command -eq 'keep-write-hook') "coexisting wrong-matcher hook preserved"
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h8
    Check ($status2 -eq 'already') "wrong-matcher repair is idempotent"
} finally { Remove-Item -Recurse -Force $h8 -ErrorAction SilentlyContinue }

# --- Test 9: one current hook replaces duplicates under both legacy matchers ---
Write-Host "Test 9: collapse mixed current and legacy dcg registrations (#529)"
$h9 = New-TempHome
try {
    $cdir = Join-Path $h9 '.claude'; New-Item -ItemType Directory -Path $cdir | Out-Null
    $settings = Join-Path $cdir 'settings.json'
    $existing = [ordered]@{
        hooks = [ordered]@{
            PreToolUse = @(
                [ordered]@{
                    matcher = 'Bash|PowerShell|Monitor'
                    hooks = @([ordered]@{ type = 'command'; command = "& '$dcgPath'"; shell = 'powershell' })
                },
                [ordered]@{
                    matcher = 'Bash|PowerShell'
                    customField = 'keep-shells-metadata'
                    hooks = @(
                        [ordered]@{ type = 'command'; command = 'C:\old\dcg.exe' },
                        [ordered]@{ type = 'command'; command = 'keep-shells' }
                    )
                },
                [ordered]@{
                    matcher = 'Bash'
                    hooks = @([ordered]@{ type = 'command'; command = $dcgPath })
                },
                [ordered]@{
                    matcher = 'Monitor'
                    customField = 'keep-monitor-metadata'
                    hooks = @([ordered]@{ type = 'command'; command = 'monitor-audit' })
                }
            )
        }
    }
    $existing | ConvertTo-Json -Depth 20 | Set-Content -Path $settings
    $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h9
    Check ($status -eq 'merged') "duplicates prevent a false 'already' result"
    $p = Get-Content -Raw $settings | ConvertFrom-Json
    $entries = @($p.hooks.PreToolUse)
    $allDcg = @($entries | ForEach-Object { $_.hooks } | Where-Object { Test-DcgHookCommand $_ })
    Check ($allDcg.Count -eq 1) "exactly one dcg hook remains across all matcher generations"
    Check ($entries.Count -eq 3) "emptied legacy matcher is removed"
    Check ($entries[0].matcher -eq 'Bash|PowerShell|Monitor') "canonical entry stays first"
    Check ($entries[0].hooks[0].command -eq "& '$dcgPath'") "canonical hook uses the current path"
    Check ($entries[1].matcher -eq 'Bash|PowerShell') "legacy sibling scope is preserved"
    Check ($entries[1].hooks[0].command -eq 'keep-shells') "legacy sibling command is preserved"
    Check ($entries[1].customField -eq 'keep-shells-metadata') "legacy sibling entry metadata is preserved"
    Check ($entries[2].matcher -eq 'Monitor') "unrelated Monitor-only hook is not widened"
    Check ($entries[2].hooks[0].command -eq 'monitor-audit') "unrelated Monitor-only hook is preserved"
    Check ($entries[2].customField -eq 'keep-monitor-metadata') "Monitor-only entry metadata is preserved"
    $status2 = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $h9
    Check ($status2 -eq 'already') "mixed matcher migration is idempotent"
} finally { Remove-Item -Recurse -Force $h9 -ErrorAction SilentlyContinue }

# Active configuration overrides HomeDir's default and preserves settings.
$activeHome = New-TempHome
Push-Location $activeHome
try {
    foreach ($form in @('absolute', 'relative', 'tilde', 'home', 'empty')) {
        switch ($form) {
            'absolute' { $env:CLAUDE_CONFIG_DIR = Join-Path $activeHome 'absolute config'; $expected = $env:CLAUDE_CONFIG_DIR }
            'relative' { $env:CLAUDE_CONFIG_DIR = 'relative config'; $expected = Join-Path (Get-Location).Path 'relative config' }
            'tilde' { $env:CLAUDE_CONFIG_DIR = '~/alternate config'; $expected = Join-Path $activeHome 'alternate config' }
            'home' { $env:CLAUDE_CONFIG_DIR = '~'; $expected = $activeHome }
            'empty' { $env:CLAUDE_CONFIG_DIR = ''; $expected = Join-Path $activeHome '.claude' }
        }
        Check ((Get-ClaudeConfigDir -HomeDir $activeHome) -eq $expected) "resolver: $form"
        New-Item -ItemType Directory -Force $expected | Out-Null
        $settings = Join-Path $expected 'settings.json'
        [System.IO.File]::WriteAllText($settings, '{"theme":"dark"}')
        $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $activeHome
        Check ($status -eq 'merged') "active configuration installed: $form"
        $value = Get-Content -Raw $settings | ConvertFrom-Json
        Check ($value.theme -eq 'dark') "settings preserved: $form"
        Check (@($value.hooks.PreToolUse).Count -eq 1) "hook present: $form"
    }
} finally { Pop-Location; $env:CLAUDE_CONFIG_DIR = $savedClaudeConfigDir }

# --- Test 10: every supported selector applies to installation and removal ---
foreach ($selection in @('unset', 'empty', 'absolute', 'tilde', 'tilde-backslash', 'home', 'relative')) {
    Write-Host "Test 10: CLAUDE_CONFIG_DIR $selection install / migration / uninstall"
    $h10 = New-TempHome
    Push-Location $h10
    try {
        $defaultDir = Join-Path $h10 '.claude'
        $defaultSettings = Join-Path $defaultDir 'settings.json'
        New-Item -ItemType Directory -Path $defaultDir | Out-Null
        $defaultConfig = '{"model":"default-model","hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell|Monitor","hooks":[{"type":"command","command":"dcg"}]}]}}'
        Set-Content -LiteralPath $defaultSettings -Value $defaultConfig -NoNewline
        switch ($selection) {
            'unset' { $env:CLAUDE_CONFIG_DIR = $null; $expectedDir = $defaultDir }
            'empty' { $env:CLAUDE_CONFIG_DIR = ''; $expectedDir = $defaultDir }
            'absolute' { $expectedDir = Join-Path $h10 'active config [work]'; $env:CLAUDE_CONFIG_DIR = $expectedDir }
            'tilde' { $env:CLAUDE_CONFIG_DIR = '~/active config'; $expectedDir = Join-Path $h10 'active config' }
            'tilde-backslash' { $env:CLAUDE_CONFIG_DIR = '~\active config'; $expectedDir = Join-Path $h10 'active config' }
            'home' { $env:CLAUDE_CONFIG_DIR = '~'; $expectedDir = $h10 }
            'relative' { $env:CLAUDE_CONFIG_DIR = 'active config'; $expectedDir = Join-Path $h10 'active config' }
        }
        $settings = Join-Path $expectedDir 'settings.json'
        Check ((Get-ClaudeConfigDir -HomeDir $h10) -eq $expectedDir) "$selection resolves the active directory"
        New-Item -ItemType Directory -Force -Path $expectedDir | Out-Null
        @{
            model = 'active-model'
            permissions = @{ allow = @('Read') }
            hooks = @{
                PreToolUse = @(@{ matcher = 'Bash'; hooks = @(
                    @{ type = 'command'; command = 'keep-active-hook' },
                    @{ type = 'command'; command = 'python3 legacy/git_safety_guard.py' }
                ) })
                PostToolUse = @(@{ matcher = 'Write'; hooks = @(@{ type = 'command'; command = 'keep-after-hook' }) })
            }
        } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $settings
        Check (Remove-DcgPredecessor -HomeDir $h10) "$selection migrates the active predecessor"
        $migrated = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        $migratedCommands = @($migrated.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
        Check (-not ($migratedCommands -match 'git_safety_guard')) "$selection removes the active predecessor only"
        $status = Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h10
        Check ($status -eq 'merged') "$selection installs in the selected settings"
        $p = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        Check ($p.model -eq 'active-model') "$selection preserves the active model"
        Check ($p.permissions.allow[0] -eq 'Read') "$selection preserves permissions"
        $commands = @($p.hooks.PreToolUse | ForEach-Object { $_.hooks } | ForEach-Object { $_.command })
        Check ($commands -contains 'keep-active-hook') "$selection preserves the third-party hook"
        Check ($p.hooks.PostToolUse[0].hooks[0].command -eq 'keep-after-hook') "$selection preserves other hook events"
        Check (Test-NoBom $settings) "$selection writes valid UTF-8 without a BOM"
        $installed = Get-Content -Raw -LiteralPath $settings
        Check ((Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h10) -eq 'already') "$selection installation is idempotent"
        Check ((Get-Content -Raw -LiteralPath $settings) -eq $installed) "$selection second install leaves bytes unchanged"
        if ($settings -ne $defaultSettings) {
            Check ((Get-Content -Raw -LiteralPath $defaultSettings) -eq $defaultConfig) "$selection install and migration preserve the default settings byte-for-byte"
        }

        # Load the uninstaller in its own scope to exercise its independently
        # shipped resolver without replacing the installer functions above.
        $removed = & {
            . (Join-Path $repoRoot 'uninstall.ps1') -LoadFunctionsOnly
            Check ((Get-ClaudeConfigDir -HomeDir $h10) -eq $expectedDir) "$selection uninstall resolves the same directory"
            Unconfigure-ClaudeHook -HomeDir $h10
        }
        Check ($removed -eq $true) "$selection uninstall removes the active hook"
        $after = Get-Content -Raw -LiteralPath $settings | ConvertFrom-Json
        $remaining = @($after.hooks.PreToolUse | ForEach-Object { $_.hooks })
        Check (@($remaining | Where-Object { Test-DcgHookCommand $_ }).Count -eq 0) "$selection uninstall removes all active dcg entries"
        Check ($remaining[0].command -eq 'keep-active-hook') "$selection uninstall preserves the third-party hook"
        Check ($after.model -eq 'active-model') "$selection uninstall preserves other settings"
        if ($settings -ne $defaultSettings) {
            Check ((Get-Content -Raw -LiteralPath $defaultSettings) -eq $defaultConfig) "$selection uninstall leaves the default protected settings unchanged"
        }
    } finally {
        Pop-Location
        Remove-Item -Recurse -Force -LiteralPath $h10 -ErrorAction SilentlyContinue
    }
}

Write-Host 'Test 11: an explicit directory creates a fresh installation with an empty PATH and without -Force'
$h11 = New-TempHome
$savedPath11 = $env:PATH
try {
    $env:PATH = ''
    $env:CLAUDE_CONFIG_DIR = Join-Path $h11 'new/active config'
    $freshSettings = Join-Path $env:CLAUDE_CONFIG_DIR 'settings.json'
    Check ((Configure-ClaudeHook -DcgPath $dcgPath -HomeDir $h11) -eq 'created') 'fresh selected config is installed automatically'
    Check (Test-Path -LiteralPath $freshSettings) 'selected directory and settings are created'
    Check (-not (Test-Path -LiteralPath (Join-Path $h11 '.claude'))) 'default directory is not created'
} finally {
    $env:PATH = $savedPath11
    Remove-Item -Recurse -Force -LiteralPath $h11 -ErrorAction SilentlyContinue
}

# #582: all four callers share the preservation and publication path. Keep
# these fixtures here so the existing CI-discovered suite exercises that path
# through the real integration functions, without running the installer body.
$env:CLAUDE_CONFIG_DIR = $null
function Write-PreservationSettings([string]$Path, [object]$Settings) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $json = ConvertTo-Json -InputObject $Settings -Depth 100 -Compress
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding $false))
}
function Get-PreservationBytes([string]$Path) {
    [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))
}
function Invoke-PreservationIntegration([object]$Agent, [string]$FixtureHome) {
    $arguments = @{ DcgPath = $dcgPath; HomeDir = $FixtureHome }
    if ($Agent.Name -ne 'Codex') { $arguments.Force = $true }
    & $Agent.Configure @arguments
}
$preservationAgents = @(
    [pscustomobject]@{ Name = 'Claude'; Configure = 'Configure-ClaudeHook'; Path = '.claude/settings.json'; Event = 'PreToolUse'; Matcher = 'Bash|PowerShell|Monitor'; Command = "& '$dcgPath'"; Shell = 'powershell' },
    [pscustomobject]@{ Name = 'Gemini'; Configure = 'Configure-GeminiHook'; Path = '.gemini/settings.json'; Event = 'BeforeTool'; Matcher = 'run_shell_command'; Command = $dcgPath; Shell = $null },
    [pscustomobject]@{ Name = 'Posit'; Configure = 'Configure-PositAssistantHook'; Path = '.posit/assistant/settings.json'; Event = 'PreToolUse'; Matcher = 'bash|powershell'; Command = ('"' + $dcgPath + '"'); Shell = $null },
    [pscustomobject]@{ Name = 'Codex'; Configure = 'Configure-CodexHook'; Path = '.codex/hooks.json'; Event = 'PreToolUse'; Matcher = 'Bash'; Command = $dcgPath; Shell = $null }
)
foreach ($agent in $preservationAgents) {
    Write-Host "Test 12: $($agent.Name) preserves operator fields across repair and repeat updates (#582)"
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome $agent.Path
        $operatorMessage = 'Checking ' + [char]0x5B89 + [char]0x5168 + ' caf' + [char]0xE9
        $oldHook = [ordered]@{
            type = 'prompt'; command = '"C:\old installation\dcg.exe"'; shell = 'foreign-shell'
            name = 'operator guard'; timeout = 15; onFailure = 'block'; statusMessage = $operatorMessage
            async = $false; optional = $null; disabled = $false; retries = 0; empty = @()
            future = [ordered]@{ policy = 'Strict'; values = @($null, $false, 0, @()); emptyObject = [ordered]@{} }
        }
        $legacyMatcher = if ($agent.Name -eq 'Claude') { 'Bash|PowerShell' } else { 'Write' }
        $eventHooks = [ordered]@{
            SessionStart = @(@{ hooks = @(@{ type = 'command'; command = 'other-event' }) })
        }
        $eventHooks[$agent.Event] = @(
            @{ matcher = $legacyMatcher; customField = 'legacy metadata'; hooks = @($oldHook, @{ type = 'command'; command = 'legacy-audit'; timeout = 7 }) },
            @{ matcher = $agent.Matcher; customField = 'canonical metadata'; hooks = @(@{ type = 'command'; command = 'canonical-audit' }) },
            @{ matcher = 'Read'; hooks = @(@{ type = 'command'; command = 'dcg-helper' }, @{ type = 'command'; command = @('dcg') }) }
        )
        Write-PreservationSettings $settings ([ordered]@{ theme = 'dark'; hooks = $eventHooks })
        $originalBytes = Get-PreservationBytes $settings
        $status = Invoke-PreservationIntegration $agent $fixtureHome
        Check ($status -eq 'merged') "$($agent.Name): stale quoted path is repaired"
        $backups = @(Get-ChildItem -LiteralPath (Split-Path -Parent $settings) -Filter ((Split-Path -Leaf $settings) + '.bak.*') -File)
        Check ($backups.Count -eq 1) "$($agent.Name): repair keeps one recovery backup"
        Check ($backups.Count -eq 1 -and (Get-PreservationBytes $backups[0].FullName) -ceq $originalBytes) "$($agent.Name): recovery backup contains exact previous bytes"
        $parsed = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
        $entries = @($parsed.hooks.($agent.Event))
        $hook = $entries[0].hooks[0]
        Check ($entries[0].matcher -ceq $agent.Matcher) "$($agent.Name): canonical matcher is first"
        Check ($hook.type -ceq 'command' -and $hook.command -ceq $agent.Command) "$($agent.Name): only DCG command identity is refreshed"
        if ($null -eq $agent.Shell) {
            Check ($null -eq $hook.PSObject.Properties['shell']) "$($agent.Name): foreign shell is removed"
        } else {
            Check ($hook.shell -ceq $agent.Shell) "$($agent.Name): platform shell is refreshed"
        }
        Check ($hook.timeout -eq 15 -and $hook.onFailure -ceq 'block') "$($agent.Name): timeout and fail-closed behavior survive"
        Check ($hook.name -ceq 'operator guard' -and $hook.statusMessage -ceq $operatorMessage) "$($agent.Name): operator name and non-ASCII status message survive"
        Check ($null -ne $hook.PSObject.Properties['optional'] -and $null -eq $hook.optional) "$($agent.Name): explicit null survives"
        Check ($hook.async -is [bool] -and -not $hook.async -and $hook.disabled -is [bool] -and -not $hook.disabled) "$($agent.Name): false values survive as booleans"
        Check (($hook.retries -is [int] -or $hook.retries -is [long]) -and $hook.retries -eq 0) "$($agent.Name): zero survives as a number"
        Check ($hook.empty -is [array] -and $hook.empty.Count -eq 0) "$($agent.Name): empty array survives"
        Check ($hook.future.policy -ceq 'Strict' -and $hook.future.values.Count -eq 4 -and $hook.future.values[3] -is [array]) "$($agent.Name): nested operator JSON survives"
        Check ($entries[0].customField -ceq 'canonical metadata' -and $entries[0].hooks[1].command -ceq 'canonical-audit') "$($agent.Name): canonical entry metadata and sibling survive"
        $legacy = @($entries | Where-Object { $_.matcher -ceq $legacyMatcher })[0]
        Check ($legacy.customField -ceq 'legacy metadata' -and $legacy.hooks.Count -eq 1 -and $legacy.hooks[0].timeout -eq 7) "$($agent.Name): unrelated legacy hook keeps its scope and metadata"
        Check ($parsed.theme -ceq 'dark' -and $parsed.hooks.SessionStart[0].hooks[0].command -ceq 'other-event') "$($agent.Name): unrelated settings and events survive"
        Check ($entries[2].hooks[0].command -ceq 'dcg-helper') "$($agent.Name): lookalike hook survives"
        Check ($entries[2].hooks.Count -eq 2 -and $entries[2].hooks[1].command -is [array] -and $entries[2].hooks[1].command[0] -ceq 'dcg') "$($agent.Name): opaque non-string command is not treated as DCG"
        $before = Get-PreservationBytes $settings
        Check ((Invoke-PreservationIntegration $agent $fixtureHome) -eq 'already') "$($agent.Name): operator metadata does not mark the repaired hook stale"
        Check ((Get-PreservationBytes $settings) -ceq $before) "$($agent.Name): repeated update leaves exact bytes unchanged"
        Check (@(Get-ChildItem -LiteralPath (Split-Path -Parent $settings) -Filter ((Split-Path -Leaf $settings) + '.bak.*') -File).Count -eq 1) "$($agent.Name): repeated update creates no extra backup"
        Check (Test-NoBom $settings) "$($agent.Name): repaired file remains UTF-8 without BOM"
    } finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }
}

Write-Host 'Test 13: Gemini and Posit supply defaults only when absent (#582)'
foreach ($agent in @($preservationAgents | Where-Object { $_.Name -in @('Gemini', 'Posit') })) {
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome $agent.Path
        $events = @{}
        $events[$agent.Event] = @(@{ matcher = $agent.Matcher; hooks = @(@{ type = 'command'; command = 'C:\old\dcg.exe'; onFailure = 'block' }) })
        Write-PreservationSettings $settings @{ hooks = $events }
        Check ((Invoke-PreservationIntegration $agent $fixtureHome) -eq 'merged') "$($agent.Name): missing default fields are repaired"
        $parsed = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
        $hook = $parsed.hooks.($agent.Event)[0].hooks[0]
        $expectedTimeout = if ($agent.Name -eq 'Gemini') { 5000 } else { 10 }
        Check ($hook.timeout -eq $expectedTimeout -and $hook.onFailure -ceq 'block') "$($agent.Name): timeout default fills the gap without dropping onFailure"
        if ($agent.Name -eq 'Gemini') { Check ($hook.name -ceq 'dcg') 'Gemini: missing name gets its default' }
        $before = Get-PreservationBytes $settings
        Check ((Invoke-PreservationIntegration $agent $fixtureHome) -eq 'already') "$($agent.Name): default completion is idempotent"
        Check ((Get-PreservationBytes $settings) -ceq $before) "$($agent.Name): repeat default completion is byte-identical"
    } finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }
}

Write-Host 'Test 14: compatible duplicate metadata is combined structurally (#582)'
$fixtureHome = New-TempHome
try {
    $settings = Join-Path $fixtureHome '.claude/settings.json'
    Write-PreservationSettings $settings @{ hooks = @{ PreToolUse = @(
        @{ matcher = 'Bash|PowerShell|Monitor'; customField = 'keep'; hooks = @(@{ type = 'command'; command = "& '$dcgPath'"; shell = 'powershell'; timeout = 15; future = [ordered]@{ first = $false; second = @($null, 0, @()) } }) },
        @{ matcher = 'Bash'; hooks = @(@{ type = 'command'; command = 'dcg'; onFailure = 'block'; future = [ordered]@{ second = @($null, 0, @()); first = $false } }) },
        @{ matcher = 'Write'; hooks = @(@{ type = 'command'; command = 'C:\old\dcg.exe'; statusMessage = 'operator'; async = $false }, @{ command = 'write-audit'; timeout = 9 }) }
    ) } }
    Check ((Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome) -eq 'merged') 'compatible duplicates merge despite nested object key order'
    $parsed = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
    $entries = @($parsed.hooks.PreToolUse)
    $hook = $entries[0].hooks[0]
    Check ($entries.Count -eq 2 -and $entries[0].customField -ceq 'keep') 'duplicate registrations collapse and canonical metadata survives'
    Check ($hook.timeout -eq 15 -and $hook.onFailure -ceq 'block' -and $hook.statusMessage -ceq 'operator') 'fields from every duplicate survive together'
    Check ($hook.async -is [bool] -and -not $hook.async -and $hook.future.second.Count -eq 3) 'false and nested arrays survive duplicate consolidation'
    Check ($entries[1].matcher -ceq 'Write' -and $entries[1].hooks[0].command -ceq 'write-audit') 'wrong-matcher sibling retains its scope'
    $before = Get-PreservationBytes $settings
    Check ((Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome) -eq 'already') 'merged duplicates settle after one repair'
    Check ((Get-PreservationBytes $settings) -ceq $before) 'settled duplicate merge leaves exact bytes unchanged'
    # Claude tool names are case-sensitive even though PowerShell -eq is not.
    $parsed.hooks.PreToolUse[0].matcher = 'bash|powershell|monitor'
    Write-PreservationSettings $settings $parsed
    Check ((Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome) -eq 'merged') 'lowercase matcher with the current command still requires repair'
    $repaired = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
    Check ($repaired.hooks.PreToolUse[0].matcher -ceq 'Bash|PowerShell|Monitor') 'repaired matcher uses the exact Claude tool-name case'
    Check ($repaired.hooks.PreToolUse[0].hooks[0].onFailure -ceq 'block') 'case-sensitive matcher repair preserves the blocking policy'
} finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }

Write-Host 'Test 15: conflicting duplicate JSON values never replace valid settings (#582)'
$conflicts = @(
    @('failure policy', '"block"', '"continue"'), @('case', '"block"', '"Block"'),
    @('numeric type', 'false', '0'), @('null', 'null', '0'), @('array shape', '[]', '{}'),
    @('nested value', '{"policy":"Strict"}', '{"policy":"strict"}'),
    @('property case', '{"Name":1}', '{"name":1}'), @('array order', '[1,2]', '[2,1]')
)
foreach ($conflict in $conflicts) {
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome '.claude/settings.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $settings) | Out-Null
        $conflictKey = if ($conflict[0] -eq 'failure policy') { 'onFailure' } else { 'operatorField' }
        $policy = if ($conflictKey -eq 'onFailure') { '' } else { ',"onFailure":"block"' }
        $original = '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell|Monitor","hooks":[{"type":"command","command":"dcg"' + $policy + ',"' + $conflictKey + '":' + $conflict[1] + '}]},{"matcher":"Write","hooks":[{"type":"command","command":"/old/dcg","' + $conflictKey + '":' + $conflict[2] + '}]}]}}'
        [System.IO.File]::WriteAllText($settings, $original)
        $before = Get-PreservationBytes $settings
        $threw = $false
        try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome | Out-Null } catch { $threw = $true }
        Check $threw "duplicate $($conflict[0]) conflict is reported"
        Check ((Get-PreservationBytes $settings) -ceq $before) "duplicate $($conflict[0]) conflict leaves original bytes unchanged"
    } finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }
}

Write-Host 'Test 16: malformed owned shapes remain untouched (#582)'
foreach ($original in @(
    '[]', '{"hooks":[]}', '{"hooks":{"PreToolUse":{}}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell|Monitor","hooks":{}}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell","hooks":42}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell|Monitor","hooks":null}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash|PowerShell","hooks":null}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg","onFailure":"block","async":"true"}]}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg","onFailure":"block","async":1}]}]}}',
    '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg","onFailure":"block","async":null}]}]}}'
)) {
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome '.claude/settings.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $settings) | Out-Null
        [System.IO.File]::WriteAllText($settings, $original)
        $before = Get-PreservationBytes $settings
        $threw = $false
        try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome | Out-Null } catch { $threw = $true }
        Check $threw 'malformed hook shape is rejected'
        Check ((Get-PreservationBytes $settings) -ceq $before) 'malformed hook shape is preserved byte-for-byte'
    } finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }
}

Write-Host 'Test 17: nested operator JSON is lossless; excessive depth is rejected (#582)'
foreach ($depth in @(35, 110)) {
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome '.claude/settings.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $settings) | Out-Null
        $nested = ('{"child":' * $depth) + '{"policy":"Strict","values":[null,false,0,[]]}' + ('}' * $depth)
        $original = '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"dcg","timeout":15,"onFailure":"block","future":' + $nested + '}]}]}}'
        [System.IO.File]::WriteAllText($settings, $original)
        $unixPermissions = [Environment]::OSVersion.Platform -eq [PlatformID]::Unix
        if ($unixPermissions) { & chmod 600 $settings }
        $before = Get-PreservationBytes $settings
        $threw = $false
        try { $status = Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome } catch { $threw = $true }
        if ($depth -eq 35) {
            Check (-not $threw -and $status -eq 'merged') 'operator JSON deeper than twenty levels is repaired losslessly'
            $parsed = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
            $hook = $parsed.hooks.PreToolUse[0].hooks[0]
            $leaf = $hook.future
            for ($level = 0; $level -lt $depth; $level++) { $leaf = $leaf.child }
            Check ($leaf.policy -ceq 'Strict' -and $leaf.values.Count -eq 4 -and $leaf.values[3] -is [array]) 'deepest object and array retain their exact JSON shape'
            Check ($hook.timeout -eq 15 -and $hook.onFailure -ceq 'block') 'deep metadata repair preserves the blocking policy'
            if ($unixPermissions) {
                Check (([int][System.IO.File]::GetUnixFileMode($settings)) -eq 384) 'atomic replacement preserves restrictive Unix mode 0600'
            }
            $before = Get-PreservationBytes $settings
            Check ((Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome) -eq 'already') 'deep preserved metadata does not cause repeated rewrites'
            Check ((Get-PreservationBytes $settings) -ceq $before) 'deep metadata repeat is byte-identical'
        } else {
            Check $threw 'metadata exceeding supported serialization depth fails visibly'
            Check ((Get-PreservationBytes $settings) -ceq $before) 'excessive depth never replaces the original valid JSON'
        }
    } finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }
}

Write-Host 'Test 18: async true is visibly repaired while other operator fields survive (#582)'
$fixtureHome = New-TempHome
try {
    $settings = Join-Path $fixtureHome '.claude/settings.json'
    Write-PreservationSettings $settings @{ hooks = @{ PreToolUse = @(@{ matcher = 'Bash'; hooks = @(@{ type = 'command'; command = 'dcg'; async = $true; timeout = 15; onFailure = 'block' }) }) } }
    $messages = @(Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome 3>&1 6>&1)
    Check (@($messages | Where-Object { "$_" -match '(?i)async|synchronous' }).Count -gt 0) 'unsafe async true repair emits a visible diagnostic'
    $parsed = Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json
    $hook = $parsed.hooks.PreToolUse[0].hooks[0]
    Check ($null -eq $hook.PSObject.Properties['async']) 'blocking hook no longer carries async true'
    Check ($hook.timeout -eq 15 -and $hook.onFailure -ceq 'block') 'async repair retains timeout and fail-closed behavior'
} finally { Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue }

Write-Host 'Test 19: staging and atomic replacement failures preserve the old valid file (#582)'
$savedFixtureWriter = (Get-Command Write-Utf8NoBomText).ScriptBlock
foreach ($failureMode in @('write', 'replace', 'recover')) {
    $fixtureHome = New-TempHome
    try {
        $settings = Join-Path $fixtureHome '.claude/settings.json'
        Write-PreservationSettings $settings @{ hooks = @{ PreToolUse = @(@{ matcher = 'Bash'; hooks = @(@{ type = 'command'; command = 'dcg'; timeout = 15; onFailure = 'block' }) }) } }
        $before = Get-PreservationBytes $settings
        function Write-Utf8NoBomText {
            param([string]$Path, [string]$Text)
            if ($failureMode -eq 'write') { throw 'injected JSON staging failure' }
            & $savedFixtureWriter -Path $Path -Text $Text
            # Withhold only the newly staged file: the real replacement must
            # fail on missing source, without touching the valid destination.
            Move-Item -LiteralPath $Path -Destination ($Path + '.withheld')
            if ($failureMode -eq 'recover') {
                # Model native ReplaceFile moving the old destination to its
                # backup before failing. The dynamic caller owns $backup;
                # the fallback lets the unchanged baseline expose its loss.
                $nativeBackup = if ($backup) { $backup } else { $settings + '.simulated-backup' }
                Move-Item -LiteralPath $settings -Destination $nativeBackup
            }
        }
        $threw = $false
        try { Configure-ClaudeHook -DcgPath $dcgPath -Force -HomeDir $fixtureHome | Out-Null } catch { $threw = $true }
        Check $threw "$failureMode failure is reported"
        $preserved = Test-Path -LiteralPath $settings -PathType Leaf
        Check ($preserved -and (Get-PreservationBytes $settings) -ceq $before) "$failureMode failure preserves exact previous bytes"
        $parsed = if ($preserved) { Get-Content -Raw -Encoding UTF8 -LiteralPath $settings | ConvertFrom-Json } else { $null }
        Check ($preserved -and $parsed.hooks.PreToolUse[0].hooks[0].onFailure -ceq 'block') "$failureMode failure retains a valid blocking hook"
    } finally {
        Set-Item -LiteralPath Function:Write-Utf8NoBomText -Value $savedFixtureWriter
        Remove-Item -Recurse -Force -LiteralPath $fixtureHome -ErrorAction SilentlyContinue
    }
}

} finally { $env:CLAUDE_CONFIG_DIR = $savedClaudeConfigDir }

if ($script:failures -gt 0) {
    Write-Host "$script:failures FAILURE(S)" -ForegroundColor Red
    exit 1
}
Write-Host "All Configure-ClaudeHook tests passed." -ForegroundColor Green
