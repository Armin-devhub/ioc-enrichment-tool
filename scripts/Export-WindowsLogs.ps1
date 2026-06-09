<#
.SYNOPSIS
    Export Windows Event Logs (or Sysmon logs) to plain-text the IOC tool reads.

.DESCRIPTION
    Windows logs are binary .evtx, which the IOC extractor can't parse. This
    script dumps recent events to .log text files under an output folder, ready
    for:  python -m ioc_enrich.cli --dir <output folder>

    Two sources:
      Windows  - System / Application / Security / Defender (default)
      Sysmon   - Microsoft-Windows-Sysmon/Operational (rich telemetry).
                 The Sysmon channel needs admin to read, so this script
                 self-elevates (one UAC prompt) when -Source Sysmon is used.

.PARAMETER OutDir
    Folder to write the .log files to (created if missing).

.PARAMETER Hours
    How far back to pull events. Default: 72.

.PARAMETER Source
    "Windows" (default) or "Sysmon".

.EXAMPLE
    .\scripts\Export-WindowsLogs.ps1 -Hours 72 -Source Sysmon
#>
param(
    [string]$OutDir = ".\eventlogs",
    [int]$Hours = 72,
    [ValidateSet("Windows", "Sysmon")][string]$Source = "Windows"
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# The Sysmon Operational channel can only be read with admin rights, so if we
# were asked for Sysmon and aren't elevated, relaunch this same script elevated.
if ($Source -eq "Sysmon" -and -not (Test-Admin)) {
    Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"",
        "-Source", "Sysmon", "-Hours", "$Hours", "-OutDir", "`"$OutDir`""
    )
    exit
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$after = (Get-Date).AddHours(-$Hours)

if ($Source -eq "Sysmon") {
    $logs = @("Microsoft-Windows-Sysmon/Operational")
} else {
    $logs = @("System", "Application", "Security",
              "Microsoft-Windows-Windows Defender/Operational")
}

foreach ($log in $logs) {
    $safe = $log -replace "[\\/]", "_"
    $dest = Join-Path $OutDir "$safe.log"
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $after } -ErrorAction Stop
        $events |
            ForEach-Object { "{0} [{1}] {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\s+", " ") } |
            Out-File -FilePath $dest -Encoding utf8
        Write-Host "Wrote $($events.Count) events -> $dest"
    }
    catch {
        Write-Warning "Skipped '$log': $($_.Exception.Message)"
    }
}

Write-Host "`nDone -> $OutDir" -ForegroundColor Green
