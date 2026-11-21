<#
.SYNOPSIS
  Installs the WELES agent as a Windows service. Run in PowerShell as administrator from the unpacked agent folder.
.EXAMPLE
  .\install-agent.ps1 -Server https://192.168.0.10:7443 -Pin <sha256> -Code <enrollment code>
.NOTES
  The agent connects out to WELES over HTTPS only (certificate pinned); no inbound port is opened. The token is stored
  with DPAPI (machine scope) in %ProgramData%\WELES Agent\agent.json, readable by Administrators and SYSTEM only.
#>
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Pin,
    [Parameter(Mandatory = $true)][string]$Code,
    [string]$InstallDir = "$env:ProgramFiles\WELES Agent"
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Uruchom PowerShell jako administrator.' }

$configDir = Join-Path $env:ProgramData 'WELES Agent'
$config = Join-Path $configDir 'agent.json'
New-Item -ItemType Directory -Force -Path $InstallDir, $configDir | Out-Null
Copy-Item -Force (Join-Path $PSScriptRoot 'weles-agent.exe') $InstallDir
# Configuration readable by Administrators and SYSTEM only.
icacls $configDir /inheritance:r /grant:r 'Administrators:(OI)(CI)F' 'SYSTEM:(OI)(CI)F' | Out-Null

$exe = Join-Path $InstallDir 'weles-agent.exe'
& $exe enroll --server $Server --pin $Pin --code $Code --config $config
if ($LASTEXITCODE -ne 0) { throw 'Rejestracja agenta nie powiodła się.' }

if (Get-Service -Name 'WELES Agent' -ErrorAction SilentlyContinue) { Stop-Service 'WELES Agent'; sc.exe delete 'WELES Agent' | Out-Null; Start-Sleep 2 }
New-Service -Name 'WELES Agent' -DisplayName 'WELES Agent' -StartupType Automatic `
    -Description 'Agent WELES: wychodzące HTTPS do WELES, wyłącznie zatwierdzone skany.' `
    -BinaryPathName "`"$exe`" run --config `"$config`"" | Out-Null
sc.exe failure 'WELES Agent' reset= 86400 actions= restart/30000/restart/60000/restart/300000 | Out-Null
Start-Service 'WELES Agent'
Write-Host "Usługa „WELES Agent” działa. Status w WELES: Agenci."
