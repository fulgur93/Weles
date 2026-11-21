# Builds WELES for Windows on a Windows machine: the self-contained package (ZIP) and, when Inno Setup 6 is installed,
# the installer (deploy\windows\weles.iss). The AI runtime is taken from artifacts\ai-runtime-win (prepared by
# deploy/tools/fetch-ai-runtime-windows.sh); without it the package has no local AI. On Linux use build-installer.sh.
# Usage: pwsh deploy/windows/publish.ps1 [-Rid win-x64] [-WithoutAI]
param([string]$Rid = "win-x64", [switch]$WithoutAI)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot/../.."
$version = ([xml](Get-Content "$root/Directory.Build.props")).Project.PropertyGroup.Version
$out = Join-Path $root "artifacts/weles-$version-$Rid"

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
dotnet publish "$root/src/Weles.App/Weles.App.csproj" -c Release -r $Rid --self-contained true `
    -p:PublishReadyToRun=true -p:DebugType=none -o "$out/app"
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Copy-Item "$PSScriptRoot/WELES.cmd" $out
Copy-Item "$root/deploy/THIRD-PARTY-NOTICES.txt" $out
$ai = Join-Path $root "artifacts\ai-runtime-win"
$withAi = (-not $WithoutAI) -and (Test-Path (Join-Path $ai "ollama\ollama.exe")) -and (Test-Path (Join-Path $ai "models\manifests"))
if ($withAi) {
    New-Item -ItemType Directory -Force -Path (Join-Path $out "runtime") | Out-Null
    Copy-Item -Recurse (Join-Path $ai "ollama") (Join-Path $out "runtime\ollama")
    Copy-Item -Recurse (Join-Path $ai "models") (Join-Path $out "runtime\models")
} elseif (-not $WithoutAI) {
    Write-Warning "artifacts\ai-runtime-win missing – the package will have no local AI."
}

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
$name = "weles-setup-$version-$Rid" + $(if ($withAi) { "" } else { "-noai" })
if ($iscc) {
    & $iscc /Q "/DSourceDir=$out" "/DAppVersion=$version" "/DWithAI=$([int]$withAi)" "/DOutputName=$name" "$PSScriptRoot\weles.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
    Write-Host "Installer: $root\artifacts\$name.exe"
} else {
    Write-Warning "Inno Setup 6 not found – building the ZIP package only."
    Compress-Archive -Path $out -DestinationPath "$out.zip" -Force
    Write-Host "Package: $out.zip"
}
