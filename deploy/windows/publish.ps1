# Builds a self-contained WELES package for Windows (no .NET runtime needed on the target machine).
# Usage: pwsh deploy/windows/publish.ps1 [-Rid win-x64|win-arm64]
param([string]$Rid = "win-x64")
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
# Local AI: Ollama for Windows + model in artifacts\ai-runtime-win\{ollama,models} (same layout as the Linux
# deploy/tools/fetch-ai-runtime.sh produces; a Windows variant of that script is part of Stage 11 packaging).
$ai = Join-Path $root "artifacts\ai-runtime-win"
if ((Test-Path (Join-Path $ai "ollama\ollama.exe")) -and (Test-Path (Join-Path $ai "models\manifests"))) {
    New-Item -ItemType Directory -Force -Path (Join-Path $out "runtime") | Out-Null
    Copy-Item -Recurse (Join-Path $ai "ollama") (Join-Path $out "runtime\ollama")
    Copy-Item -Recurse (Join-Path $ai "models") (Join-Path $out "runtime\models")
} else {
    Write-Warning "artifacts\ai-runtime-win missing – the package will have no local AI."
}

Compress-Archive -Path $out -DestinationPath "$out.zip" -Force
Write-Host "Package: $out.zip"
