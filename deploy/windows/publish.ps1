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
# Stage 6/11: runtime\ollama and models\ are added here.

Compress-Archive -Path $out -DestinationPath "$out.zip" -Force
Write-Host "Package: $out.zip"
