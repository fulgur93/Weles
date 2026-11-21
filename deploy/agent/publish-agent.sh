#!/usr/bin/env bash
# Builds the self-contained WELES agent (no .NET runtime needed on the agent machine).
# Usage: deploy/agent/publish-agent.sh [linux-x64|linux-arm64|win-x64]
set -euo pipefail
RID="${1:-linux-x64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props")"
OUT="$ROOT/artifacts/weles-agent-$VERSION-$RID"

rm -rf "$OUT"
dotnet publish "$ROOT/src/Weles.Agent/Weles.Agent.csproj" -c Release -r "$RID" --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none -o "$OUT"
cp "$ROOT/deploy/THIRD-PARTY-NOTICES.txt" "$OUT/"
case "$RID" in
  win-*) cp "$ROOT/deploy/windows/install-agent.ps1" "$OUT/"
         (cd "$ROOT/artifacts" && rm -f "$(basename "$OUT").zip" && zip -qr "$(basename "$OUT").zip" "$(basename "$OUT")")
         echo "Package: $OUT.zip" ;;
  *)     cp "$ROOT/deploy/linux/weles-agent.service" "$OUT/"
         tar -C "$ROOT/artifacts" -czf "$OUT.tar.gz" "$(basename "$OUT")"
         echo "Package: $OUT.tar.gz" ;;
esac
