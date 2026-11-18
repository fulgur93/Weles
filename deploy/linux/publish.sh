#!/usr/bin/env bash
# Builds a self-contained WELES package for Linux (no .NET runtime needed on the target machine).
# Usage: deploy/linux/publish.sh [linux-x64|linux-arm64]
set -euo pipefail
RID="${1:-linux-x64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props")"
OUT="$ROOT/artifacts/weles-$VERSION-$RID"

rm -rf "$OUT"
dotnet publish "$ROOT/src/Weles.App/Weles.App.csproj" -c Release -r "$RID" --self-contained true \
  -p:PublishReadyToRun=true -p:DebugType=none -o "$OUT/app"

install -m 0755 "$ROOT/deploy/linux/weles.sh" "$OUT/weles"
cp "$ROOT/deploy/THIRD-PARTY-NOTICES.txt" "$OUT/"
# Stage 6/11: runtime/ollama and models/ are added here.

tar -C "$ROOT/artifacts" -czf "$OUT.tar.gz" "$(basename "$OUT")"
echo "Package: $OUT.tar.gz"
