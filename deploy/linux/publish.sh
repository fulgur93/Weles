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
# Local AI: Ollama + model prepared by deploy/tools/fetch-ai-runtime.sh (nothing is downloaded on the user's machine).
AI="$ROOT/artifacts/ai-runtime"
if [ -x "$AI/ollama/bin/ollama" ] && [ -d "$AI/models/manifests" ]; then
  mkdir -p "$OUT/runtime"
  cp -a "$AI/ollama" "$OUT/runtime/ollama"
  cp -a "$AI/models" "$OUT/runtime/models"
  echo "AI runtime included: $(du -sh "$OUT/runtime" | cut -f1)"
else
  echo "WARNING: artifacts/ai-runtime missing – run deploy/tools/fetch-ai-runtime.sh; the package will have no local AI." >&2
fi

tar -C "$ROOT/artifacts" -czf "$OUT.tar.gz" "$(basename "$OUT")"
echo "Package: $OUT.tar.gz"
