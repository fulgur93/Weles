#!/usr/bin/env bash
# Builds a self-contained WELES package for Linux (no .NET runtime needed on the target machine).
# Usage: deploy/linux/publish.sh [linux-x64|linux-arm64] [--without-ai] [--no-archive]
set -euo pipefail
RID="linux-x64"; WITH_AI=1; ARCHIVE=1
for arg in "$@"; do
  case "$arg" in
    --without-ai) WITH_AI=0 ;;
    --no-archive) ARCHIVE=0 ;;
    *) RID="$arg" ;;
  esac
done
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
if [ "$WITH_AI" = 0 ]; then
  echo "Package without local AI (--without-ai)."
elif [ -x "$AI/ollama/bin/ollama" ] && [ -d "$AI/models/manifests" ]; then
  mkdir -p "$OUT/runtime"
  cp -a "$AI/ollama" "$OUT/runtime/ollama"
  cp -a "$AI/models" "$OUT/runtime/models"
  echo "AI runtime included: $(du -sh "$OUT/runtime" | cut -f1)"
else
  echo "WARNING: artifacts/ai-runtime missing – run deploy/tools/fetch-ai-runtime.sh; the package will have no local AI." >&2
fi

if [ "$ARCHIVE" = 1 ]; then
  tar -C "$ROOT/artifacts" -cf - "$(basename "$OUT")" | zstd -T0 -3 -q -o "$OUT.tar.zst" -f
  echo "Package: $OUT.tar.zst"
fi
echo "Directory: $OUT"
