#!/usr/bin/env bash
# Builds the Windows installer on a Linux machine: self-contained WELES for win-x64, the bundled AI runtime for Windows
# (artifacts/ai-runtime-win from deploy/tools/fetch-ai-runtime-windows.sh) and Inno Setup run under Wine
# (deploy/tools/fetch-innosetup.sh). On Windows use deploy/windows/publish.ps1 instead.
# Usage: deploy/windows/build-installer.sh [--without-ai]
set -euo pipefail
WITH_AI=1
for arg in "$@"; do case "$arg" in --without-ai) WITH_AI=0 ;; *) echo "Unknown option $arg" >&2; exit 2 ;; esac; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props")"
RID=win-x64
OUT="$ROOT/artifacts/weles-$VERSION-$RID"
AI="$ROOT/artifacts/ai-runtime-win"
export WINEPREFIX="${WELES_BUILD_CACHE:-$HOME/.cache/weles-build}/wine" WINEDEBUG=-all
ISCC="$WINEPREFIX/drive_c/InnoSetup/ISCC.exe"
[ -f "$ISCC" ] || "$ROOT/deploy/tools/fetch-innosetup.sh"

rm -rf "$OUT"
dotnet publish "$ROOT/src/Weles.App/Weles.App.csproj" -c Release -r "$RID" --self-contained true \
  -p:PublishReadyToRun=true -p:DebugType=none -o "$OUT/app"
cp "$ROOT/deploy/THIRD-PARTY-NOTICES.txt" "$OUT/"
NAME="weles-setup-$VERSION-$RID"
if [ "$WITH_AI" = 1 ]; then
  [ -f "$AI/ollama/ollama.exe" ] && [ -d "$AI/models/manifests" ] || { echo "artifacts/ai-runtime-win missing – run deploy/tools/fetch-ai-runtime-windows.sh or use --without-ai" >&2; exit 1; }
  mkdir -p "$OUT/runtime"
  cp -a "$AI/ollama" "$OUT/runtime/ollama"
  cp -a "$AI/models" "$OUT/runtime/models"
else
  NAME="$NAME-noai"
fi

rm -f "$ROOT/artifacts/$NAME".exe "$ROOT/artifacts/$NAME"-*.bin
wine "$ISCC" /Q "/DSourceDir=$(winepath -w "$OUT")" "/DAppVersion=$VERSION" "/DWithAI=$WITH_AI" "/DOutputName=$NAME" \
  "$(winepath -w "$ROOT/deploy/windows/weles.iss")"
ls -la "$ROOT/artifacts/$NAME"*
(cd "$ROOT/artifacts" && sha256sum "$NAME".exe "$NAME"-*.bin 2>/dev/null > "$NAME.sha256" || true)
echo "Installer: $ROOT/artifacts/$NAME.exe"
