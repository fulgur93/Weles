#!/usr/bin/env bash
# Installs Inno Setup (the Windows installer compiler) into a private Wine prefix, so the Windows installer can be built
# on Linux. On Windows use Inno Setup directly (ISCC.exe). Pinned version, SHA-256 verified.
#   deploy/tools/fetch-innosetup.sh          → ~/.cache/weles-build/wine (WINEPREFIX), ISCC at C:\InnoSetup\ISCC.exe
set -euo pipefail
VERSION="6.7.4"
SHA256="a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c"
DIR="${WELES_BUILD_CACHE:-$HOME/.cache/weles-build}"
export WINEPREFIX="$DIR/wine" WINEDEBUG=-all
installer="$DIR/innosetup-$VERSION.exe"
mkdir -p "$DIR"
[ -f "$installer" ] || curl -fL --retry 3 -o "$installer" "https://github.com/jrsoftware/issrc/releases/download/is-${VERSION//./_}/innosetup-$VERSION.exe"
echo "$SHA256  $installer" | sha256sum -c -
if [ ! -f "$WINEPREFIX/drive_c/InnoSetup/ISCC.exe" ]; then
  wineboot -i >/dev/null 2>&1 || true
  wine "$installer" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER /DIR="C:\\InnoSetup" >/dev/null 2>&1
fi
ls -la "$WINEPREFIX/drive_c/InnoSetup/ISCC.exe"
