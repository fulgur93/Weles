#!/usr/bin/env bash
# Builds the Debian/Ubuntu package (weles_<version>_<arch>.deb): WELES self-contained in /opt/weles, the bundled Ollama
# and model in /opt/weles/runtime, the `weles` command, a menu entry (normal and demo mode) and the icon.
# User data stays in ~/.local/share/weles – never in /opt, and it is kept when the package is removed.
# Usage: deploy/linux/build-deb.sh [linux-x64|linux-arm64] [--without-ai]
set -euo pipefail
RID="linux-x64"; EXTRA=()
for arg in "$@"; do case "$arg" in --without-ai) EXTRA+=("$arg") ;; *) RID="$arg" ;; esac; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$ROOT/Directory.Build.props")"
case "$RID" in linux-x64) ARCH=amd64 ;; linux-arm64) ARCH=arm64 ;; *) echo "Unsupported RID $RID" >&2; exit 2 ;; esac

"$ROOT/deploy/linux/publish.sh" "$RID" --no-archive "${EXTRA[@]}"
SRC="$ROOT/artifacts/weles-$VERSION-$RID"
STAGE="$ROOT/artifacts/deb-stage-$RID"
SUFFIX=""; [ "${#EXTRA[@]}" -gt 0 ] && SUFFIX="-noai"
DEB="$ROOT/artifacts/weles${SUFFIX}_${VERSION}_${ARCH}.deb"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/opt/weles" "$STAGE/usr/bin" "$STAGE/usr/share/applications" \
         "$STAGE/usr/share/icons/hicolor/scalable/apps" "$STAGE/usr/share/doc/weles"

cp -a "$SRC/app" "$STAGE/opt/weles/app"
[ -d "$SRC/runtime" ] && cp -a "$SRC/runtime" "$STAGE/opt/weles/runtime"
cp "$ROOT/deploy/THIRD-PARTY-NOTICES.txt" "$STAGE/opt/weles/"
cp "$ROOT/deploy/THIRD-PARTY-NOTICES.txt" "$STAGE/usr/share/doc/weles/copyright"
cat > "$STAGE/usr/bin/weles" <<'SH'
#!/bin/sh
# WELES – the panel opens in the browser on 127.0.0.1; data in ~/.local/share/weles.
exec /opt/weles/app/Weles "$@"
SH
chmod 0755 "$STAGE/usr/bin/weles"
install -m 0644 "$ROOT/deploy/assets/weles.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/weles.svg"
cat > "$STAGE/usr/share/applications/weles.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=WELES
GenericName=Attack Surface Intelligence
Comment=Audyt bezpieczeństwa sieci lokalnej z lokalnym AI
Comment[en]=Local network security audit with local AI
Exec=weles
Icon=weles
Terminal=false
Categories=Network;Security;
StartupNotify=false
Actions=Demo;

[Desktop Action Demo]
Name=Tryb demonstracyjny
Name[en]=Demo mode
Exec=weles --demo
DESKTOP
cp "$ROOT/deploy/linux/weles-agent.service" "$STAGE/usr/share/doc/weles/" 2>/dev/null || true

# Permissions: everything readable, nothing writable by users (WELES never writes to its installation directory).
find "$STAGE/opt" -type d -exec chmod 0755 {} +
find "$STAGE/opt" -type f -perm -u+x -exec chmod 0755 {} +
find "$STAGE/opt" -type f ! -perm -u+x -exec chmod 0644 {} +

SIZE_KB="$(du -sk --exclude=DEBIAN "$STAGE" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: weles${SUFFIX}
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Installed-Size: $SIZE_KB
Depends: libc6 (>= 2.31), libgcc-s1, libstdc++6, zlib1g, libssl3 | libssl3t64, libicu78 | libicu76 | libicu74 | libicu72 | libicu70, ca-certificates
Recommends: iputils-ping, xdg-utils
Maintainer: WELES <weles@localhost.invalid>
Homepage: https://github.com/fulgur93/Weles
Description: WELES – Attack Surface Intelligence Platform
 Local security audit of your own network: device and service discovery,
 vulnerability matching (offline NVD/KEV/EPSS database), contextual risk
 assessment, change monitoring, PDF reports and a local AI analyst (bundled
 Ollama runtime and model – works without the Internet).
 The panel listens on 127.0.0.1 only. Scans run only on scopes you approve.
CONTROL
for script in postinst postrm; do
  cat > "$STAGE/DEBIAN/$script" <<'SH'
#!/bin/sh
set -e
# Refresh the menu and icon caches when the tools exist; nothing else is touched (no services, no users).
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
exit 0
SH
  chmod 0755 "$STAGE/DEBIAN/$script"
done

fakeroot dpkg-deb --build -Zzstd -z3 "$STAGE" "$DEB"
rm -rf "$STAGE"
dpkg-deb --info "$DEB" | sed -n '1,12p'
ls -la "$DEB"
