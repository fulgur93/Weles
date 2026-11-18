#!/usr/bin/env sh
# WELES launcher. User data goes to ~/.local/share/weles – never to the installation directory.
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/app/Weles" "$@"
