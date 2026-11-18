#!/usr/bin/env bash
# Refreshes the bundled IEEE MA-L (OUI) registry used to identify device vendors from MAC addresses.
# oui.txt is used because it is the complete registry (oui.csv has been observed to lack ~1/3 of assignments).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/oui.txt" https://standards-oui.ieee.org/oui/oui.txt
COUNT="$(grep -c '(hex)' "$TMP/oui.txt")"
[ "$COUNT" -gt 30000 ] || { echo "Unexpected registry size: $COUNT" >&2; exit 1; }
gzip -9 -c "$TMP/oui.txt" > "$ROOT/src/Weles.Infrastructure/Discovery/Data/oui.txt.gz"
echo "Updated oui.txt.gz ($COUNT assignments)"
