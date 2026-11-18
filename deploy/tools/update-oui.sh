#!/usr/bin/env bash
# Refreshes the bundled IEEE MA-L (OUI) registry used to identify device vendors from MAC addresses.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
curl -fsSL -o "$TMP/oui.csv" https://standards-oui.ieee.org/oui/oui.csv
head -1 "$TMP/oui.csv" | grep -q '^Registry,Assignment,Organization Name' || { echo "Unexpected format" >&2; exit 1; }
gzip -9 -c "$TMP/oui.csv" > "$ROOT/src/Weles.Infrastructure/Discovery/Data/oui.csv.gz"
rm -rf "$TMP"
echo "Updated oui.csv.gz"
