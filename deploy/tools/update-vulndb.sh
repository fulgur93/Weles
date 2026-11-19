#!/usr/bin/env bash
# Rebuilds the offline vulnerability snapshot bundled with WELES from NVD, CISA KEV and FIRST EPSS.
# Without NVD_API_KEY NVD allows 5 requests / 30 s – the build takes ~5 minutes.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
dotnet run --project "$root/tools/Weles.VulnDbBuilder" -c Release -- "$root/src/Weles.Infrastructure/Vulnerabilities/Data/vulndb.json.gz"
