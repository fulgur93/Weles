#!/usr/bin/env bash
# Installs the DEB package on clean systems (Docker images) and checks what a user would see:
# apt install with dependencies → WELES started by an ordinary user → panel pages → bundled AI answers offline →
# apt remove leaves the user's data. Usage: deploy/tests/test-deb-clean.sh [deb] [image...]
#   (default images: ubuntu:24.04 debian:12; needs Docker)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEB="${1:-$(ls "$ROOT"/artifacts/weles_*_amd64.deb | head -1)}"
shift || true
IMAGES=("$@"); [ "${#IMAGES[@]}" -eq 0 ] && IMAGES=(ubuntu:24.04 debian:12)

for image in "${IMAGES[@]}"; do
  echo "=== $image: $(basename "$DEB")"
  docker run --rm -v "$DEB:/tmp/weles.deb:ro" "$image" bash -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq curl >/dev/null
    apt-get install -y -qq /tmp/weles.deb >/dev/null
    echo "installed: $(dpkg-query -W -f="\${Package} \${Version}" weles), $(du -sh /opt/weles | cut -f1) in /opt/weles"
    test -x /usr/bin/weles && test -f /usr/share/applications/weles.desktop && test -f /usr/share/icons/hicolor/scalable/apps/weles.svg
    useradd -m tester
    su tester -c "weles --no-browser --port 5080 > /home/tester/weles.log 2>&1 &"
    for i in $(seq 1 90); do grep -q "WELES: http" /home/tester/weles.log && break; sleep 1; done
    url=$(grep -o "http://127.0.0.1:5080/auth?token=[A-Za-z0-9_%-]*" /home/tester/weles.log)
    curl -s -c /tmp/c -o /dev/null "$url"
    for p in / /assets /discovery /vulnerabilities /reports /agents /settings; do
      printf "%s %s  " "$p" "$(curl -s -b /tmp/c -o /dev/null -w "%{http_code}" "http://127.0.0.1:5080$p")"
    done; echo
    for i in $(seq 1 60); do grep -q "Bundled Ollama started" /home/tester/weles.log && break; sleep 1; done
    grep -E "Bundled Ollama started|Imported bundled vulnerability" /home/tester/weles.log | sed "s/^.*INF\] //"
    answer=$(curl -s --max-time 300 http://127.0.0.1:11435/api/chat -d "{\"model\":\"qwen3:4b-instruct-2507-q4_K_M\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"Odpowiedz jednym słowem: stolica Polski?\"}],\"options\":{\"num_predict\":10}}" | sed -n "s/.*\"content\":\"\([^\"]*\)\".*/\1/p")
    echo "AI: $answer"
    test -n "$answer"
    apt-get install -y -qq procps >/dev/null
    pkill -x Weles
    for i in $(seq 1 15); do pgrep -x Weles >/dev/null || pgrep -x ollama >/dev/null || break; sleep 1; done
    if pgrep -x ollama >/dev/null; then echo "ollama still running"; exit 1; fi
    if grep -q "Unhandled exception" /home/tester/weles.log; then grep -A3 "Unhandled exception" /home/tester/weles.log; exit 1; fi
    echo "WELES stopped cleanly, Ollama stopped with it"
    apt-get remove -y -qq weles >/dev/null
    test ! -e /opt/weles/app && test ! -e /usr/bin/weles && echo "removed; user data kept: $(ls /home/tester/.local/share/weles/data)"
  '
done
