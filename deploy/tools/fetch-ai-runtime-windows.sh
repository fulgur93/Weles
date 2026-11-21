#!/usr/bin/env bash
# Prepares the AI runtime for the Windows package on a Linux build machine: the official Ollama for Windows (same pinned
# version as deploy/tools/fetch-ai-runtime.sh, SHA-256 verified), CPU/Vulkan only, and the same model files – the model
# blobs are platform independent, so they are copied from the Linux runtime instead of being downloaded again.
#   deploy/tools/fetch-ai-runtime-windows.sh [output-dir]      (default: artifacts/ai-runtime-win)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
OLLAMA_VERSION="$(sed -n 's/^OLLAMA_VERSION="\(.*\)"/\1/p' "$root/deploy/tools/fetch-ai-runtime.sh")"
ARCHIVE="ollama-windows-amd64.zip"
linux="$root/artifacts/ai-runtime"
out="${1:-$root/artifacts/ai-runtime-win}"
mkdir -p "$out/download"

[ -d "$linux/models/manifests" ] || { echo "Run deploy/tools/fetch-ai-runtime.sh first (it prepares the model)." >&2; exit 1; }

base="https://github.com/ollama/ollama/releases/download/$OLLAMA_VERSION"
echo "Ollama $OLLAMA_VERSION for Windows → $out/ollama"
curl -fL --retry 3 -o "$out/download/sha256sum.txt" "$base/sha256sum.txt"
verify() { (cd "$out/download" && grep " \./$ARCHIVE\$\| $ARCHIVE\$" sha256sum.txt | sed 's# \./# #' | sha256sum -c "$@" -); }
if [ ! -f "$out/download/$ARCHIVE" ] || ! verify --status; then
  curl -fL --retry 3 -o "$out/download/$ARCHIVE" "$base/$ARCHIVE"
fi
verify
rm -rf "$out/ollama" && mkdir -p "$out/ollama"
unzip -q "$out/download/$ARCHIVE" -d "$out/ollama"
# CPU-only package (as on Linux): drop the CUDA/ROCm libraries; the CPU and Vulkan backends stay.
rm -rf "$out/ollama/lib/ollama"/cuda_* "$out/ollama/lib/ollama"/rocm* 2>/dev/null || true
[ -f "$out/ollama/ollama.exe" ] || { echo "ollama.exe missing in the archive" >&2; exit 1; }

rm -rf "$out/models" && cp -a "$linux/models" "$out/models"
du -sh "$out/ollama" "$out/models"
