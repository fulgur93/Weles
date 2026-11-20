#!/usr/bin/env bash
# Prepares the AI runtime bundled with WELES: the official Ollama release (pinned version, SHA-256 verified) and the
# default model pulled into a models directory. The result is copied into the package by the publish scripts; at run time
# WELES starts it as a child process and never downloads anything.
#   deploy/tools/fetch-ai-runtime.sh [output-dir]        (default: artifacts/ai-runtime)
set -euo pipefail
OLLAMA_VERSION="v0.40.16"
MODEL="${WELES_AI_MODEL:-qwen3:4b-instruct-2507-q4_K_M}"
ARCHIVE="ollama-linux-amd64.tar.zst"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$root/artifacts/ai-runtime}"
mkdir -p "$out/download" "$out/ollama" "$out/models"

base="https://github.com/ollama/ollama/releases/download/$OLLAMA_VERSION"
echo "Ollama $OLLAMA_VERSION → $out/ollama"
curl -fL --retry 3 -o "$out/download/sha256sum.txt" "$base/sha256sum.txt"
if [ ! -f "$out/download/$ARCHIVE" ] || ! (cd "$out/download" && grep " \./$ARCHIVE\$\| $ARCHIVE\$" sha256sum.txt | sed 's# \./# #' | sha256sum -c --status); then
  curl -fL --retry 3 -o "$out/download/$ARCHIVE" "$base/$ARCHIVE"
fi
(cd "$out/download" && grep " \./$ARCHIVE\$\| $ARCHIVE\$" sha256sum.txt | sed 's# \./# #' | sha256sum -c -)
rm -rf "$out/ollama" && mkdir -p "$out/ollama"
tar --zstd -xf "$out/download/$ARCHIVE" -C "$out/ollama"
# CPU-only package: drop the CUDA libraries (~1 GB); Vulkan/CPU backends stay.
rm -rf "$out/ollama/lib/ollama"/cuda_* 2>/dev/null || true

echo "Model $MODEL → $out/models"
port=11436
OLLAMA_HOST="127.0.0.1:$port" OLLAMA_MODELS="$out/models" "$out/ollama/bin/ollama" serve >"$out/download/serve.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do curl -fs "http://127.0.0.1:$port/api/version" >/dev/null && break; sleep 1; done
OLLAMA_HOST="127.0.0.1:$port" "$out/ollama/bin/ollama" pull "$MODEL"
OLLAMA_HOST="127.0.0.1:$port" "$out/ollama/bin/ollama" list
du -sh "$out/ollama" "$out/models"
