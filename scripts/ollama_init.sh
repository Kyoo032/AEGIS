#!/bin/sh
set -eu
: "${OLLAMA_MODELS:=qwen3.5:0.8b}"
for model in $OLLAMA_MODELS; do
    ollama pull "$model"
done
