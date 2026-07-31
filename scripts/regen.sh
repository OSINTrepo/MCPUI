#!/usr/bin/env bash
# Пересобрать конфиги из реестра (registry/servers.yaml).
set -euo pipefail
cd "$(dirname "$0")/.."
python generator/generate.py
