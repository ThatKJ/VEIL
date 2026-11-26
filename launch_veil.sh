#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Starting VEIL — Clinical Privacy Command Center (100% offline, stdlib-only)..."
exec python3 tools/veil_ui.py --demo --open "$@"
