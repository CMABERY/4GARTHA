#!/usr/bin/env bash
set -euo pipefail

export PATH="$(pwd)/cli:$PATH"

python3 cli/nre-verify-fixtures --all
