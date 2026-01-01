#!/usr/bin/env bash
set -euo pipefail

export PATH="$(pwd)/cli:$PATH"

python cli/nre-verify-fixtures --all
