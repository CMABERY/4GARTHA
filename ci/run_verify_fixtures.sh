#!/usr/bin/env bash
set -euo pipefail

export PATH="$(pwd)/cli:$PATH"

nre-verify-fixtures --all
