#!/usr/bin/env bash
# Independent (non-Python) check of the anchoring vectors and the stored anchor
# log. A second implementation path beside the Python conformance tests (C10),
# not a replacement for them: ci/anchor-go uses the Sigsum reference
# implementation (sigsum.org/sigsum-go v0.14.1, pinned with hashes in go.sum),
# its sigsum-verify command, and golang.org/x/mod's signed-note code, never
# 4GARTHA's Python.
#
# Checks (see ci/anchor-go/main.go):
#   - every vector in conformance/anchor-v1-vectors.json: RFC 6962 known
#     answers, record-ID leaf hashes, roots and inclusion paths, checkpoints,
#     policies and Sigsum proofs (reference outcomes as recorded), and the
#     complete example anchor log
#   - every Sigsum proof vector again through the sigsum-verify binary
#   - ledger/anchors: leaves.json rebuilt into the tree and every checkpoint
#     root compared. Stored Sigsum proofs are verified against the anchor
#     policy named by $ANCHOR_POLICY; if proofs are stored and no policy is
#     given, this fails (there is nothing to check them against). CI cannot
#     judge trust: such a policy, if it lives in the repository, is controlled
#     by the repository's writers (ASSURANCE.md 5.7).
#
# Fails closed: a missing tool, a module whose hash differs from go.sum, a
# vector count below its minimum, or any mismatch exits non-zero. GOTOOLCHAIN
# is local: an older Go fails rather than downloading a toolchain.
#
# Usage: ci/verify_anchor_vectors.sh [vectors.json]
set -euo pipefail
export LC_ALL=C

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
VECTORS="${1:-$repo/conformance/anchor-v1-vectors.json}"
POLICY="${ANCHOR_POLICY:-}"

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in go mktemp rm; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done
[ -f "$VECTORS" ] || fail "vectors file not found: $VECTORS"
[ -z "$POLICY" ] || [ -f "$POLICY" ] || fail "ANCHOR_POLICY does not name a file: $POLICY"

export GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOWORK=off
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$here/anchor-go"
echo "independent anchor check: $(go version)"
go build -trimpath -o "$work/anchor-go" .
go build -trimpath -o "$work/sigsum-verify" sigsum.org/sigsum-go/cmd/sigsum-verify
go mod verify
"$work/sigsum-verify" --version

args=(-vectors "$VECTORS" -sigsum-verify "$work/sigsum-verify" -anchors "$repo/ledger/anchors")
if [ -n "$POLICY" ]; then
  args+=(-policy "$POLICY")
fi
"$work/anchor-go" "${args[@]}"
