#!/usr/bin/env bash
# Comprehensive verification script for root_entropy commit fixtures (noquote variant)
#
# This script performs all 10 verification steps from the checklist:
# 1. Basic file presence and top-level checks
# 2. Extract AK PEM and signature (decode base64 to files)
# 3. Inspect AK key type (RSA expected)
# 4. Compute canonical AK public-key fingerprint
# 5. Reconstruct canonical signed statement
# 6. Verify RSA signature using OpenSSL
# 7. Sanity-check no raw entropy committed
# 8. Run ingest and assert node_id contract
# 9. Manual recompute (debug)
# 10. Check quote fields are empty (for noquote fixture)
#
# Usage:
#   bash ci/verify_commit_fixture.sh [fixture_basename]
#
# Example:
#   bash ci/verify_commit_fixture.sh commit_noquote
#
# If no fixture basename is provided, defaults to 'commit_noquote'

set -euo pipefail

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_step() {
    echo ""
    echo -e "${GREEN}==== Step $1 ====${NC}"
    echo "$2"
}

# Default fixture basename
FIXTURE_BASENAME="${1:-commit_noquote}"

# Paths
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_JSON="${REPO_ROOT}/commit-fixtures/${FIXTURE_BASENAME}.json"
FIXTURE_NODE_ID="${REPO_ROOT}/commit-fixtures/${FIXTURE_BASENAME}.node_id"
WORKDIR="/tmp/root-entropy-check-$$"

log_info "Repository root: ${REPO_ROOT}"
log_info "Fixture: ${FIXTURE_BASENAME}"
log_info "Workdir: ${WORKDIR}"

# Cleanup on exit
cleanup() {
    if [ -d "${WORKDIR}" ]; then
        log_info "Cleaning up workdir: ${WORKDIR}"
        rm -rf "${WORKDIR}"
    fi
}
trap cleanup EXIT

# ============================================================================
# Step 1: Basic file presence and top-level quick checks
# ============================================================================
log_step 1 "Basic file presence and top-level quick checks"

if [ ! -f "${FIXTURE_JSON}" ]; then
    log_error "Fixture JSON not found: ${FIXTURE_JSON}"
    exit 1
fi

if [ ! -f "${FIXTURE_NODE_ID}" ]; then
    log_error "Fixture node_id file not found: ${FIXTURE_NODE_ID}"
    exit 1
fi

log_info "Files exist:"
ls -lh "${FIXTURE_JSON}" "${FIXTURE_NODE_ID}"

log_info "JSON structure (first 40 lines):"
jq -S . "${FIXTURE_JSON}" | head -40

# ============================================================================
# Step 2: Extract AK PEM and signature (decode base64 to files)
# ============================================================================
log_step 2 "Extract AK PEM and signature (decode base64 to files)"

mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

jq -r '.ak_public_pem_base64' "${FIXTURE_JSON}" | base64 -d > ak.pem
jq -r '.signature_base64' "${FIXTURE_JSON}" | base64 -d > sig.bin

log_info "Extracted ak.pem ($(wc -c < ak.pem) bytes)"
log_info "Extracted sig.bin ($(wc -c < sig.bin) bytes)"

# Check that ak.pem looks like a PEM file
if ! head -1 ak.pem | grep -q "BEGIN"; then
    log_error "ak.pem doesn't appear to be a PEM file"
    exit 1
fi

# ============================================================================
# Step 3: Inspect AK key type and ensure it's RSA
# ============================================================================
log_step 3 "Inspect AK key type and ensure it's RSA"

if ! openssl pkey -pubin -in ak.pem -text -noout > ak_info.txt 2>&1; then
    log_error "Failed to parse AK public key"
    cat ak_info.txt
    exit 1
fi

log_info "AK public key info:"
head -20 ak_info.txt

if ! grep -q "RSA Public-Key" ak_info.txt; then
    log_error "AK key is not RSA. Current code expects RSA keys."
    exit 1
fi

log_info "✓ AK key is RSA"

# ============================================================================
# Step 4: Compute canonical AK public-key fingerprint (AK DER -> sha256)
# ============================================================================
log_step 4 "Compute canonical AK public-key fingerprint"

openssl pkey -pubin -inform PEM -in ak.pem -outform DER -out ak.der

if command -v sha256sum > /dev/null 2>&1; then
    AK_FP=$(sha256sum ak.der | awk '{print $1}')
elif command -v shasum > /dev/null 2>&1; then
    AK_FP=$(shasum -a 256 ak.der | awk '{print $1}')
else
    log_error "Neither sha256sum nor shasum found"
    exit 1
fi

log_info "AK public key SHA256 fingerprint: ${AK_FP}"
export AK_FP

# ============================================================================
# Step 5: Reconstruct canonical signed statement bytes
# ============================================================================
log_step 5 "Reconstruct canonical signed statement bytes"

export FIXTURE_JSON
python3 - <<'PY'
import json
import os
import sys

try:
    fixture_path = os.environ.get('FIXTURE_JSON')
    if not fixture_path:
        raise ValueError("FIXTURE_JSON environment variable not set")
    with open(fixture_path, 'r', encoding='utf-8') as f:
        commit = json.load(f)
    
    ak_fp = os.environ['AK_FP']
    
    # Construct canonical statement (matching what the generator signed)
    stmt = {
        "v": 1,
        "node_type": "root_entropy",
        "algorithm": commit["algorithm"],
        "entropy_length_bytes": int(commit["entropy_length_bytes"]),
        "root_hash": commit["root_hash"],
        "ak_pubkey_fp_sha256": ak_fp,
        "tpm_quote_sha256": commit.get("tpm_quote_sha256"),
        "tpm_quote_nonce_sha256": commit.get("tpm_quote_nonce_sha256")
    }
    
    # Canonical JSON: sorted keys, compact separators
    s = json.dumps(stmt, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    
    with open('statement.bin', 'wb') as f:
        f.write(s.encode('utf-8'))
    
    print("Canonical statement (JSON):")
    print(s)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
PY

if [ ! -f statement.bin ]; then
    log_error "Failed to create statement.bin"
    exit 1
fi

log_info "✓ statement.bin created ($(wc -c < statement.bin) bytes)"

# ============================================================================
# Step 6: Verify the raw signature using OpenSSL
# ============================================================================
log_step 6 "Verify the raw signature using OpenSSL"

if openssl dgst -sha256 -verify ak.pem -signature sig.bin statement.bin > verify_result.txt 2>&1; then
    log_info "✓ Signature verification: $(cat verify_result.txt)"
else
    log_error "Signature verification FAILED"
    cat verify_result.txt
    exit 1
fi

# ============================================================================
# Step 7: Sanity-check that no raw entropy was committed
# ============================================================================
log_step 7 "Sanity-check that no raw entropy was committed"

log_info "Checking for offensive field names..."
if jq -e 'has("entropy_bin") or has("entropy_base64") or has("raw_entropy")' "${FIXTURE_JSON}" > /dev/null 2>&1; then
    log_error "WARNING: raw entropy present in fixture!"
    jq 'keys' "${FIXTURE_JSON}"
    exit 1
fi

log_info "✓ No obvious raw entropy fields found"

log_info "All fields in fixture:"
jq -r 'keys_unsorted[] as $k | "\($k): \(.[$k] | type)"' "${FIXTURE_JSON}"

# ============================================================================
# Step 8: Run ingest and assert node_id contract
# ============================================================================
log_step 8 "Run ingest and assert node_id contract"

log_info "Running ingest_root_entropy.py..."
if ! python3 "${REPO_ROOT}/ingest_root_entropy.py" "${FIXTURE_JSON}" > ingest_out.json 2>ingest_err.txt; then
    log_error "ingest_root_entropy.py failed"
    cat ingest_err.txt
    exit 1
fi

log_info "Ingest output:"
jq . ingest_out.json

log_info "Asserting node_id contract..."
if ! python3 "${REPO_ROOT}/ci/assert_node_id.py" ingest_out.json "${FIXTURE_NODE_ID}" 2>&1; then
    log_error "assert_node_id.py failed"
    exit 1
fi

# ============================================================================
# Step 9: Manual recompute (debug)
# ============================================================================
log_step 9 "Manual recompute (debug verification)"

python3 - <<'PY'
import json
import hashlib

with open('ingest_out.json', 'r') as f:
    o = json.load(f)

node_id = o['node_id']
node_rec = o['node_record']

s = json.dumps(node_rec, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
h = hashlib.sha256(s).hexdigest()

print(f"node_id from ingest: {node_id}")
print(f"recomputed sha256  : {h}")
print(f"Match: {node_id == h}")

if node_id != h:
    import sys
    sys.exit(1)
PY

log_info "✓ Manual recompute matches"

# ============================================================================
# Step 10: Quick check that quote fields are empty (noquote fixture)
# ============================================================================
log_step 10 "Check that quote fields are empty (noquote fixture)"

log_info "Checking quote-related fields..."

QUOTE_MSG=$(jq -r '.tpm_quote_msg_base64 // empty' "${FIXTURE_JSON}")
QUOTE_SIG=$(jq -r '.tpm_quote_sig_base64 // empty' "${FIXTURE_JSON}")
QUOTE_PCRS=$(jq -r '.tpm_quote_pcrs_base64 // empty' "${FIXTURE_JSON}")

if [ -n "${QUOTE_MSG}" ] || [ -n "${QUOTE_SIG}" ] || [ -n "${QUOTE_PCRS}" ]; then
    log_warn "Quote fields are non-empty for a noquote fixture"
    echo "  tpm_quote_msg_base64: ${QUOTE_MSG}"
    echo "  tpm_quote_sig_base64: ${QUOTE_SIG}"
    echo "  tpm_quote_pcrs_base64: ${QUOTE_PCRS}"
    log_warn "Re-generate fixture with ENABLE_QUOTE=0 if this is unexpected"
else
    log_info "✓ Quote fields are empty (as expected for noquote fixture)"
fi

# ============================================================================
# All checks passed
# ============================================================================
echo ""
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_info "✅ All verification checks PASSED"
log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_info ""
log_info "The fixture is self-consistent and safe to commit:"
log_info "  - Signature verified against AK public key"
log_info "  - No raw entropy present"
log_info "  - Node ID contract verified"
log_info ""
log_info "You can safely commit:"
log_info "  - ${FIXTURE_JSON}"
log_info "  - ${FIXTURE_NODE_ID}"
echo ""

exit 0
