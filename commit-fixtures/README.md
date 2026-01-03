# Root Entropy Commit Fixtures

This directory contains cryptographically signed root_entropy node fixtures used for testing and verification.

## Current Status

**Note**: This directory is ready to receive fixtures but currently contains no fixture files. Fixtures will be added once generated using the TPM-based generator with the appropriate configuration.

## Structure

Each fixture consists of two files:
- `<name>.json` - The commit fixture containing the signed statement and metadata
- `<name>.node_id` - The pinned node_id (sha256 of canonical node_record)

## Fixture Types

### No-Quote Fixtures (`commit_noquote.*`)

These fixtures are generated with TPM quote disabled (`ENABLE_QUOTE=0`):
- Contains TPM-signed statement but no TPM quote/attestation
- Quote-related fields (`tpm_quote_msg_base64`, `tpm_quote_sig_base64`, etc.) are empty or null
- Signature is raw RSA signature bytes (tpm2_sign with `-f plain`)

## Verification

### Quick Verification

Run the comprehensive verification script:

```bash
bash ci/verify_commit_fixture.sh commit_noquote
```

This performs all 10 verification steps from the checklist.

### Manual Step-by-Step Verification

Follow the detailed checklist in the problem statement, or run individual verification steps:

#### 1. Basic checks
```bash
ls -l commit-fixtures/commit_noquote.json commit-fixtures/commit_noquote.node_id
jq -S . commit-fixtures/commit_noquote.json | head -40
```

#### 2-6. Signature verification
```bash
# From repository root
mkdir -p /tmp/verify-temp && cd /tmp/verify-temp
jq -r '.ak_public_pem_base64' /path/to/commit-fixtures/commit_noquote.json | base64 -d > ak.pem
jq -r '.signature_base64' /path/to/commit-fixtures/commit_noquote.json | base64 -d > sig.bin
openssl pkey -pubin -in ak.pem -text -noout
openssl pkey -pubin -in ak.pem -outform DER -out ak.der
AK_FP=$(sha256sum ak.der | awk '{print $1}')
# ... (continue with statement reconstruction and verification)
```

Note: Replace `/path/to/commit-fixtures/` with the actual path to your commit-fixtures directory.

#### 7. Check for raw entropy
```bash
jq -e 'has("entropy_bin") or has("entropy_base64") or has("raw_entropy")' \
  commit-fixtures/commit_noquote.json && \
  echo "WARNING: raw entropy present" || \
  echo "No raw entropy fields"
```

#### 8. Verify node_id contract
```bash
python3 ingest_root_entropy.py commit-fixtures/commit_noquote.json > /tmp/ingest.json
python3 ci/assert_node_id.py /tmp/ingest.json commit-fixtures/commit_noquote.node_id
```

## Security Notes

- **Never commit raw entropy**: Fixtures must not contain `entropy_bin`, `entropy_base64`, or similar fields
- **Signature verification is mandatory**: All fixtures must have valid TPM signatures
- **Pin node_id**: The `.node_id` file ensures immutability of the canonical record
- **RSA keys only**: Current verification expects RSA attestation keys (2048-bit or higher)

## Adding New Fixtures

1. Generate fixture using the generator with appropriate flags (e.g., `ENABLE_QUOTE=0`)
2. Place generated files in this directory:
   - `commit-fixtures/<name>.json`
   - `commit-fixtures/<name>.node_id`
3. Run comprehensive verification:
   ```bash
   bash ci/verify_commit_fixture.sh <name>
   ```
4. If all checks pass, commit both files
5. Never commit files with raw entropy or failed verification

## Troubleshooting

### Signature Verification Failure

- Ensure signature is raw bytes (`tpm2_sign -f plain`)
- Verify statement.bin matches exactly what was signed
- Check that AK public key matches the signing key

### Node ID Mismatch

- Ensure canonical JSON uses `sort_keys=True` and `separators=(',', ':')`
- Verify no extra fields or different field ordering in node_record
- Check that ingest script matches generator's canonicalization

### Key Type Issues

- Current code expects RSA keys
- If using EC keys, verification commands need adjustment
- Check key type: `openssl pkey -pubin -in ak.pem -text -noout | grep -E "(RSA|EC)"`

## References

- Canonical JSON spec: RFC 8785-style with sorted keys, compact separators
- TPM 2.0 Specification: for quote/attestation semantics
- OpenSSL verification: `openssl dgst -sha256 -verify` for raw RSA signatures
