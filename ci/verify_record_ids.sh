#!/usr/bin/env bash
# Independent (non-Python) check of the record-ID fixtures in
# conformance/record-v1-vectors.json. A second implementation path beside the
# Python conformance tests (C9), not a replacement for them: it uses only jq
# (serialization) and coreutils sha256sum (hashing), never 4GARTHA's
# canonicalizer or hashing code.
#
# For each positive record-ID fixture:
#   1. serialize the fixture's `record` object independently with `jq -cSj`
#      and require those bytes to equal `canonical_utf8` (the expected bytes
#      are never trusted as input to the hash)
#   2. require sha256("4gartha.record/1" || 0x00 || bytes) == `record_id`
#   3. require sha256(bytes) == `plain_sha256_of_canonical`
# Fails closed: a missing tool, a missing or unexpected fixture, a changed
# fixture count, a missing field, or any mismatch exits non-zero.
#
# Usage: ci/verify_record_ids.sh [vectors.json]
set -euo pipefail
export LC_ALL=C

VECTORS="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/conformance/record-v1-vectors.json}"
EXPECTED_FIXTURES=(
  admission-ascii
  admission-non-ascii
  derivation-with-environment
  derivation-duplicate-inputs-no-environment
)
DOMAIN_TAG_TEXT='4gartha.record/1'   # followed by one NUL byte

fail() { echo "FAIL: $*" >&2; exit 1; }

for tool in jq sha256sum cmp od mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done
[ -f "$VECTORS" ] || fail "vectors file not found: $VECTORS"

echo "independent record-ID check: $(jq --version), $(sha256sum --version | head -n1)"
echo "vectors: $VECTORS"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The literal domain tag must also be what the vectors file declares.
printf '%s\0' "$DOMAIN_TAG_TEXT" > "$work/tag"
tag_hex=$(od -An -v -tx1 "$work/tag" | tr -d ' \n')
declared_tag=$(jq -er '.domain_tag_hex' "$VECTORS") || fail "vectors file has no domain_tag_hex"
[ "$tag_hex" = "$declared_tag" ] || fail "domain tag mismatch: literal $tag_hex, vectors declare $declared_tag"

# Fixture set: exactly the expected names, each exactly once.
count=$(jq -er '.record_ids | if type == "array" then length else error("record_ids is not an array") end' "$VECTORS") \
  || fail "vectors file has no record_ids array"
[ "$count" -eq "${#EXPECTED_FIXTURES[@]}" ] \
  || fail "expected ${#EXPECTED_FIXTURES[@]} record-ID fixtures, found $count"
for want in "${EXPECTED_FIXTURES[@]}"; do
  n=$(jq -r --arg w "$want" '[.record_ids[] | select(.name == $w)] | length' "$VECTORS")
  [ "$n" -eq 1 ] || fail "fixture '$want' appears $n time(s) (expected exactly 1)"
done

failures=0
for i in $(seq 0 $((count - 1))); do
  name=$(jq -er ".record_ids[$i].name" "$VECTORS")
  for f in record canonical_utf8 record_id plain_sha256_of_canonical; do
    jq -e ".record_ids[$i] | has(\"$f\") and (.$f != null)" "$VECTORS" >/dev/null \
      || fail "$name: missing field '$f'"
  done
  jq -e ".record_ids[$i].record | type == \"object\"" "$VECTORS" >/dev/null || fail "$name: record is not an object"

  # (1) independent serialization vs the expected canonical bytes
  jq -cSj ".record_ids[$i].record" "$VECTORS" > "$work/serialized"
  jq -j ".record_ids[$i].canonical_utf8" "$VECTORS" > "$work/expected"
  if cmp -s "$work/serialized" "$work/expected"; then canon=ok; else canon=MISMATCH; fi

  # (2) domain-separated record ID, computed over the *independently serialized* bytes
  want_id=$(jq -er ".record_ids[$i].record_id" "$VECTORS")
  got_id=$(cat "$work/tag" "$work/serialized" | sha256sum | cut -d' ' -f1)
  [ "$got_id" = "$want_id" ] && rid=ok || rid=MISMATCH

  # (3) plain SHA-256 of the same bytes
  want_plain=$(jq -er ".record_ids[$i].plain_sha256_of_canonical" "$VECTORS")
  got_plain=$(sha256sum < "$work/serialized" | cut -d' ' -f1)
  [ "$got_plain" = "$want_plain" ] && plain=ok || plain=MISMATCH
  [ "$got_plain" != "$got_id" ] || plain="MISMATCH (equals record ID)"

  if [ "$canon$rid$plain" = "okokok" ]; then
    echo "ok   $name  record_id=$got_id"
  else
    failures=$((failures + 1))
    echo "FAIL $name  serialization=$canon record_id=$rid plain_sha256=$plain"
    echo "       expected record_id $want_id"
    echo "       computed record_id $got_id"
  fi
done

if [ "$failures" -ne 0 ]; then
  fail "$failures of $count record-ID fixture(s) did not reproduce"
fi
echo "independent record-ID check: $count/$count fixtures reproduced (serialization, record_id, plain sha256)"
