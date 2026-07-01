#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${1:-$(mktemp -d)}"
PASSPHRASE="${KEM_COURIER_PASSPHRASE:-correct horse battery staple}"
BIN="$ROOT/target/debug/kem-courier"

mkdir -p "$WORKDIR"
cd "$ROOT"

cargo build --quiet

cd "$WORKDIR"
printf 'confidential supplier contract\n' > supplier-contract.txt

"$BIN" identity generate --name sender --out sender.identity.json
"$BIN" identity generate --name recipient --out recipient.identity.json
"$BIN" identity export-public --identity sender.identity.json --out sender.public.json
"$BIN" identity export-public --identity recipient.identity.json --out recipient.public.json
"$BIN" identity seal --identity recipient.identity.json --out recipient.identity.sealed.json --passphrase "$PASSPHRASE"
"$BIN" identity checkout --identity recipient.identity.sealed.json --ttl 15m --reason "demo decrypt" --out recipient.lease.json --passphrase "$PASSPHRASE"

"$BIN" encrypt \
  --sender sender.identity.json \
  --recipient recipient.public.json \
  --mode hybrid-x25519-mlkem768 \
  --in supplier-contract.txt \
  --out supplier-contract.kemc

python3 - <<'PY'
import json
sender = json.load(open('sender.public.json'))
recipient = json.load(open('recipient.public.json'))
policy = f'''minimum_encryption_mode: hybrid-x25519-mlkem768
require_sender_signature: true
require_signed_metadata: true
allow_unsigned_envelopes: false
max_envelope_age_days: 30
allowed_senders:
  - name: sender
    fingerprint: "{sender['fingerprint']}"
allowed_recipients:
  - name: recipient
    fingerprint: "{recipient['fingerprint']}"
key_lifecycle:
  reject_expired_identity_keys: true
  max_identity_age_days: 365
'''
open('enterprise-policy.yaml', 'w').write(policy)
PY

"$BIN" inspect supplier-contract.kemc
"$BIN" decrypt \
  --identity recipient.identity.sealed.json \
  --passphrase "$PASSPHRASE" \
  --lease recipient.lease.json \
  --policy enterprise-policy.yaml \
  --sender sender.public.json \
  --in supplier-contract.kemc \
  --out supplier-contract.decrypted.txt

cmp supplier-contract.txt supplier-contract.decrypted.txt
"$BIN" access-review --policy enterprise-policy.yaml --in supplier-contract.kemc --out access-review.md
"$BIN" tamper supplier-contract.kemc --field suite --out tampered.kemc
if "$BIN" decrypt \
  --identity recipient.identity.sealed.json \
  --passphrase "$PASSPHRASE" \
  --lease recipient.lease.json \
  --policy enterprise-policy.yaml \
  --sender sender.public.json \
  --in tampered.kemc \
  --out should-not-exist.txt; then
  echo "tampered envelope unexpectedly decrypted" >&2
  exit 1
fi
"$BIN" audit verify

echo "KEM Courier demo complete: $WORKDIR"
