#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${1:-$(mktemp -d)}"
PASSPHRASE="${QSTG_PASSPHRASE:-correct horse battery staple}"
BIN="$ROOT/target/debug/qstg"

mkdir -p "$WORKDIR"
cd "$ROOT"
cargo build --quiet

cd "$WORKDIR"
"$BIN" identity generate --name ai-gateway --out gateway.identity.json
"$BIN" identity generate --name security-recipient --out security-recipient.identity.json
"$BIN" identity export-public --identity security-recipient.identity.json --out security-recipient.public.json

"$BIN" ai evaluate \
  --request "$ROOT/examples/malicious-ai-request.example.json" \
  --policy "$ROOT/examples/ai-trust-policy.example.yaml" \
  --sender gateway.identity.json \
  --recipient security-recipient.public.json \
  --out malicious-provenance.json \
  --access-review-out malicious-access-review.md \
  --envelope-out malicious-evidence.kemc \
  --passphrase "$PASSPHRASE"

"$BIN" ai evaluate \
  --request "$ROOT/examples/allowed-ai-request.example.json" \
  --policy "$ROOT/examples/ai-trust-policy.example.yaml" \
  --sender gateway.identity.json \
  --recipient security-recipient.public.json \
  --out allowed-provenance.json \
  --access-review-out allowed-access-review.md \
  --envelope-out allowed-evidence.kemc \
  --passphrase "$PASSPHRASE"

"$BIN" inspect allowed-evidence.kemc
"$BIN" audit verify

printf '\nQuantum-Safe AI Trust Gateway demo complete: %s\n' "$WORKDIR"
printf 'Review artifacts:\n- %s/malicious-access-review.md\n- %s/allowed-access-review.md\n- %s/allowed-evidence.kemc\n' "$WORKDIR" "$WORKDIR" "$WORKDIR"
