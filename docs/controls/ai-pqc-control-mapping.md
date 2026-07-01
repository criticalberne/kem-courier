# AI/PQC Control Mapping

This document maps the Quantum-Safe AI Trust Gateway demo to the control families a Principal Security Architect would need to explain to security leadership, platform teams, and auditors.

## AI security controls

| Risk | Gateway control | Evidence artifact |
| --- | --- | --- |
| Prompt injection | Deterministic prompt/context pattern gate denies direct and indirect injection indicators. | `prompt_injection_detected`, denial reason, access review. |
| Sensitive information disclosure | Data classification drives model/tool authorization and PQC evidence requirements. | provenance `data_classification`, policy file, review. |
| Excessive agency | Tool requests are allowlisted and classification-limited. | `tool_decisions` in provenance. |
| Insecure plugin/tool design | Unknown tools deny by default; sensitive tools can require human approval. | denied/approval-required tool decisions. |
| Overreliance | Access review exposes machine decisions and reasons for human review. | markdown access-review report. |
| Audit gap | Every AI evaluation appends a hash-chained audit event. | `qstg.audit.jsonl`, `audit verify`. |

## PQC controls

| Risk | Gateway control | Evidence artifact |
| --- | --- | --- |
| Harvest-now-decrypt-later | Confidential approved AI artifacts are wrapped in ML-KEM-768 evidence envelopes. | `.kemc` evidence envelope. |
| Migration uncertainty | Hybrid X25519 + ML-KEM-768 is the default evidence mode. | envelope `suite` and `mode`. |
| Downgrade attack | Suite and mode are signed metadata and appear in access review. | envelope signature and review. |
| Metadata tampering | ML-DSA-65 signs canonical envelope metadata. | decrypt/verify fails on tamper. |
| Weak operational governance | Policy defines model, tool, classification, and PQC envelope requirements. | YAML policy and provenance reasons. |
| Unreviewable security decisions | Signed provenance links actor, model, decision, tool decisions, controls, and envelope fingerprint. | `*-provenance.json`. |

## Example policy controls

The baseline demo policy in `examples/ai-trust-policy.example.yaml` requires PQC envelopes for `confidential` and `regulated` data, allows only `approved-local-model`, permits `summarize_document` up to `regulated`, and blocks `send_email` for confidential data.

## Standards alignment

The project is a prototype, so the mappings below are architectural alignments rather than certification claims.

- **OWASP LLM01 Prompt Injection:** prompt/context indicators are detected and deny unsafe requests.
- **OWASP LLM02 Sensitive Information Disclosure:** data classification gates model/tool use and PQC evidence generation.
- **OWASP LLM06 Excessive Agency:** tools are policy-governed and deny by default.
- **NIST AI RMF Govern:** policy and access-review artifacts define accountable AI use.
- **NIST AI RMF Map:** request manifests capture actor, model, data class, tools, and context.
- **NIST AI RMF Measure:** deterministic detectors and tests measure known abuse cases.
- **NIST AI RMF Manage:** deny/approval decisions enforce operational controls before action.
- **PQC migration architecture:** named hybrid suites, authenticated algorithm metadata, and policy requirements demonstrate crypto-agility.

## Acceptance evidence

A healthy build should demonstrate:

1. A malicious confidential request is denied and does not produce an evidence envelope.
2. An allowed confidential request produces signed provenance and a hybrid PQC evidence envelope.
3. The access review names the decision, classification, prompt-injection result, tool decisions, controls, suite, and envelope fingerprint.
4. `qstg audit verify` succeeds after normal AI/PQC operations.
5. Existing file-envelope tamper tests continue to fail closed.
