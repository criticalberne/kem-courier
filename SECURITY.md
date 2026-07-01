# Security Policy

Quantum-Safe AI Trust Gateway is an educational prototype for AI security governance, post-quantum evidence envelopes, and enterprise key-custody design. It is not production-certified cryptographic or AI-safety software.

## Supported versions

Only the current `main` branch is supported for demonstration and learning purposes.

## Reporting a vulnerability

Please open a GitHub issue if you find a security defect in the prototype implementation, tests, or documentation.

For a real deployment decision, do not rely on this project without:

- Independent cryptographic review.
- Dependency and supply-chain review.
- Operational threat modeling.
- Secret-management integration review.
- Key lifecycle and incident-response design.
- AI red-team methodology and model/provider risk review.
- Prompt-injection detector evaluation against current attack corpora.

## Explicit non-goals

Quantum-Safe AI Trust Gateway does not currently provide:

- Production certification.
- Hardware-backed key storage.
- Secure deletion.
- Distributed audit immutability.
- Enterprise identity federation.
- Protection from malware on the local host.
- Protection after private key compromise.
- Complete prompt-injection prevention.
- Real model-provider isolation.
- Human approval workflow persistence.
- Production DLP/classification guarantees.
