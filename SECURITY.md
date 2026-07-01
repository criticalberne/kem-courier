# Security Policy

KEM Courier is an educational prototype for post-quantum file exchange and enterprise key-custody design. It is not production-certified cryptographic software.

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

## Explicit non-goals

KEM Courier does not currently provide:

- Production certification.
- Hardware-backed key storage.
- Secure deletion.
- Distributed audit immutability.
- Enterprise identity federation.
- Protection from malware on the local host.
- Protection after private key compromise.
