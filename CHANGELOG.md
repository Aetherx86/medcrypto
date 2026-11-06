# Changelog

Versions follow this rule: a bug or security fix increments `0.0.X`, and new functionality or new platform
support increments `0.X.0`.

## 0.1.0

- Added `medcrypto.wasm`, a WebAssembly Component with SHA-256, HKDF, AES-256-GCM, Ed25519, Merkle roots and audit
  chain links. The one binary runs from Python, TypeScript and Go, and it imports nothing at all. It has a checksum
  and a build provenance attestation.
- Security: the command line and the GUI used fixed constants as ZKP blinding factors, so anybody could recover a
  small committed value, such as a lab result, by trying each possibility. Each proof now gets a fresh blinding
  factor from the operating system's random source. Proofs made by earlier versions should be treated as exposing
  their values.
- Added a repository guard against supply chain tampering to CI, least-privilege workflow permissions, and
  commit-pinned actions in the new workflow.

## 0.0.1-beta

First release.
