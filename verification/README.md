# arkhe-verify — Phase 1

`arkhe-verify` is the portable verification surface for Arkhe.

It does not replace IDEs, GitHub, Cosign, Docker or Kubernetes. It provides one
verification core and exposes it through thin adapters:

- Rust native core
- CLI
- WASM
- MCP server
- GitHub Action
- Cosign/Sigstore bridge

## Trust boundary

The Rust core is pure and deterministic: no network, no filesystem, no ambient
clock, no mutable policy resolution.

Adapters provide bytes; the core verifies them.

`SameCanonicalInputs => SameVerificationResult`

## Phase-1 gates

1. static golden vectors are consumed, never regenerated in CI;
2. native and WASM must agree on every golden vector;
3. unknown/invalid inputs fail closed;
4. MCP is a thin adapter, not semantic authority;
5. Cosign/Sigstore are integration bridges, not Arkhe semantic sources;
6. WormGraph is evidence substrate, not an IDE/user surface.

## Unified workspace

Native crates belong to the root Cargo workspace. The MCP adapter is at
`integrations/verify-mcp`, Cosign at `integrations/cosign`, and Kubernetes examples
at `ops/verification`. Build from the repository root:

```powershell
cargo test -p arkhe-verify-core --locked
pnpm verify:wasm
pnpm build:adapters
pnpm test:adapters
```

The static contract remains `verification/tests/golden_vectors.json`. CANDIDATE
vectors keep their original status; integration does not silently freeze them.
Current executed results are recorded in [root status](../docs/STATUS.md).

The [Gravit interoperability golden set v1](interop/gravit-golden-v1/README.md)
provides eight pinned accept/reject cases for RFC 6962 inclusion, Ed25519 and
the proposed witness-quorum profile, with an independent reader specification.
Run `python verification/interop/gravit-golden-v1/verify.py` from the workspace root.

## Stage 10 laboratory profile

The [GGUF supply-chain PoC](../docs/STAGE10-GGUF.md) adds binary subset validation,
dual artifact digests, pinned builder signatures and RFC 6962 inclusion against a
signed local checkpoint. Run `arkhe-verify verify-gguf-artifact` with artifact,
bundle and independently trusted policy files. This profile does not implement
Sigstore/Fulcio verification; the existing `verify-gguf` only canonicalizes JSON.
For real Sigstore message-signature bundles, the [Sigstore adapter](../integrations/cosign/README.md)
combines Rust GGUF inspection with the official verifier for Fulcio chains, exact
identity/issuer, CT SCTs, authenticated timestamps and Rekor inclusion/checkpoints.
