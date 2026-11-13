# arkhe-verify

The portable verification surface for Arkhe: one pure Rust core, exposed through a CLI
and a WASM build, that checks Arkhe evidence offline.

The core takes bytes and returns a verdict. It does not open sockets, does not read the
filesystem beyond the inputs handed to it, does not read a clock, and does not resolve
policy at runtime. Adapters provide bytes; the core verifies them.

    SameCanonicalInputs => SameVerificationResult

## Check it yourself

```
git clone https://github.com/rafael-arkhe/arkhe-verify
cd arkhe-verify
cargo test --workspace
```

128 tests. They consume frozen golden vectors that are never regenerated in CI, require
the native and WASM paths to agree on every vector, and require unknown or malformed
input to fail closed rather than to pass quietly.

A smaller check, if you want to see the core do arithmetic before you read any of it:

```
$ cargo run -q -p arkhe-verify-cli -- blake3 61726b6865
8dc81cd08a81c1442bebb5ff51c2e1cfa1320d4251988367d5b2907337c14d71
```

`cargo run -q -p arkhe-verify-cli -- --help` lists the rest: custody chains, absence
records, release manifests, C2PA manifests and the restricted GGUF profile.

## What is in here

| Path | What it is |
| --- | --- |
| `kernel/arkhe-core` | Canonical types and the classification discipline the rest depends on |
| `verification/crates/arkhe-verify-core` | The pure verifier. No I/O, no clock, no network |
| `verification/crates/arkhe-verify-cli` | Thin command-line adapter over the core |
| `verification/crates/arkhe-verify-wasm` | The same core compiled for the browser, so an audit runs anywhere a browser runs |
| `integration/auth-md` | Signed-document adapter used by the WASM surface |
| `tests/`, `verification/tests/`, `verification/vectors/` | The frozen vectors, positive and negative |

Directory structure is preserved from the Arkhe monorepo this was extracted from, so a
fix ports in either direction without a rewrite.

## What this repository does not claim

Stated plainly, because a project selling verifiability cannot be vague about its own
state.

- It does not claim the Arkhe network exists or runs. There is no public testnet, no
  token and no paying customer.
- It does not verify that a model produced a correct or useful output. It verifies
  provenance and integrity. A receipt shows that the declared model ran over the declared
  input and produced that output; whether the output is any good is not a cryptographic
  question.
- Golden vectors are consumed here, not authored here. A vector set that is wrong will be
  verified as wrong, consistently.
- The figures published elsewhere for receipt size and verification overhead are
  measurements of the full system. This repository alone does not reproduce them.
- Passing tests on one machine is not an independent attestation. Nobody outside the
  project has audited this code.

## Related

The dated, signed freeze of the method — with its own verification script and a
field-by-field comparison procedure — is at
[arkhe-t0](https://github.com/rafael-arkhe/arkhe-t0).

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option —
the Rust ecosystem convention, and the same terms the rest of the public Arkhe code
carries. Permissive on purpose: a verification standard is worth more adopted than owned,
and this one is meant to be cheaper to adopt than to argue with.
