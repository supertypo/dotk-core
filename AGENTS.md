# Contributor notes for dotk-core

This file holds the workflow and the rules that a change must not break. README.md says what the
crate is and how to build it.

## Workflow

1. Run `git pull` before you change anything.
2. Implement the change with its tests. If a change can regress behavior, write the regression
   test first.
3. Run `cargo test --all-features`.
4. Run `cargo clippy --all-targets --all-features -- -D warnings`, and fix the findings.
5. Run `cargo check --target wasm32-unknown-unknown --features node`.
6. Run `cargo fmt`.
7. Commit directly on `main` with a short message, and push. CI runs the same steps.

## Rules

- No path can build a transaction that overpays. Every fee, bond, deposit and change value that a
  builder emits has an upper bound, and a test must hold each bound. `MAX_FEE_SOMPI` binds what
  actually leaves the inputs, dust folded into the fee included.
- Every change output must be committed to by a `SIGHASH_ALL` signature, because a covenant pins
  only its own outputs. The unfunded evict is the one exception. A wallet's signature is adopted
  only through `sign::accept_wallet_sig` or `sign::accept_funding_sig_script`.
- Treat a manifest as hostile input. Nothing that it declares can panic this crate, and its
  bytecode counts only after it hashes to the template hashes that the manifest pins. Those pins
  protect only a manifest that the caller trusts.
- `tests/fixtures/genesis.json` is a generated test deployment. Never edit it by hand.
- A comment states a non-obvious, important fact, in the fewest words that carry it. Describe the
  current state only, never its history. Never name a file, a document or a project that a reader
  of this repository cannot open. Open standards and open-source projects are fine to name.
- Documentation and comments use American spelling, simple tenses and the active voice, and no
  semicolons or em-dashes.
