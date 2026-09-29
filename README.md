# dotk-core

The protocol of [dotk.name](https://dotk.name), the `.k` name registry on Kaspa, as a Rust
library. It reads the registry and builds transactions against it:

- names, keys, and the state of deeds and gaps
- cards, which carry a name's records, and subnames
- the decoder that finds registry transactions and classifies them
- the rules that derive the registry's gaps from its names
- the intent builders and the transaction assembler, with the fee ceilings that they enforce

The crate carries no compiler. A deployment's covenant bytecode arrives in its manifest, and
`Templates::from_manifest` refuses bytecode that does not hash to the template hashes that the
manifest pins. Those pins protect only a manifest that the caller trusts.

## Network fees

A node admits a transaction that pays the relay floor, 100 sompi per gram of the larger of its
compute and normalized transient mass. While the node's ready mempool fits in one block, the node
takes every transaction, so the fee is exactly the floor. Past one block, the node ranks by the
largest of compute, normalized transient and storage mass. The fee is then the node's
normal-priority feerate on that mass, when that is more than the floor. Where the node does not
report its ready mempool, the fee is the feerate on the fee mass, when that is more than the floor.
No fee passes 5 KAS, and
none is more than `OVERPAY_CEILING_SOMPI` above what its own transaction requires. That excess is
change too small to keep. Where change cannot pay for its own storage mass, the builder refuses,
and another coin is the remedy.

## Build and test

```bash
cargo build
cargo test --all-features
```

The `node` feature adds `net`, the wRPC connection to a Kaspa node and its fee market. The
`test-fixture` feature exposes `TEST_GENESIS`, a generated test deployment, for the tests of
crates that build on this one. The crate also builds for `wasm32-unknown-unknown`, with the
`getrandom` backend flag that `.cargo/config.toml` sets.

## License

[MIT](LICENSE).
