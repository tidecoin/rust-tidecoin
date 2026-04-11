# Embedded Hashes Smoke Test

This crate is a maintained but limited embedded smoke test for `tidecoin_hashes`
in a Cortex-M-style `no_std` environment. It is not part of the main workspace
check path and must not be checked with the default host target.

Current support level:

- supported target: `thumbv7m-none-eabi`
- supported purpose: verify that the hash engine builds and runs in a bare-metal
  target with `panic-halt`
- not currently a broad embedded support matrix
- not currently run by the main workspace checks

Known limitation:

Running `cargo check --manifest-path hashes/embedded/Cargo.toml` without an
embedded target tries to build the `#![no_std]` binary for the host. That fails
with `unwinding panics are not supported without std` because the host build
uses the default unwind panic strategy while this crate is meant to halt on
panic through `panic-halt`.

Use the target-specific check instead:

```shell
rustup target add thumbv7m-none-eabi
source ./scripts/env.sh
cargo check --target thumbv7m-none-eabi
```

The optional `alloc` feature still needs nightly today because it uses an
embedded allocator hook. The default non-alloc smoke test should stay on stable.

To run the embedded test, first prepare your environment:

```shell
sudo ./scripts/install-deps
rustup target add thumbv7m-none-eabi
```

Then:

```shell
source ./scripts/env.sh && cargo run --target thumbv7m-none-eabi
```

Output should be something like:

```text
hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad hash_check:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
hash:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad hash_check:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Cleanup

After sourcing `scripts/env.sh` and _before_ building again using another target
you'll want to unset `RUSTFLAGS` otherwise you'll get linker errors.

```shell
unset RUSTFLAGS
```
