# batdeob fuzz target

Run:

```bash
cd rust/fuzz
cargo +nightly fuzz run analyze
```

The target wraps `analyze(&[u8], &Config)` with tight per-invocation limits
(1s timeout, 1024 iterations, 1 MB output, depth 4, 4 child scripts). Run
indefinitely or for a fixed budget via `-runs=N` / `-max_total_time=S`.

Requires nightly toolchain:

```bash
rustup install nightly --component rust-src
cargo install cargo-fuzz
```
