//! Source for `oversized-output.component.wasm`.
//!
//! Rebuild from the repository root with the pinned Rust toolchain:
//! `rustc --edition=2024 --crate-name oversized_output --target wasm32-wasip2
//! -C opt-level=z -C lto=fat -C panic=abort -C strip=debuginfo
//! tests/fixtures/oversized_output.rs
//! -o tests/fixtures/oversized-output.component.wasm`.

use std::io::{self, Write};

fn main() {
    io::stdout()
        .write_all(&[b'x'; 4_096])
        .expect("the test runtime intentionally rejects this output");
}
