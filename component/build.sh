#!/bin/sh
# Builds dist/medcrypto.wasm. It needs the wasm32-unknown-unknown target and wasm-tools.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here/.."
cargo build --locked --release -p medcrypto-component --target wasm32-unknown-unknown "$@"
target_dir=${CARGO_TARGET_DIR:-target}
mkdir -p component/dist
wasm-tools component new "$target_dir/wasm32-unknown-unknown/release/medcrypto_component.wasm" -o component/dist/medcrypto.wasm
wasm-tools validate --features component-model component/dist/medcrypto.wasm
echo "built component/dist/medcrypto.wasm ($(wc -c < component/dist/medcrypto.wasm | tr -d ' ') bytes)"
