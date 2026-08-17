#!/bin/sh
# Construit l'UI pour le navigateur.
#
# 🔴 `wasm-bindgen` (le binaire) doit avoir EXACTEMENT la même version que le crate
# `wasm-bindgen` du Cargo.lock. Une divergence produit un bundle qui se charge et
# plante à la première fonction, sur une erreur qui ne mentionne pas la version.
set -e
cd "$(dirname "$0")/../.."

VERSION=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | grep version | cut -d'"' -f2)
INSTALLEE=$(wasm-bindgen --version 2>/dev/null | awk '{print $2}')

if [ "$VERSION" != "$INSTALLEE" ]; then
  echo "🔴 wasm-bindgen $INSTALLEE installé, $VERSION attendu."
  echo "   cargo install wasm-bindgen-cli --version $VERSION"
  exit 1
fi

cargo build -p hlb-ui --lib --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript \
  --out-dir crates/hlb-ui/web --out-name hlb_ui \
  target/wasm32-unknown-unknown/release/hlb_ui.wasm

# ⚠️ `wasm-opt` est facultatif mais retire encore ~20 % : sans lui le bundle marche,
# il est juste plus lourd.
if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz -o crates/hlb-ui/web/hlb_ui_bg.wasm crates/hlb-ui/web/hlb_ui_bg.wasm
fi

echo "✓ UI web dans crates/hlb-ui/web/"
echo "  hlb-controller --ui-dir crates/hlb-ui/web"
