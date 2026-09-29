#!/usr/bin/env bash
# Downloads test binaries from gimli-rs/object-testfiles (pinned) into test/fixtures/,
# and builds a universal Mach-O from two of them.
set -euo pipefail
SHA="372470ab139b11cf6f729e2261561ca4d7c9ad0e"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/test/fixtures"
mkdir -p "$OUT"
FILES=(
  elf/base            # x86_64 dynamic executable (libc.so.6)
  elf/base-aarch64
  elf/base.o          # relocatable object
  elf/comdat.o        # C++: mangled symbols
  macho/base-aarch64
  macho/base-x86_64
  macho/libexports.dylib
  pe/import.exe       # imports and a delay-load import
  pe/export.dll
)
for f in "${FILES[@]}"; do
  dest="$OUT/$(echo "$f" | tr / -)"
  [ -f "$dest" ] || curl -sSfL "https://raw.githubusercontent.com/gimli-rs/object-testfiles/$SHA/$f" -o "$dest"
done
echo "not a binary" > "$OUT/readme.txt"
PYTHON=$(command -v python3 || command -v python)
"$PYTHON" "$ROOT/scripts/make_fat.py" "$OUT/fat-macho" "$OUT/macho-base-x86_64" "$OUT/macho-base-aarch64"
