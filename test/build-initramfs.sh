#!/usr/bin/env bash
# Build a minimal initramfs (single static /init) into test-assets/initramfs.img.
# Requires: gcc (static), cpio, gzip. Source: test/initramfs/init.c.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # workspace root
out="$here/test-assets"
work="$out/initramfs.d"
mkdir -p "$out"

echo "[initramfs] compiling static init…"
gcc -static -Os -s -o "$out/init" "$here/test/initramfs/init.c"

echo "[initramfs] assembling cpio…"
rm -rf "$work"
mkdir -p "$work/dev"   # mount point for devtmpfs (init mounts it)
cp "$out/init" "$work/init"
chmod 0755 "$work/init"

# newc-format cpio, gzip-compressed (universally accepted by the kernel unpacker).
( cd "$work" && find . -print0 | cpio --null -o --format=newc --quiet ) | gzip -9 > "$out/initramfs.img"
rm -rf "$work"

echo "[initramfs] wrote $out/initramfs.img ($(du -h "$out/initramfs.img" | cut -f1))"
