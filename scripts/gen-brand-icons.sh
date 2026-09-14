#!/usr/bin/env bash
# andvari brand icons — regenerate EVERY tile icon in the fleet from the one source SVG.
#
# H138 (audit 2026-09-13): 0.26.3 shipped the mark in two geometries. The tile icons (web
# favicon, desktop .ico/.png, extension icon16-128) drew a 14-unit inset stave at stroke 1.8
# (ratio 0.129) while BrandSigil, the extension popup/options headers and the Android launcher
# drew the 18-unit wordmark stave at the same stroke (ratio 0.100) — so the same product's rune
# was ~29 % bolder and shorter on the browser tab than in the popup header two centimetres away.
# The owner picked ONE geometry: the wordmark. assets/brand/andvari-mark.svg is now the source
# and this script is the only sanctioned way to produce a derivative of it.
#
# Rendering is done with rsvg-convert (librsvg) and ImageMagick's convert, both of which are
# what produced the 0.26.3 set on this host; Pillow is not required. Run from anywhere.
#
#   ./scripts/gen-brand-icons.sh          # rewrite every derivative in the tree
#   ./scripts/gen-brand-icons.sh --check  # render to a temp dir and DIFF against the tree; the
#                                         # release gate runs this, so a source-geometry change
#                                         # committed without a re-run fails there instead of
#                                         # shipping a stale tab icon (R49)
#
# Outputs (all tracked; commit whatever this changes):
#   web/public/favicon.svg                     verbatim copy of the source (served at /favicon.svg)
#   web/public/apple-touch-icon.png            180  iOS home screen
#   web/public/icon-192.png  icon-512.png      manifest.webmanifest "any" icons (H136)
#   web/public/icon-512-maskable.png           manifest "maskable" icon — full bleed, rune inside
#                                              the 80 % safe circle so Android's mask cannot clip it
#   extension/icons/icon{16,32,48,128}.png     MV3 action + store listing
#   app-desktop/icons/andvari.svg              verbatim copy of the source (provenance next to the
#                                              rasters jpackage consumes)
#   app-desktop/icons/andvari.ico              16/24/32/48/64/128/256 — windows.iconFile
#   app-desktop/icons/andvari.png              512 — linux.iconFile
#   app-desktop/src/main/resources/andvari.png 256 — the running window/taskbar icon
#
# NOT generated: app-android/src/main/res/drawable/ic_launcher_foreground.xml. The adaptive icon
# is a vector drawable that already carries this exact geometry by hand (and must, to scale into
# the 108dp safe zone with no raster step) — it is the sibling that was right all along. If the
# source geometry ever changes, change that file in the same commit; the web brand-assets test
# fails when the two disagree.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_DIR/assets/brand/andvari-mark.svg"
cd "$REPO_DIR"

# R49: --check renders everything into a scratch tree and compares, instead of writing. The test
# suite could only assert that each tile EXISTS and is non-empty (a raster's bytes are not
# derivable in JS), so the one failure this whole file exists to prevent — the source geometry
# changes and nobody re-runs the script — shipped green. Here the renderer IS the oracle.
CHECK=0
case "${1:-}" in
  --check) CHECK=1; shift ;;
  "") ;;
  *) echo "unknown arg: ${1}; usage: $0 [--check]" >&2; exit 2 ;;
esac

for tool in rsvg-convert convert; do
  command -v "$tool" >/dev/null || { echo "missing $tool (apt install librsvg2-bin imagemagick)" >&2; exit 1; }
done
[ -f "$SRC" ] || { echo "missing source $SRC" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# In --check mode every output is written under $OUT (a mirror of the tree's layout) and compared
# afterwards; otherwise $OUT is the tree itself and this behaves exactly as before.
OUT="$REPO_DIR"
if [ "$CHECK" = 1 ]; then
  OUT="$TMP/tree"
  mkdir -p "$OUT/web/public" "$OUT/extension/icons" "$OUT/app-desktop/icons" "$OUT/app-desktop/src/main/resources"
fi
GENERATED=()

png() { rsvg-convert -w "$1" -h "$1" "$SRC" -o "$OUT/$2"; GENERATED+=("$2"); }
copy() { cp "$SRC" "$OUT/$1"; GENERATED+=("$1"); }

echo "==> web"
copy web/public/favicon.svg
png 180 web/public/apple-touch-icon.png
png 192 web/public/icon-192.png
png 512 web/public/icon-512.png

# Maskable: Android may crop the icon to anything from a circle to a squircle, keeping only the
# central 80 %. The tile's own rounded corners would be eaten, so the maskable variant is the rune
# alone (the <rect> stripped — no geometry is re-typed here, the mark still comes from the source)
# rendered at 60 % and centred on a full-bleed field of the app dark.
grep -v '<rect' "$SRC" > "$TMP/mark-only.svg"
# R52: the strip is LINE-oriented and silent. It works only because the source happens to put the
# rect on its own line and the paths on theirs; reformat the SVG to one line, or add a second
# background element, and `grep -v` either takes the mark away with the tile or leaves the tile in
# — and the script still exits 0, so web/public/icon-512-maskable.png becomes a plain dark square
# (or a clipped one) that every existing test accepts because it is a non-empty PNG. Assert both
# halves of what the strip is supposed to have done, and fail loudly rather than composite junk.
grep -q 'M12 3v18' "$TMP/mark-only.svg" || { echo "maskable strip removed the mark itself — is the source still one element per line?" >&2; exit 1; }
grep -q '<rect' "$TMP/mark-only.svg" && { echo "maskable strip left the background tile in — the mask would clip its corners" >&2; exit 1; }
rsvg-convert -w 308 -h 308 "$TMP/mark-only.svg" -o "$TMP/mark-only.png"
convert -size 512x512 xc:'#14120E' "$TMP/mark-only.png" -gravity center -composite \
        -depth 8 -define png:color-type=6 "$OUT/web/public/icon-512-maskable.png"
MASKABLE="web/public/icon-512-maskable.png"
GENERATED+=("$MASKABLE")

echo "==> extension"
for s in 16 32 48 128; do png "$s" "extension/icons/icon${s}.png"; done

echo "==> desktop"
copy app-desktop/icons/andvari.svg
png 512 app-desktop/icons/andvari.png
png 256 app-desktop/src/main/resources/andvari.png
for s in 16 24 32 48 64 128 256; do rsvg-convert -w "$s" -h "$s" "$SRC" -o "$TMP/ico-$s.png"; done
# 256 stays PNG-compressed inside the .ico (Vista+ convention, and what 0.26.3 shipped);
# the smaller frames are plain BMP so pre-Vista shells and jpackage's own reader agree.
convert "$TMP/ico-16.png" "$TMP/ico-24.png" "$TMP/ico-32.png" "$TMP/ico-48.png" \
        "$TMP/ico-64.png" "$TMP/ico-128.png" "$TMP/ico-256.png" "$OUT/app-desktop/icons/andvari.ico"
GENERATED+=("app-desktop/icons/andvari.ico")

if [ "$CHECK" = 0 ]; then
  echo "==> done; git status will show what moved"
  exit 0
fi

# --- --check: compare the freshly rendered tree against the committed one -------------------
# Byte-compare everything EXCEPT the maskable PNG: ImageMagick stamps a creation date into it, so
# its bytes differ on every run even when every pixel is identical. That one is compared by pixels
# (`compare -metric AE` must be 0), which is the property that actually matters.
stale=()
for f in "${GENERATED[@]}"; do
  [ -f "$REPO_DIR/$f" ] || { stale+=("$f (missing from the tree)"); continue; }
  if [ "$f" = "${MASKABLE:-}" ]; then
    diff_px="$(convert "$OUT/$f" "$REPO_DIR/$f" -metric AE -compare -format '%[distortion]' info: 2>/dev/null || echo fail)"
    [ "$diff_px" = "0" ] && continue
    stale+=("$f (pixels differ from a fresh render)")
  else
    cmp -s "$OUT/$f" "$REPO_DIR/$f" || stale+=("$f")
  fi
done
if [ "${#stale[@]}" -gt 0 ]; then
  echo "    BRAND ICONS STALE — these do not match a fresh render of $SRC:" >&2
  printf '      %s\n' "${stale[@]}" >&2
  echo "    Run scripts/gen-brand-icons.sh and commit what it changes (a hand-edited raster or a" >&2
  echo "    source-geometry change with no re-run is exactly what this catches)." >&2
  exit 1
fi
echo "==> brand icons match a fresh render of the source" 
