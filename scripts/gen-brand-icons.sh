#!/usr/bin/env bash
# andvari brand icons: render every icon in the tree from the sources under assets/brand/.
#
# Why one script: the mark once shipped in two geometries at the same time. The browser tab's icon
# was drawn from one set of numbers and the extension's header from another, so the same product's
# rune looked bolder and shorter on the tab than in the popup beside it. Since then every rendered
# icon comes from the sources under assets/brand/ through this script, and no rendered icon is ever
# edited by hand.
#
# Which source at which size (assets/brand/BRAND.md, "The icon"):
#   16, 24, 32 px   andvari-mark-16.svg, -24.svg, -32.svg: the small tile redrawn on the pixel grid
#   48, 64 px       andvari-mark.svg: the small tile (flat rune on flat hardwood, corners rounded)
#   128 px and up   andvari-mark-gilded.svg: the gilded rune on polished hardwood, full bleed where
#                   the platform rounds or masks the icon itself, and clipped here to rounded
#                   corners (24 of 108) where the platform shows the picture as it is
# Five of the large pictures carry a light noise on their gradient (one draw per pixel, +-1.4
# levels, a fixed seed, so a re-render is identical), which keeps the dark radial gradient from
# showing 8-bit bands.
#
# Tools: rsvg-convert (librsvg), ImageMagick's convert (the .ico), and Python 3 with the Pillow
# library (the noise and the pixel comparison). They are tools of this script; no app needs them.
#
#   scripts/gen-brand-icons.sh          # rewrite every rendered icon in the tree
#   scripts/gen-brand-icons.sh --check  # render into a temporary folder and compare the decoded
#                                       # pixels (alpha included, no tolerance) with the committed
#                                       # files, every frame of the .ico included; the release gate
#                                       # runs this, so a source changed without a re-render, or an
#                                       # icon edited by hand, fails there instead of shipping
#
# Outputs (all tracked; commit whatever this changes):
#   file                                         px    source               noise
#   web/public/favicon.svg                       -     andvari-mark.svg, copied verbatim
#   web/public/apple-touch-icon.png              180   gilded, full bleed   yes  (iOS rounds it)
#   web/public/icon-192.png                      192   gilded, rounded      no
#   web/public/icon-512.png                      512   gilded, rounded      yes
#   web/public/icon-512-maskable.png             512   gilded, full bleed   yes  (Android masks it;
#                                                      the rune stays inside the maskable safe circle)
#   extension/icons/icon16.png, icon32.png       16/32 andvari-mark-16/-32  no
#   extension/icons/icon48.png                   48    andvari-mark.svg     no
#   extension/icons/icon128.png                  128   gilded, rounded      no
#   app-desktop/icons/andvari.svg                -     andvari-mark.svg, copied verbatim
#   app-desktop/icons/andvari.png                512   gilded, rounded      yes  (linux.iconFile)
#   app-desktop/src/main/resources/andvari.png   256   gilded, rounded      no   (the window icon)
#   app-desktop/icons/andvari.ico                16/24/32 pixel-fitted tiles, 48/64 andvari-mark.svg,
#                                                128/256 gilded rounded; no noise (windows.iconFile)
#   app-ios/Andvari/Assets.xcassets/AppIcon.appiconset/icon-1024.png
#                                                1024  gilded, full bleed   yes  (RGB, no alpha:
#                                                      the App Store refuses an icon with alpha)
#
# NOT rendered here: the Android adaptive icon (app-android/src/main/res/drawable/ic_launcher_*.xml).
# Those are vector drawables that carry the rune's geometry as numbers, so they scale into the
# launcher's safe zone with no raster step; web/src/ui/brand-assets.test.ts compares them with the
# sources. Nothing for the stores is rendered here either.
#
# The temporary folder this makes goes when a run ends well. A run that fails leaves it and names
# it, so the renders of a failing comparison can be looked at.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRAND="$REPO_DIR/assets/brand"
TILE="$BRAND/andvari-mark.svg"
GILDED="$BRAND/andvari-mark-gilded.svg"
cd "$REPO_DIR"

CHECK=0
case "${1:-}" in
  --check) CHECK=1; shift ;;
  "") ;;
  *) echo "unknown arg: ${1}; usage: $0 [--check]" >&2; exit 2 ;;
esac

for tool in rsvg-convert convert python3; do
  command -v "$tool" >/dev/null || {
    echo "missing $tool: this script needs rsvg-convert, ImageMagick's convert, and Python 3 with Pillow" >&2
    echo "(Debian/Ubuntu: apt install librsvg2-bin imagemagick python3-pil)" >&2
    exit 1
  }
done
python3 -I -c 'import PIL' 2>/dev/null || {
  echo "missing the Pillow library for python3 (Debian/Ubuntu: apt install python3-pil)" >&2
  exit 1
}
for f in "$TILE" "$GILDED" "$BRAND"/andvari-mark-{16,24,32}.svg; do
  [ -f "$f" ] || { echo "missing source $f" >&2; exit 1; }
done

# The noise and the comparison, in Python with Pillow.
#   dither FILE   adds the noise in place. A picture with see-through pixels (the rounded icons)
#                 stays RGBA: the noise goes on R, G and B where alpha is above 0, alpha is never
#                 touched, and a fully transparent pixel stays as it is. A fully opaque picture
#                 comes out RGB. Either way one draw per pixel, in row order, whatever its alpha.
#   compare A B   compares the decoded pixels of A (a fresh render) and B (the committed file) as
#                 RGBA, frame by frame for an .ico, with no tolerance; prints what differs and
#                 exits 1 when anything does.
#   noalpha FILE  exits 1 when FILE has an alpha channel.
PY='
import random, sys
from PIL import Image, ImageChops

def dither(path, amount=1.4, seed=7):
    src = Image.open(path).convert("RGBA")
    keep_alpha = src.getchannel("A").getextrema()[0] < 255
    im = src if keep_alpha else src.convert("RGB")
    rnd = random.Random(seed)
    px = im.load()
    q = lambda v: min(255, max(0, round(v)))
    for y in range(im.height):
        for x in range(im.width):
            n = rnd.uniform(-amount, amount)
            if keep_alpha:
                r, g, b, a = px[x, y]
                if a:
                    px[x, y] = (q(r + n), q(g + n), q(b + n), a)
            else:
                r, g, b = px[x, y]
                px[x, y] = (q(r + n), q(g + n), q(b + n))
    im.save(path)

def frames(path):
    im = Image.open(path)
    if im.format == "ICO":
        out = [im.ico.frame(i).convert("RGBA") for i in range(len(im.ico.entry))]
        return sorted(out, key=lambda f: f.size)
    return [im.convert("RGBA")]

def compare(fresh, committed):
    a, b = frames(fresh), frames(committed)
    if [f.size for f in a] != [f.size for f in b]:
        print("sizes differ: fresh %s, committed %s" % ([f.size for f in a], [f.size for f in b]))
        return 1
    bad = 0
    for fa, fb in zip(a, b):
        if fa.tobytes() == fb.tobytes():
            continue
        d = ImageChops.difference(fa, fb).split()
        worst = d[0]
        for c in d[1:]:
            worst = ImageChops.lighter(worst, c)
        h = worst.histogram()
        n = fa.width * fa.height - h[0]
        top = max(i for i, c in enumerate(h) if c)
        print("%dx%d: %d of %d pixels differ, by up to %d levels in a channel"
              % (fa.width, fa.height, n, fa.width * fa.height, top))
        bad = 1
    return bad

cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "dither":
    for p in args:
        dither(p)
elif cmd == "compare":
    sys.exit(compare(args[0], args[1]))
elif cmd == "noalpha":
    sys.exit(1 if "A" in Image.open(args[0]).getbands() else 0)
else:
    sys.exit("unknown command " + cmd)
'
py() { python3 -I -c "$PY" "$@"; }

TMP="$(mktemp -d)"
trap 'if [ "$?" = 0 ]; then rm -rf "$TMP"; else echo "    this run'"'"'s temporary folder is left for a look: $TMP" >&2; fi' EXIT

# The rounded composition: the gilded master clipped to corners of 24 in 108. It is made here from
# the master's own text (a clip path before its gradient, everything after the gradient inside the
# clip), so the master stays the one source of the large icons. Each half of that cut is checked:
# if the master's layout ever changes, this fails loudly instead of rendering something else.
gilded_text="$(<"$GILDED")"
case "$gilded_text" in
  "<svg "*'viewBox="0 0 108 108"'*"</radialGradient>"*"</svg>") ;;
  *) echo "$GILDED: expected one <svg> in a 108 box with its gradient first; the rounded icons cannot be cut from it" >&2; exit 1 ;;
esac
case "$gilded_text" in
  *'id="c"'*|*"clip-path"*) echo "$GILDED: already carries a clip; the rounded icons cannot be cut from it" >&2; exit 1 ;;
esac
head_part="${gilded_text%%</radialGradient>*}</radialGradient>"
body_part="${gilded_text#*</radialGradient>}"
body_part="${body_part%</svg>}"
svg_open="${head_part%%>*}>"
gradient="${head_part#*>}"
ROUNDED="$TMP/andvari-mark-gilded-rounded.svg"
printf '%s<clipPath id="c"><rect width="108" height="108" rx="24"/></clipPath>%s<g clip-path="url(#c)">%s</g></svg>\n' \
  "$svg_open" "$gradient" "$body_part" > "$ROUNDED"
for needle in 'rx="24"' '<path ' 'url(#pg)'; do
  grep -qF "$needle" "$ROUNDED" || {
    echo "the rounded composition lost the clip, the rune or the ground; is $GILDED still one gradient, one ground and the rune?" >&2
    exit 1
  }
done

# In --check mode every output is written under $OUT (a mirror of the tree's layout) and compared
# afterwards; otherwise $OUT is the tree itself.
OUT="$REPO_DIR"
if [ "$CHECK" = 1 ]; then
  OUT="$TMP/tree"
  mkdir -p "$OUT/web/public" "$OUT/extension/icons" "$OUT/app-desktop/icons" \
           "$OUT/app-desktop/src/main/resources" "$OUT/app-ios/Andvari/Assets.xcassets/AppIcon.appiconset"
fi
GENERATED=()
TO_DITHER=()

# render SOURCE PX PATH [dither]
render() {
  rsvg-convert -w "$2" -h "$2" "$1" -o "$OUT/$3"
  GENERATED+=("$3")
  [ "${4:-}" = dither ] && TO_DITHER+=("$OUT/$3")
  return 0
}
copy() { cp "$1" "$OUT/$2"; GENERATED+=("$2"); }
# the source for a small size: the pixel-fitted tile at 16, 24, 32; the small tile at 48, 64
small_src() { case "$1" in 16|24|32) echo "$BRAND/andvari-mark-$1.svg" ;; *) echo "$TILE" ;; esac; }

echo "==> web"
copy "$TILE" web/public/favicon.svg
render "$GILDED" 180 web/public/apple-touch-icon.png dither
render "$ROUNDED" 192 web/public/icon-192.png
render "$ROUNDED" 512 web/public/icon-512.png dither
render "$GILDED" 512 web/public/icon-512-maskable.png dither

echo "==> extension"
for s in 16 32 48; do render "$(small_src "$s")" "$s" "extension/icons/icon${s}.png"; done
render "$ROUNDED" 128 extension/icons/icon128.png

echo "==> desktop"
copy "$TILE" app-desktop/icons/andvari.svg
render "$ROUNDED" 512 app-desktop/icons/andvari.png dither
render "$ROUNDED" 256 app-desktop/src/main/resources/andvari.png
ico_frames=()
for s in 16 24 32 48 64 128 256; do
  if [ "$s" -ge 128 ]; then src="$ROUNDED"; else src="$(small_src "$s")"; fi
  rsvg-convert -w "$s" -h "$s" "$src" -o "$TMP/ico-$s.png"
  ico_frames+=("$TMP/ico-$s.png")
done
convert "${ico_frames[@]}" "$OUT/app-desktop/icons/andvari.ico"
GENERATED+=("app-desktop/icons/andvari.ico")

echo "==> iPhone"
IOS_ICON="app-ios/Andvari/Assets.xcassets/AppIcon.appiconset/icon-1024.png"
render "$GILDED" 1024 "$IOS_ICON" dither

py dither "${TO_DITHER[@]}"
py noalpha "$OUT/$IOS_ICON" || { echo "$IOS_ICON came out with an alpha channel; the App Store refuses it" >&2; exit 1; }

if [ "$CHECK" = 0 ]; then
  echo "==> done; git status will show what moved"
  exit 0
fi

# --- --check: compare the fresh renders with the committed files, by decoded pixels -----------
# Pixels, not bytes: another PNG encoder (or another version of this one) writes other bytes for
# the same picture, and that must not fail the check; a single changed pixel must.
stale=()
for f in "${GENERATED[@]}"; do
  [ -f "$REPO_DIR/$f" ] || { stale+=("$f (missing from the tree)"); continue; }
  case "$f" in
    *.svg) cmp -s "$OUT/$f" "$REPO_DIR/$f" || stale+=("$f (not a verbatim copy of its source)") ;;
    *)
      if ! why="$(py compare "$OUT/$f" "$REPO_DIR/$f")"; then
        stale+=("$f: ${why//$'\n'/; }")
      fi
      ;;
  esac
done
if [ "${#stale[@]}" -gt 0 ]; then
  echo "    BRAND ICONS STALE: these do not match a fresh render of the sources in assets/brand/:" >&2
  printf '      %s\n' "${stale[@]}" >&2
  echo "    Run scripts/gen-brand-icons.sh and commit what it changes (a source changed with no" >&2
  echo "    re-render, or a rendered icon edited by hand, is what this catches)." >&2
  exit 1
fi
echo "==> every brand icon matches a fresh render of the sources in assets/brand/"
