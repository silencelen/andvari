# andvari brand

The identity of every andvari surface: the apps' icons, the browser extension, the web vault, the
website, the store listings and this repository. The files named here are the sources; every icon
and picture is rendered from them. Inside the apps only the icon, the rune and the drawn name carry
the brand; the apps keep their platform's own text style and their own palette. `design-card.html`
shows all of it on one page (open it in a browser; it is generated from these files).

## The mark

**ᛅ**, the Younger Futhark rune *ár*, the "a" of andvari, cut as a carver cuts it: two bands with
their ends cut on a slant, as a knife leaves a rune in wood. Andvari is the dwarf of Norse myth who
kept a hoard of gold under a waterfall; the mark is his rune, carved into dark wood and gilded.

Geometry, in a 24-unit box (y down):

| Part | Corners |
|---|---|
| Stave | (10.7, 2.35) (13.3, 3.55) (13.3, 21.25) (10.7, 20.05) |
| Falling stroke | (4.85, 6.768) (19.15, 13.368) (19.15, 16.232) (4.85, 9.632) |

Both bands are 2.6 wide. The falling stroke drops 6 for every 13 across; the stave's ends are cut
on that slope and the stroke's ends on the line of the stave. Draw the stroke first and the stave
over it. The mark is never rotated, mirrored, outlined or given a shadow.

It has two drawings:

- **Gilded**, for icons from 128 px up and for large art: each band is a V-cut groove in two golds,
  lit from the upper left, so the far wall of each groove catches the light (the stave's right
  half, the falling stroke's lower half). `andvari-rune-gilded.svg`.
- **Flat**, one color, for 64 px and below, for one-color uses (notification and themed icons)
  and inside the apps. `andvari-rune.svg` draws in `currentColor`.

At 16, 24 and 32 px the flat rune is redrawn on the pixel grid, so the stave's edges fall on whole
pixels: `andvari-mark-16.svg`, `-24.svg`, `-32.svg`. Use those files at those sizes rather than
scaling another.

## The icon

The gilded rune on **polished hardwood**: a warm brown-black with a soft light from the upper left,
as on a lacquered panel. The rune is 64 units tall in a 108-unit square, centered on its own box,
so its farthest point stays inside Android's 66-unit safe circle. From 32 px down the ground is
flat hardwood and the rune flat.

| File | Use |
|---|---|
| `andvari-mark-gilded.svg` | the icon master: full bleed, for every surface that rounds its own corners (iOS, the stores) |
| `andvari-mark-flat.svg` | the same composition, flat, for one-color contexts that still want a tile |
| `andvari-mark.svg` | the small tile: flat rune on flat hardwood, corners rounded (5 of 24); favicons and 48 to 64 px |
| `andvari-mark-16.svg`, `-24.svg`, `-32.svg` | the small tile redrawn on the pixel grid |

## The name

**andvari**, always lowercase, also at the start of a sentence. The drawn wordmark is EB Garamond
at weight 620, 8/1000 em tighter than the font's own spacing, outlined: `wordmark.svg` draws in
`currentColor`, so it never depends on an installed font. One color, bone on dark and ink on
light; the gold belongs to the rune. As a mark, never set the name in another face or in two colors;
in running text it takes the text's own face. One place can't take the drawing: the browser
extension's panel inside other sites' pages, whose script has a strict size limit, shows the name as
plain text in one color.

## The line

**the keeper of the hoard**, lowercase, in EB Garamond, upright (never italic), at weight 430, in
the dim text color: under the stacked lockup, on store art and link previews. In app screens it is
set in the app's own text style.

## Lockups

| File | Use |
|---|---|
| `lockup-horizontal-{dark,light}.svg` | headers, the website's top bar, the README: the rune as tall as the d |
| `lockup-stacked-{dark,light}.svg` | first-run and lock screens, splash, social cards |
| `lockup-stacked-line-{dark,light}.svg` | the same with the line, for store art and the About box |

Keep clear space around a lockup at least the width of the rune on every side, and never place the
rune after the name.

## Typefaces

Brand surfaces only (the website, store art, link previews, documents, the README's pictures):

- **EB Garamond** (SIL Open Font License 1.1): the name, headlines, the line.
- **Alegreya Sans** (SIL Open Font License 1.1): everything you read: body text, captions, labels.

Both are served by the website from its own address, never from a font service. In pictures every
word is outlined, so a picture never depends on an installed font.

| Step | Face | Size / line height | Use |
|---|---|---|---|
| Display one | EB Garamond 600 | 56 px / 1.05 | the website's opening line; store-art headlines |
| Display two | EB Garamond 600 | 38 px / 1.1 | section headings |
| Display three | EB Garamond 600 | 26 px / 1.2 | card titles |
| Lead | Alegreya Sans 400 | 19 px / 1.55 | the line under a headline |
| Body | Alegreya Sans 400 | 17 px / 1.6 | everything you read |
| Small | Alegreya Sans 400 | 14 px / 1.5, dim | captions and notes |
| Label | Alegreya Sans 600 | 12 px, spaced capitals | eyebrows, store-art labels |

## Color

| Token | Dark | Light | Use |
|---|---|---|---|
| Ground | `#14120E` | `#F4EFE4` | the apps' and the website's ground |
| Text | `#EDE4D0` bone | `#2C2517` ink | the name, text (14.8:1, 13.2:1) |
| Text, dim | `#A79C85` | `#6B6047` | the line, secondary text (6.9:1, 5.4:1) |
| Gold | `#D0A94A` | `#7D5E14` | the rune, accents, links (8.4:1, 5.3:1) |
| Success | `#7FA86A` | `#4C7538` | done, saved (6.9:1, 4.7:1) |
| Warning | `#E08A4F` | `#A3521C` | needs care (7.1:1, 4.8:1) |
| Error | `#D97F6F` | `#B3402C` | failed, destructive: the apps' own (6.4:1, 5.0:1) |
| Info | `#8FA6C0` | `#3F5F82` | neutral notices (7.5:1, 5.8:1) |
| Gold, lit / shade | `#E9C978` / `#A8832F` | | the two walls of a gilded groove |
| Hardwood | `#1F1711` | | the icon ground at 32 px and below; wide dark surfaces |
| Polished hardwood | `#33261A` → `#1F1711` → `#120D09` | | radial, center 28 % across and 22 % down, radius 95 % |

The ratios are each color against its own ground (WCAG; text needs 4.5:1).

## Surfaces

Large fields (link previews, the website's hero, store art, the README's pictures) are **polished
hardwood with carved grooves**: hairlines on the rune's own slope (6 down for 13 across), 22 px
apart at 1200 px wide, each a shaded line (black, 28 %) with a lit line (`#F3D9A0`, 7 %) 1.6 px
below it, so the grooves are lit like the rune's. Up close they read as carved wood; from afar,
as plain hardwood. `grooves.svg` covers any box.

## Screenshots

App screens sit in a **plain phone outline in warm black** (`#0B0A08`; bezel 2.4 % of the screen's
height; corners 7.5 % outside, 5.5 % on the screen; a `#4A3F2E` edge) or a plain computer window
(the same black, a slim title bar, no maker's controls), with a soft shadow, on polished hardwood
with grooves. The outlines are drawn for andvari and are not pictures of any company's hardware.
Screens show a made-up person (everyone at `example.com`); other sites appear only by name, never
with their logos.

## Templates

| Template | Size |
|---|---|
| Link preview (Open Graph) | 1200 × 630 |
| GitHub social preview | 1280 × 640 |
| Google Play feature graphic | 1024 × 500 |
| Google Play phone screenshot | 1080 × 1920 |
| App Store screenshot, 6.9-inch | 1320 × 2868 |
| Hero: a computer and a phone (README, website) | 1600 × 900 |
| Chrome Web Store small tile / marquee / screenshot | 440 × 280, 1400 × 560, 1280 × 800 |

## Voice

Plain, honest sentences in US English. Say what andvari does and what it can't. The hoard is the
one metaphor, kept to the line and small places in the apps ("Search the hoard"); everything about
safety is said plainly. No exclamation marks, no superlatives, no claims the design can't back.

## The marks and the licenses (decided on 21 November 2026)

andvari's code is free software: the server under the GNU Affero GPL v3.0-or-later, the apps, the
shared core and the tools under the GNU GPL v3.0-or-later (see `LICENSING.md`). Those licenses cover
the code. They do not grant rights to the name **andvari**, the rune mark or the drawn wordmark,
which identify this project.

You may use the name and the mark to refer to andvari: to say that your server runs andvari, that
something works with it, or to write about it. Please don't use them as the name or the icon of a
modified build, a fork, or another product or service, or in a way that suggests the andvari project
made or endorses something it didn't. If you distribute a modified version, give it its own name and
icon.

The typefaces keep their own license (`OFL-EBGaramond.txt`, `OFL-AlegreyaSans.txt`); the outlined
wordmark is a drawing made with EB Garamond.
