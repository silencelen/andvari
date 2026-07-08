/**
 * Pure QR renderer: module matrix (from vendor/qrcode-generator's qrModules) →
 * inline SVG. No state, no effects — testable via renderToStaticMarkup in the
 * node vitest environment.
 *
 * Deliberate choices:
 * - 4-module quiet zone baked into the viewBox (the QR spec minimum; scanners
 *   genuinely fail without it).
 * - ONE merged <path> of run-length rects + shape-rendering="crispEdges": crisp
 *   at any CSS size, and ~n DOM nodes fewer than per-module <rect>s.
 * - Always dark-on-white regardless of app theme (the .qr-card wrapper is
 *   hard-coded white): an inverted QR is a coin-flip across scanner apps.
 */

const QUIET = 4; // modules of white border on every side

/** One SVG path drawing every dark module, rows merged into horizontal runs. */
export function qrPathD(modules: boolean[][]): string {
  let d = "";
  for (let y = 0; y < modules.length; y++) {
    const row = modules[y] ?? [];
    const w = row.length; // per-row width — QR matrices are square, but don't assume it
    for (let x = 0; x < w; x++) {
      if (!row[x]) continue;
      let run = 1;
      while (x + run < w && row[x + run]) run++;
      d += `M${x + QUIET} ${y + QUIET}h${run}v1h-${run}z`;
      x += run - 1;
    }
  }
  return d;
}

export function QrSvg({ modules, ariaLabel }: { modules: boolean[][]; ariaLabel: string }) {
  const size = modules.length + QUIET * 2;
  return (
    <div className="qr-card">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={ariaLabel}
        shapeRendering="crispEdges"
      >
        <rect width={size} height={size} fill="#fff" />
        <path d={qrPathD(modules)} fill="#000" />
      </svg>
    </div>
  );
}
