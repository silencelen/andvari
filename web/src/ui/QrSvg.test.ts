import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { QrSvg, qrPathD } from "./QrSvg";

describe("qrPathD (matrix → run-length SVG path, QUIET=4)", () => {
  it("offsets a single dark module by the quiet zone", () => {
    expect(qrPathD([[true]])).toBe("M4 4h1v1h-1z");
  });

  it("merges a horizontal run into one rect", () => {
    expect(qrPathD([[true, true, true]])).toBe("M4 4h3v1h-3z");
  });

  it("splits a run across a light gap", () => {
    expect(qrPathD([[true, false, true]])).toBe("M4 4h1v1h-1zM6 4h1v1h-1z");
  });

  it("emits nothing for an all-light matrix", () => {
    expect(qrPathD([[false, false], [false, false]])).toBe("");
  });
});

describe("QrSvg", () => {
  const html = renderToStaticMarkup(
    createElement(QrSvg, { modules: [[true, false], [false, true]], ariaLabel: "test QR" }),
  );

  it("renders one accessible svg with the quiet-zone viewBox", () => {
    expect(html).toContain('viewBox="0 0 10 10"'); // 2 modules + 4*2 quiet
    expect(html).toContain('role="img"');
    expect(html).toContain('aria-label="test QR"');
  });

  it("draws dark-on-white: a white background rect and exactly one black path", () => {
    expect(html).toContain('fill="#fff"');
    expect(html).toContain('fill="#000"');
    expect((html.match(/<path /g) ?? []).length).toBe(1);
    expect(html).toContain("crispEdges");
    expect(html).toContain('class="qr-card"');
  });
});
