import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Field } from "./Field";

/**
 * P1 label association (a11yweb-01), proven statically: renderToStaticMarkup runs no
 * effects but DOES emit the useId-derived id and the label's htmlFor, so the for⇄id
 * pairing — the whole point of Field — is a pure string assertion (house pattern:
 * Devices.test.ts / QrSvg.test.ts).
 */
describe("Field — label ⇄ control association", () => {
  const idOf = (html: string, tag: string) => html.match(new RegExp(`<${tag}[^>]*\\bid="([^"]+)"`))?.[1];
  const forOf = (html: string) => html.match(/<label[^>]*\bfor="([^"]+)"/)?.[1];

  it("points <label for> at the injected id of an <input> child", () => {
    const html = renderToStaticMarkup(createElement(Field, { label: "Email", children: createElement("input", { type: "email" }) }));
    const forAttr = forOf(html);
    const inputId = idOf(html, "input");
    expect(forAttr).toBeTruthy();
    expect(inputId).toBeTruthy();
    expect(forAttr).toBe(inputId); // the association, not merely "an id exists"
    expect(html).toContain(">Email</label>");
  });

  it("associates a <select> child the same way", () => {
    const html = renderToStaticMarkup(createElement(Field, { label: "Role", children: createElement("select") }));
    expect(forOf(html)).toBe(idOf(html, "select"));
  });

  it("associates a <textarea> child the same way", () => {
    const html = renderToStaticMarkup(createElement(Field, { label: "Notes", children: createElement("textarea") }));
    expect(forOf(html)).toBe(idOf(html, "textarea"));
  });

  it("does not clobber the child's other props", () => {
    const html = renderToStaticMarkup(
      createElement(Field, { label: "Password", children: createElement("input", { type: "password", className: "mono" }) }),
    );
    expect(html).toContain('type="password"');
    expect(html).toContain('class="mono"');
  });

  it("renders a hint after the control, inside the same .field block", () => {
    const html = renderToStaticMarkup(
      createElement(Field, {
        label: "New password",
        children: createElement("input", { type: "password" }),
        hint: createElement("span", { className: "muted" }, "too weak"),
      }),
    );
    // hint text present, and it follows the input (control is named before the advisory).
    expect(html).toContain("too weak");
    expect(html.indexOf("<input")).toBeLessThan(html.indexOf("too weak"));
  });

  it("gives distinct ids to two Fields (useId is per-instance)", () => {
    const html = renderToStaticMarkup(
      createElement(
        "div",
        null,
        createElement(Field, { label: "A", children: createElement("input") }),
        createElement(Field, { label: "B", children: createElement("input") }),
      ),
    );
    const ids = [...html.matchAll(/<label[^>]*\bfor="([^"]+)"/g)].map((m) => m[1]);
    expect(ids).toHaveLength(2);
    expect(ids[0]).not.toBe(ids[1]);
  });
});
