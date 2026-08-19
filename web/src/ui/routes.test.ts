import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ROUTED_VIEWS, hashToView, viewToHash } from "./routes";

/**
 * Web route structure (owner dev-note 2026-08-19). The mapping is pure; what has to HOLD is the
 * doctrine around it — views only, mirror-not-navigation, one popstate consumer — which lives as
 * wiring inside Vault.tsx with no seam to call. Mapping tests first, source pins after (the
 * vault-layers idiom).
 */

describe("routes — the view ↔ fragment mapping", () => {
  it("round-trips every routed view, with the home view as the BARE url", () => {
    for (const v of ROUTED_VIEWS) expect(hashToView(viewToHash(v), true)).toBe(v);
    expect(viewToHash("vault")).toBe("");
    expect(viewToHash("health")).toBe("#/health");
  });

  it("is total: garbage, enroll-shaped, and #recover fragments all land on the home view", () => {
    for (const h of ["", "#", "#/", "#/nope", "#recover", "#gibberish", "#/health/extra", "/health", "health"]) {
      expect(hashToView(h, true), `hash ${JSON.stringify(h)}`).toBe("vault");
    }
  });

  it("gates #/admin on actually being an admin", () => {
    expect(hashToView("#/admin", true)).toBe("admin");
    expect(hashToView("#/admin", false)).toBe("vault");
  });
});

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
const routesTs = readFileSync(here("./routes.ts"), "utf8");

describe("routes — the wiring doctrine, pinned on the source", () => {
  it("the routed-view list stays in lockstep with Vault's View union", () => {
    const m = vaultTsx.match(/type View = ([^;]+);/);
    expect(m, "Vault's View union moved — update the pin").not.toBeNull();
    const viewUnion = [...m![1]!.matchAll(/"([a-z]+)"/g)].map((x) => x[1]).sort();
    expect(viewUnion).toEqual([...ROUTED_VIEWS].sort());
  });

  it("ONE popstate consumer — the back guard; the route mirror never listens", () => {
    expect(vaultTsx.match(/addEventListener\("popstate"/g)).toHaveLength(1);
    expect(routesTs).not.toContain("addEventListener");
  });

  it("the mirror writes are replaceState-only; every pushState stays inside the guard", () => {
    // pushState appears exactly twice, both sentinel pushes ({ andvariBack: true }).
    const pushes = vaultTsx.match(/history\.pushState\(/g) ?? [];
    expect(pushes).toHaveLength(2);
    expect(vaultTsx.match(/pushState\(\{ andvariBack: true \}/g)).toHaveLength(2);
    // No direct location.hash assignment anywhere (that would PUSH a history entry).
    expect(vaultTsx).not.toMatch(/location\.hash\s*=/);
  });

  it("views only — no layer or item state ever reaches the fragment", () => {
    // The mirror derives from `view` alone: the module's CODE knows none of the layer
    // setters/ids (its doc comment legitimately NAMES them to state the boundary — strip
    // comments before scanning, the a11y-controls code() idiom).
    const code = routesTs
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .split("\n")
      .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
      .join("\n");
    for (const leak of ["selected", "editing", "importOpen", "exportMode", "sharingSettingsVaultId", "itemId", "query"]) {
      expect(code, `routes.ts must not know about ${leak}`).not.toContain(leak);
    }
    expect(vaultTsx).toContain("const routeHash = useRef(viewToHash(view));");
  });

  it("the mount reads the fragment back (the refresh-returns-here half of the feature)", () => {
    expect(vaultTsx).toContain('useState<View>(() => hashToView(typeof window === "undefined" ? "" : window.location.hash, isAdmin))');
  });
});
