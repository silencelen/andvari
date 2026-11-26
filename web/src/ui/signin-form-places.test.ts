import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");

/** The text of [from] up to (not including) the first [to] after it. */
function slice(text: string, from: string, to: string): string {
  const a = text.indexOf(from);
  expect(a, from).toBeGreaterThanOrEqual(0);
  const b = text.indexOf(to, a + from.length);
  expect(b, to).toBeGreaterThan(a);
  return text.slice(a, b);
}

/**
 * The sign-in form's record (tabsession.ts signInForm) lives as long as its `SignIn` component stays mounted. The web's
 * tests have no drawn page, so the places that mount the form, and what keeps or replaces it there, are read from the
 * source: between two submits of one form nothing the submit does replaces it. What only a drawn page could prove (that
 * React keeps the instance across those renders) is said in the comments.
 */
describe("the sign-in form's record lives across the submits of one form", () => {
  const welcome = src("./Welcome.tsx");
  const signIn = slice(welcome, "function SignIn(", "\nfunction ");
  const unlock = slice(welcome, "function Unlock(", "\nfunction ");
  const fresh = slice(welcome, "export function FreshStart(", "\nfunction ");

  it("one record per mounted form, made once and kept by the component", () => {
    // useRef keeps the first value it was given for the life of the instance: the record is made once per mount.
    expect(signIn).toContain("const form = useRef(signInForm(ctx.client, tokensKeptAcrossLock));");
    expect(welcome.split("signInForm(").length - 1, "the record is made in SignIn alone").toBe(1);
    // Every submit goes through that record.
    expect(signIn).toContain("const { flow, replaces } = form.current.submit();");
  });

  it("the form is mounted at three places, none with a key, and a submit changes none of what chooses between them", () => {
    const mounts = welcome.split("\n").filter((l) => l.includes("<SignIn "));
    expect(mounts).toHaveLength(3);
    for (const m of mounts) expect(m, "a key would replace the form at each change of it").not.toContain("key=");
    // The first screen: under its own `screen` state, which only the person's taps change (Back, the forgotten-password
    // link); SignIn is given no way to change it.
    expect(fresh).toContain('{screen === "signin" && (');
    expect(mounts.filter((m) => m.includes("initialEmail={knownEmail}"))).toHaveLength(1);
    expect(signIn).not.toContain("setScreen");
    // The unlock card: one place where the server ended a session that the offline copy kept, one for a sign-in without
    // tokens (no offline copy) or asked for from the card. Only the first depends on the copy being on, and with the copy
    // on no record names anything (tabsession-replaced.test.ts), so a form moved between the two loses nothing.
    expect(unlock).toContain("if (endedByServer(session)) {");
    expect(unlock).toContain("if (!session.tokens || signInInstead) {");
    expect(src("./sessionend.ts")).toContain("return s !== null && s.tokens === null && tokensKeptAcrossLock(s.userId);");
    // signInInstead is set by the unlock card's own button, before its form is shown, and never back.
    expect(unlock.split("setSignInInstead(").length - 1).toBe(1);
    expect(unlock).toContain("setSignInInstead(true)");
  });

  it("a submit that keeps the form calls neither the vault's opening nor the way out: only an opened account and the kit's time limit leave it", () => {
    const submit = slice(signIn, "const submit = async", "if (capture) {");
    // enter() opens the vault (the phase changes and the form goes, as it should); it is called only for "opened".
    expect(submit.split("await enter(").length - 1).toBe(1);
    expect(slice(submit, 'case "opened": {', 'case "keys_not_this_account":')).toContain("await enter(");
    expect(submit).not.toContain("onForget(");
    expect(submit).not.toContain("onReady(");
  });

  it("above the form: the card's pin check and the welcome card's key change only with what no submit of the form changes", () => {
    // PinSettled checks again only when whether a session is held changes (a phase change from the first screen to the
    // unlock card, which replaces the form anyway).
    expect(slice(welcome, "function PinSettled(", "\nfunction ")).toContain("}, [ctx, holding]);");
    // The welcome card is keyed by a sign-in this browser ended by itself (App endByClient: the kit's time limit, the
    // operator's account): a way out, after which the form's sign-in is over.
    const app = src("./App.tsx");
    expect(app).toContain('key={phase.kind === "unlock" && phase.endedHere !== undefined ? `ended-here-${phase.endedHere}` : "welcome"}');
    expect(app.split("endedHere: endedHereSeq.current").length - 1).toBe(1);
    expect(slice(app, "const endByClient = useCallback(", "\n  );")).toContain("endedHere: endedHereSeq.current");
  });
});
