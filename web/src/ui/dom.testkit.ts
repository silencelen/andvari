import { Window } from "happy-dom";
import { act, type ReactElement } from "react";

/**
 * Drawing a screen inside a test: a page (happy-dom) is put in place as this test's `window` and `document`, the component
 * is drawn into it by React itself, and the person's acts are made as a browser makes them. The page's own names that Node
 * lacks are added for the test and taken away by {@link closePage}; Node's own (its URL, fetch, storage of the test) stay.
 * happy-dom leaves a key's default action to the browser, so {@link pressEnter} does what the HTML standard has a browser
 * do with Enter: a focused button is activated (clicked), and in a text field of a form the form's default button (its
 * first submit button) is clicked, or the form is submitted where it has none.
 */
const g = globalThis as Record<string, unknown>;
let page: Window | null = null;
let added: string[] = [];

/** Puts a page in place for this test file (before anything is drawn). */
export function openPage(url = "https://vault.example.org/"): Window {
  if (page) return page;
  page = new Window({ url });
  added = [];
  for (const k of [...Object.getOwnPropertyNames(page), "window", "document"]) {
    if (k in g && k !== "window" && k !== "document") continue;
    try {
      g[k] = k === "window" ? page : (page as unknown as Record<string, unknown>)[k];
      added.push(k);
    } catch {
      /* a name the page does not let be read outside itself */
    }
  }
  g.IS_REACT_ACT_ENVIRONMENT = true;
  return page;
}

/** Takes the page and every name it added away again. */
export async function closePage(): Promise<void> {
  if (!page) return;
  for (const k of added) delete g[k];
  delete g.IS_REACT_ACT_ENVIRONMENT;
  await page.happyDOM.close();
  page = null;
}

const win = (): Window => {
  if (!page) throw new Error("openPage() first");
  return page;
};

export type Drawn = { readonly page: HTMLElement; unmount(): Promise<void> };

export async function draw(el: ReactElement): Promise<Drawn> {
  // React's page code reads the page's names when it is loaded: loaded once the page is in place.
  const { createRoot } = await import("react-dom/client");
  const page = win().document.createElement("div") as unknown as HTMLElement;
  win().document.body.appendChild(page as never);
  const root = createRoot(page);
  await act(async () => root.render(el));
  return {
    page,
    unmount: async () => {
      await act(async () => root.unmount());
      page.remove();
    },
  };
}

/** Lets awaited work (a count, a fake server's answer) settle and React draw what it set. */
export async function settle(times = 3): Promise<void> {
  for (let i = 0; i < times; i++) await act(async () => new Promise((r) => setTimeout(r, 0)));
}

export async function click(el: Element): Promise<void> {
  await act(async () => (el as HTMLElement).click());
  await settle();
}

/** Types [text] into [input] as a person does: the field gets focus, then its value changes with an `input` event. */
export async function type(input: HTMLInputElement, text: string): Promise<void> {
  await act(async () => {
    input.focus();
    const set = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")?.set;
    set?.call(input, text);
    input.dispatchEvent(new (win().Event)("input", { bubbles: true }) as unknown as Event);
  });
}

/** The element that has the focus now (the page's body where none has). */
export function focused(): Element | null {
  return win().document.activeElement as unknown as Element | null;
}

/** The Enter key on the focused element (or [at]), with the browser's default action where the page did not cancel it. */
export async function pressEnter(at?: Element): Promise<void> {
  const w = win();
  const target = (at ?? focused() ?? w.document.body) as HTMLElement;
  await act(async () => {
    const down = new w.KeyboardEvent("keydown", { key: "Enter", code: "Enter", bubbles: true, cancelable: true }) as unknown as Event;
    if (!target.dispatchEvent(down)) return;
    if (target instanceof (w.HTMLButtonElement as unknown as typeof HTMLButtonElement)) {
      if (!target.disabled) target.click();
      return;
    }
    if (target instanceof (w.HTMLInputElement as unknown as typeof HTMLInputElement) && target.form) {
      const form = target.form;
      const submitter = [...form.querySelectorAll("button, input[type=submit]")].find((b) => (b as HTMLButtonElement).type === "submit") as HTMLButtonElement | undefined;
      if (submitter) {
        if (!submitter.disabled) submitter.click();
      } else form.requestSubmit();
    }
  });
  await settle();
}

/** The buttons whose text is [text]. */
export function buttonsNamed(page: ParentNode, text: string): HTMLButtonElement[] {
  return [...page.querySelectorAll("button")].filter((b) => b.textContent === text);
}

export function buttonNamed(page: ParentNode, text: string): HTMLButtonElement {
  const all = buttonsNamed(page, text);
  if (all.length !== 1) throw new Error(`${all.length} buttons named ${text}`);
  return all[0] as HTMLButtonElement;
}
