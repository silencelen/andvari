/**
 * The question the popup asks before it fills a login saved for another site than the page's, as the worker hands it
 * over: the names it shows, and the token the person's yes is sent back with.
 *
 * DOM-free: the worker builds it; the popup only shows it.
 */
import { ANOTHER_SITE, FILL_PAGE_NOT_SECURE } from "./copy";
import { fillApproved } from "./errors";
import { isPlainHttp, normalizeHost, type PslResolve } from "./urimatch";

export interface OtherSiteQuestion {
  /** Where the login is saved: its host, with its scheme where the page has the same host. */
  savedFor: string;
  /**
   * This page: its host; its origin where the login's host is the same (the schemes are then what differs); and on a page
   * served over plain http, its origin marked as not secure.
   */
  page: string;
  /** The registrable domain of the page's host, where the host is longer than it (a long host can push it out of view). */
  domain: string | null;
  /** What the popup sends back with the person's yes: it holds for this login on this page only. */
  confirm: string;
}

/** The token of a yes for the login [itemId] on the page at the top-level origin [top]. */
export function otherSiteConfirmation(itemId: string, top: string): string {
  return `${top} ${itemId}`;
}

/** The scheme an address was saved with, lower-cased, or null for one saved without it. */
function schemeOf(uri: string): string | null {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(uri.trim());
  return m === null ? null : m[1]!.toLowerCase();
}

/**
 * The question for the login [itemId], saved for [saved], on the page whose top-level origin is [top] (canonical, as the
 * worker read it). It never names the same thing twice: where the two hosts are the same, the schemes are named.
 */
export function otherSiteQuestion(itemId: string, saved: readonly string[], top: string, resolve: PslResolve): OtherSiteQuestion {
  const pageHost = normalizeHost(top) ?? top;
  const savedUri = saved.find((u) => normalizeHost(u) !== null) ?? null;
  const savedHost = savedUri === null ? null : normalizeHost(savedUri);
  const sameHost = savedHost !== null && savedHost === pageHost;
  const savedScheme = savedUri === null ? null : schemeOf(savedUri);
  const savedFor = savedHost === null ? ANOTHER_SITE : sameHost && savedScheme !== null ? `${savedScheme}://${savedHost}` : savedHost;
  const page = isPlainHttp(top) ? fillApproved(FILL_PAGE_NOT_SECURE, top) : sameHost ? top : pageHost;
  const r = resolve(pageHost);
  const domain = r.kind === "registrable" && r.domain !== pageHost ? r.domain : null;
  return { savedFor, page, domain, confirm: otherSiteConfirmation(itemId, top) };
}
