/**
 * Cheapest honest check for "are we on a private origin?". The web client is served
 * same-origin by the andvari server (session.defaultBaseUrl() is ""), so the page
 * origin IS the server origin; the deployment story (spec 05 T6/T11) is: tailnet
 * origin = `*.ts.net` (or a raw Tailscale 100.64/10 address), LAN = RFC1918 /
 * localhost / mDNS-style suffixes — anything else is the public break-glass origin
 * (Cloudflare-fronted). This is a UI posture knob, not a security boundary: it decides
 * which surfaces to ADVERTISE (export buttons, device-install pointers), never what a
 * session may do.
 *
 * Shared by export/plan.ts (break-glass export suppression, spec 07 intro) and
 * ui/Devices.tsx (the devices hub hides tailnet pointers on the public origin).
 * DOM-free so it unit-tests in the node vitest environment.
 */
export function isPrivateOrigin(origin: string): boolean {
  let host: string;
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return false; // unparseable origin — fail toward hiding (SHOULD-level feature)
  }
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1); // IPv6 literal
  if (host === "localhost" || host === "::1") return true;
  if (host.endsWith(".ts.net")) return true; // Tailscale MagicDNS (tailnet origin)
  if (host.endsWith(".local") || host.endsWith(".lan") || host.endsWith(".home.arpa") || host.endsWith(".internal")) return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true; // loopback
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true; // RFC1918
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true; // RFC1918
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(host)) return true; // RFC1918
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/.test(host)) return true; // Tailscale CGNAT 100.64/10
  return false;
}
