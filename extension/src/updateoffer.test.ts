// node --test. Security review 2026-10, branch A15 (step 0): the "Download & reload" link.
//
// The update offer is verified when it is fetched (updateverify.ts) but was trusted on read: updateStatus re-checked
// only the version, and the popup linked whatever URL was stored. A record written by anything but the verified fetch
// path (pre-A15: any content script, through chrome.storage.local) put an arbitrary link into the extension's own UI.
// The link now has exactly one shape, `${DEFAULT_SERVER_URL}/downloads/<basename>`, only while the current server is
// the default (the only origin whose /downloads the pinned key signs), and the stored record is re-checked on every
// read, in the worker AND in the popup.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { DEFAULT_SERVER_URL } from "./serverurl.ts";
import { offerDownloadUrl, readUpdateOffer } from "./updateoffer.ts";

const D = DEFAULT_SERVER_URL;

test("the manifest's relative /downloads/<basename> becomes an absolute link on the default origin", () => {
  assert.equal(offerDownloadUrl("/downloads/andvari-extension-chrome-0.29.0.zip", D), `${D}/downloads/andvari-extension-chrome-0.29.0.zip`);
  assert.equal(offerDownloadUrl("/downloads/andvari-extension-firefox-0.29.0.xpi", D), `${D}/downloads/andvari-extension-firefox-0.29.0.xpi`);
  // The absolute form is accepted only when it already names the default origin's /downloads/.
  assert.equal(offerDownloadUrl(`${D}/downloads/andvari-extension-chrome-0.29.0.zip`, D), `${D}/downloads/andvari-extension-chrome-0.29.0.zip`);
});

test("refused: any other origin, any other path, and anything that is not a plain basename", () => {
  const bad: unknown[] = [
    "https://evil.example/downloads/andvari-extension-chrome-0.29.0.zip",
    "http://andvari.monahanhosting.com/downloads/x.zip", // scheme
    `${D}.evil.example/downloads/x.zip`, // look-alike host
    `${D}:8443/downloads/x.zip`, // port
    `${D}/download/x.zip`,
    `${D}/downloads/`,
    `${D}/downloads/sub/x.zip`,
    "/downloads/../api/v1/x",
    "/downloads/..",
    "/downloads/.hidden",
    "/downloads/x.zip?a=1",
    "/downloads/x.zip#frag",
    "/downloads/x%2F..zip",
    "/downloads/x\\y.zip",
    "/downloads/x y.zip",
    "/downloads/" + "a".repeat(200),
    "//evil.example/downloads/x.zip", // protocol-relative
    "javascript:alert(1)",
    "data:text/html,x",
    "downloads/x.zip",
    "",
    null,
    undefined,
    42,
    { href: "/downloads/x.zip" },
  ];
  for (const u of bad) assert.equal(offerDownloadUrl(u, D), null, JSON.stringify(u));
});

test("no link at all while the current server is not the default (its /downloads is not what the pinned key signs)", () => {
  for (const server of ["https://self.example", "http://192.168.1.9:8080", `${D}:8443`, "https://andvari.monahanhosting.com.evil.example"]) {
    assert.equal(offerDownloadUrl("/downloads/andvari-extension-chrome-0.29.0.zip", server), null, server);
    assert.equal(offerDownloadUrl(`${D}/downloads/andvari-extension-chrome-0.29.0.zip`, server), null, server);
  }
});

test("readUpdateOffer re-checks a STORED offer on every read: version, server, and both links", () => {
  const good = { latest: "0.29.0", chromeUrl: `${D}/downloads/andvari-extension-chrome-0.29.0.zip`, firefoxUrl: `${D}/downloads/andvari-extension-firefox-0.29.0.xpi` };
  assert.deepEqual(readUpdateOffer(good, "0.28.1", D), good);
  // A planted record: newer version, links elsewhere. The offer may stand (the version rule passes) but no link does.
  const planted = { latest: "0.29.0", chromeUrl: "https://evil.example/andvari.zip", firefoxUrl: "/downloads/../evil" };
  assert.deepEqual(readUpdateOffer(planted, "0.28.1", D), { latest: "0.29.0", chromeUrl: null, firefoxUrl: null });
  // The relative form a pre-A15 build might have stored is absolutized against the default, never another origin.
  assert.deepEqual(readUpdateOffer({ latest: "0.29.0", chromeUrl: "/downloads/a.zip", firefoxUrl: null }, "0.28.1", D), {
    latest: "0.29.0",
    chromeUrl: `${D}/downloads/a.zip`,
    firefoxUrl: null,
  });
  // Not newer than what is installed, not a version at all, or not an object: no offer.
  assert.equal(readUpdateOffer({ ...good, latest: "0.28.1" }, "0.28.1", D), null);
  assert.equal(readUpdateOffer({ ...good, latest: "0.20.0" }, "0.28.1", D), null);
  assert.equal(readUpdateOffer({ ...good, latest: "99.0.0-evil" }, "0.28.1", D), null);
  assert.equal(readUpdateOffer({ ...good, latest: 99 }, "0.28.1", D), null);
  for (const raw of [undefined, null, "0.29.0", [], 7]) assert.equal(readUpdateOffer(raw, "0.28.1", D), null, JSON.stringify(raw));
  // A non-default server shows no offer at all, whatever is stored.
  assert.equal(readUpdateOffer(good, "0.28.1", "https://self.example"), null);
});
