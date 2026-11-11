// Safari build only: the first script of the background page (manifest.safari.json lists it before background.js).
// Nobody can attach a debugger to Safari on a phone, so this records, in storage.local, when the page loaded and any
// error it throws: the message, the place and the stack, never data. The popup's Details shows them when the worker
// does not answer (safari-diag.js). Classic script, not bundled, so it runs even if background.js fails to parse.
// These keys are display-only and carry no trust: nothing but that Details panel reads them.
(function () {
  "use strict";
  var api = typeof browser !== "undefined" ? browser : typeof chrome !== "undefined" ? chrome : null;
  var area = api && api.storage && api.storage.local;
  var errors = [];
  function put(items) {
    try {
      var p = area && area.set(items);
      if (p && typeof p.catch === "function") p.catch(function () {});
    } catch (e) {
      /* no storage: nothing to record into */
    }
  }
  function record(kind, message, where, stack) {
    if (errors.length >= 5) return; // the first few name the cause; later ones are its echoes
    errors.push({
      at: new Date().toISOString(),
      kind: kind,
      message: String(message).slice(0, 300),
      where: where ? String(where).slice(0, 200) : null,
      stack: stack ? String(stack).slice(0, 1500) : null,
    });
    put({ "diag.backgroundErrors": errors });
  }
  put({ "diag.backgroundLoadedAt": new Date().toISOString(), "diag.backgroundReadyAt": null, "diag.backgroundErrors": [] });
  self.addEventListener("error", function (e) {
    record("error", e.message || (e.error && e.error.message) || "error", (e.filename || "") + ":" + (e.lineno || 0) + ":" + (e.colno || 0), e.error && e.error.stack);
  });
  self.addEventListener("unhandledrejection", function (e) {
    var r = e.reason;
    record("unhandledrejection", (r && r.message) || r, null, r && r.stack);
  });
  // background.js calls these: a guarded top-level registration that failed, and the end of its evaluation.
  self.__andvariBootRecord = function (label, e) {
    record("guarded: " + label, (e && e.message) || e, null, e && e.stack);
  };
  self.__andvariBootReady = function () {
    put({ "diag.backgroundReadyAt": new Date().toISOString() });
  };
})();
