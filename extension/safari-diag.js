// Safari build only: what safari-boot.js recorded about the background page, for the popup's Details. Classic script,
// loaded by the popup on demand. It reads three display-only keys from storage.local and nothing else.
(function () {
  "use strict";
  self.__andvariBackgroundDiag = function () {
    var api = typeof browser !== "undefined" ? browser : chrome;
    var keys = ["diag.backgroundLoadedAt", "diag.backgroundReadyAt", "diag.backgroundErrors"];
    return new Promise(function (resolve) {
      try {
        var p = api.storage.local.get(keys, function (got) {
          resolve(got || {});
        });
        if (p && typeof p.then === "function") p.then(function (got) { resolve(got || {}); }, function (e) { resolve({ readError: String(e) }); });
      } catch (e) {
        resolve({ readError: String(e) });
      }
    });
  };
})();
