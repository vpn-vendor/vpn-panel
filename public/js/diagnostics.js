
(function () {
    "use strict";
    if (!document.querySelector("[data-probe-running]")) { return; }
    var timer = setInterval(function () {
        fetch("/diagnostics/probe/status", { credentials: "same-origin", cache: "no-store" })
            .then(function (r) { return r.json(); })
            .then(function (st) { if (!st.running) { clearInterval(timer); window.location.reload(); } })
            .catch(function () {  });
    }, 2000);
})();
