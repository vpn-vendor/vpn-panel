
(function () {
  "use strict";
  var vp = window.vp;
  if (!vp) { return; }

  var TICK_MS = 1000;

  vp.island("applying", function (root, h) {
    var url = root.getAttribute("data-status");
    var state = root.getAttribute("data-state");
    var busy = false;

    function each(sel, fn) { Array.prototype.forEach.call(document.querySelectorAll(sel), fn); }

    function show(w) {
      if (w.state !== state) { window.location.reload(); return; }
      each("[data-wait-bar]", function (el) { el.setAttribute("stroke-dasharray", w.dash + " 100"); });
      each("[data-wait-big]", function (el) { el.textContent = w.big; });
      each("[data-wait-small]", function (el) { el.textContent = w.small; });
      (w.checks || []).forEach(function (c) {
        var li = root.querySelector("[data-check='" + c.key + "']");
        if (!li) { return; }
        li.className = "wz-check wz-check-" + c.state;
        var mark = li.querySelector(".wz-check-mark");
        if (mark) { mark.textContent = c.state === "done" ? "✓" : c.state === "fail" ? "!" : ""; }
        var t = li.querySelector("[data-check-title]");
        var d = li.querySelector("[data-check-desc]");
        if (t) { t.textContent = c.title; }
        if (d) { d.textContent = c.desc; }
      });
    }

    function poll() {
      if (busy || !url || state === "rolledback") { return; }
      busy = true;
      fetch(url, { cache: "no-store", credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (w) { busy = false; if (w) { show(w); } })
        .catch(function () { busy = false; });
    }

    h.every(TICK_MS, poll);
  });
})();
