
(function () {
  "use strict";
  window.addEventListener("DOMContentLoaded", function () {
    var box = document.getElementById("confirm-box");
    if (!box) { return; }
    var csrf = box.dataset.csrf;
    var timeout = parseInt(box.dataset.timeout, 10) || 120;

    var confirmURL = box.dataset.confirm || "/network/confirm";
    var back = box.dataset.return || "/network";
    var counter = document.getElementById("confirm-counter");
    var left = timeout;
    var finished = false;

    var tick = setInterval(function () {
      left -= 1;
      if (counter) { counter.textContent = String(Math.max(left, 0)); }
      if (left <= -5 && !finished) {
        finished = true;
        clearInterval(tick);
        window.location.href = back;
      }
    }, 1000);

    function confirmNow() {
      if (finished) { return; }
      finished = true;
      clearInterval(tick);
      var body = new URLSearchParams();
      body.set("_csrf", csrf);
      fetch(confirmURL, { method: "POST", body: body })
        .then(function () { window.location.href = back; })
        .catch(function () { window.location.href = back; });
    }

    function probe() {
      if (finished) { return; }
      fetch("/health", { cache: "no-store" })
        .then(function (r) { if (r.ok) { confirmNow(); } else { setTimeout(probe, 2000); } })
        .catch(function () { setTimeout(probe, 2000); });
    }
    setTimeout(probe, 1500);
  });
})();
