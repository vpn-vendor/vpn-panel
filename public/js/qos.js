(function () {
    "use strict";

    var root = document.querySelector('[data-island="qos-form"]');
    if (root) {
        var box = root.querySelector("#qos-enabled");
        var fields = [root.querySelector("#qos-down"), root.querySelector("#qos-up")];
        var syncFields = function () {
            if (!box) { return; }
            fields.forEach(function (f) { if (f) { f.disabled = !box.checked; } });
        };
        if (box) {
            box.addEventListener("change", syncFields);
            syncFields();
            window.addEventListener("pagehide", function () {
                box.removeEventListener("change", syncFields);
            }, { once: true });
        }
    }

    var running = document.querySelector("[data-speedtest-running]");
    if (running) {
        var timer = setInterval(function () {
            fetch("/qos/speedtest/status", { credentials: "same-origin" })
                .then(function (r) { return r.json(); })
                .then(function (st) {
                    if (!st.running) {
                        clearInterval(timer);
                        window.location.reload();
                    }
                })
                .catch(function () {  });
        }, 2000);
    }

    document.querySelectorAll("[data-fill-tariff]").forEach(function (btn) {
        btn.addEventListener("click", function (ev) {
            ev.preventDefault();
            var down = document.querySelector("input[name=down_mbit]");
            var up = document.querySelector("input[name=up_mbit]");
            if (down) { down.value = btn.getAttribute("data-down"); }
            if (up) { up.value = btn.getAttribute("data-up"); }
            if (box && !box.checked) { box.checked = true; syncFields(); }
            if (down) { down.scrollIntoView({ behavior: "smooth", block: "center" }); }
        });
    });
}());
