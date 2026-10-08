(function () {
    "use strict";

    var form = document.querySelector("[data-wizard-provider]");
    if (!form) { return; }
    var radios = form.querySelectorAll(".choice-input[data-reveals], .choice-input");
    var groups = form.querySelectorAll("[data-reveal]");

    function sync() {
        var chosen = "";
        radios.forEach(function (r) { if (r.checked) { chosen = r.getAttribute("data-reveals") || ""; } });
        groups.forEach(function (g) { g.hidden = g.getAttribute("data-reveal") !== chosen; });
    }
    radios.forEach(function (r) { r.addEventListener("change", sync); });
    sync();

    var ip = form.querySelector("[data-wan-ip]");
    var mask = form.querySelector("[data-wan-mask]");
    var gw = form.querySelector("[data-wan-gateway]");
    var warn = form.querySelector(".js-gw-warn");
    if (!ip || !gw) { return; }
    var timer = null;
    function ask() {
        var params = new URLSearchParams();
        params.set("ip", ip.value.trim());
        params.set("gateway", gw.value.trim());
        params.set("mask", mask ? mask.value.trim() : "");
        fetch("/network/suggest?" + params.toString(), { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                if (mask && d.suggested && d.mask && !mask.value.trim()) { mask.placeholder = d.mask; }
                if (warn) {
                    warn.textContent = d.gatewayWarning || "";
                    warn.hidden = !d.gatewayWarning;
                }
            })
            .catch(function () {  });
    }
    function later() {
        if (timer) { clearTimeout(timer); }
        timer = setTimeout(ask, 400);
    }
    [ip, mask, gw].forEach(function (el) { if (el) { el.addEventListener("input", later); } });
}());
