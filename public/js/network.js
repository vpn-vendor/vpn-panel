(function () {
    "use strict";

    document.querySelectorAll("tr[data-iface] .js-role").forEach(function (sel) {
        var row = sel.closest("tr");
        var lanCidr = row.querySelector(".js-lan-cidr");
        var wanNote = row.querySelector(".js-wan-note");
        var name = "cidr_" + sel.getAttribute("data-iface");
        function sync() {
            var isLan = sel.value === "lan";
            var isWan = sel.value === "wan";
            if (lanCidr) {
                lanCidr.hidden = !isLan;

                lanCidr.name = isLan ? name : "";
            }
            if (wanNote) { wanNote.hidden = !isWan; }
        }
        sel.addEventListener("change", sync);
        sync();
    });

    var wan = document.querySelector(".wan-config");
    if (!wan) { return; }

    var method = wan.querySelector(".js-wanmethod");
    var stat = wan.querySelector(".js-static-fields");
    var pppoe = wan.querySelector(".js-pppoe-fields");
    var ip = wan.querySelector(".js-ip");
    var mask = wan.querySelector(".js-mask");
    var maskHint = wan.querySelector(".js-mask-hint");
    var gw = wan.querySelector(".js-gw");
    var gwWarn = wan.querySelector(".js-gw-warn");

    var vlan = wan.querySelector(".js-vlan");
    var vlanHint = wan.querySelector(".js-vlan-hint");
    var nic = wan.getAttribute("data-wan-iface") || "";

    var IFNAME_MAX = 15;
    var VLAN_MAX = 4094;
    function linkIface(tag) {
        var name = nic + "." + tag;
        return name.length <= IFNAME_MAX ? name : "vlan" + tag;
    }
    function syncVlan() {
        if (!vlan || !vlanHint) { return; }
        var v = vlan.value.trim();
        if (v === "") {
            vlanHint.textContent = "Оставьте пустым, если провайдер про VLAN ничего не писал.";
            return;
        }
        if (!/^[0-9]+$/.test(v) || +v < 1 || +v > VLAN_MAX) {
            vlanHint.textContent = "Тег должен быть числом от 1 до " + VLAN_MAX + ".";
            return;
        }
        vlanHint.textContent = "Будет создано подключение " + linkIface(+v) + ".";
    }
    if (vlan) {
        vlan.addEventListener("input", syncVlan);
        syncVlan();
    }

    function syncMethod() {
        stat.hidden = method.value !== "static";
        if (pppoe) { pppoe.hidden = method.value !== "pppoe"; }
    }
    method.addEventListener("change", syncMethod);
    syncMethod();

    function prefixFromMask(v) {
        v = (v || "").trim();
        if (!v) { return -1; }
        var m = v.match(/^\/?(\d{1,2})$/);
        if (m) { var p = parseInt(m[1], 10); return (p >= 0 && p <= 32) ? p : -1; }
        return -1; // точечную маску переводит сервер (/network/suggest)
    }

    var timer = null;
    var lastPrefix = -1; // из ответа сервера: покрывает и точечную маску, и подсказку
    function ask() {
        var params = new URLSearchParams();
        params.set("ip", ip.value.trim());
        params.set("gateway", gw.value.trim());
        params.set("mask", mask.value.trim());
        fetch("/network/suggest?" + params.toString(), { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (d) {
                lastPrefix = (typeof d.prefix === "number") ? d.prefix : -1;
                if (maskHint) {
                    if (d.suggested && d.mask) {
                        maskHint.textContent = "Похоже, маска " + d.mask + " (/" + d.prefix + "). " + (d.suggestReason || "");
                    } else if (d.mask) {
                        maskHint.textContent = "Маска " + d.mask + " (/" + d.prefix + ")";
                    } else {
                        maskHint.textContent = "";
                    }
                }
                if (gwWarn) {
                    if (d.gatewayWarning) {
                        gwWarn.textContent = d.gatewayWarning;
                        gwWarn.hidden = false;
                    } else {
                        gwWarn.hidden = true;
                    }
                }
            })
            .catch(function () {  });
    }
    function askSoon() {
        if (timer) { clearTimeout(timer); }
        timer = setTimeout(ask, 300);
    }
    [ip, mask, gw].forEach(function (el) {
        if (el) { el.addEventListener("input", askSoon); el.addEventListener("blur", ask); }
    });

    var form = wan.closest("form");
    if (form) {
        form.addEventListener("submit", function () {
            if (method.value !== "static") { return; }
            var v = ip.value.trim();
            if (v && v.indexOf("/") === -1) {
                var p = prefixFromMask(mask.value);
                if (p < 0) { p = lastPrefix; } // точечная маска/подсказка с сервера
                if (p >= 0) { ip.value = v + "/" + p; }
            }
        });
    }
})();
