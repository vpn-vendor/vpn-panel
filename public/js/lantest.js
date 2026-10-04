
(function () {
    "use strict";
    var box = document.getElementById("lantest");
    if (!box) { return; }
    var csrf = box.dataset.csrf;
    var probes = box.dataset.probes === "1";
    var status = document.getElementById("lantest-status");
    var result = document.getElementById("lantest-result");
    var buttons = box.querySelectorAll("button[data-mode]");
    var DURATION = { quick: 3000, full: 5000 };

    function say(text) { status.hidden = false; status.textContent = text; }
    function lock(on) { buttons.forEach(function (b) { b.disabled = on; }); }

    function probe() {
        if (!probes) { return Promise.resolve(null); }
        var body = new URLSearchParams(); body.set("_csrf", csrf);
        return fetch("/lantest/probe", { method: "POST", body: body, credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (j) { return (j && typeof j.avg_ms === "number") ? j.avg_ms : null; })
            .catch(function () { return null; });
    }

    function download(mode) {
        var started = performance.now();
        var bytes = 0;
        var limit = DURATION[mode] || 3000;
        function next() {
            if (performance.now() - started >= limit) {
                var seconds = (performance.now() - started) / 1000;
                return Promise.resolve(Math.round(bytes * 8 / seconds / 1000000));
            }
            return fetch("/lantest/data?mode=" + encodeURIComponent(mode) + "&t=" + Date.now(), { cache: "no-store", credentials: "same-origin" })
                .then(function (r) {
                    if (!r.ok) { return r.text().then(function (t) { throw new Error(t || ("код " + r.status)); }); }
                    return r.arrayBuffer();
                })
                .then(function (buf) { bytes += buf.byteLength; return next(); });
        }
        return next();
    }

    buttons.forEach(function (btn) {
        btn.addEventListener("click", function () {
            var mode = btn.dataset.mode;
            lock(true); result.hidden = true;
            say("Замер задержки без нагрузки…");
            var idle = null, load = null;
            probe().then(function (v) {
                idle = v;
                say("Идёт закачка с сервера…");
                var loadProbe = new Promise(function (resolve) { setTimeout(function () { probe().then(resolve); }, 800); });
                return Promise.all([download(mode), loadProbe]);
            }).then(function (pair) {
                var mbit = pair[0]; load = pair[1];
                var body = new URLSearchParams();
                body.set("_csrf", csrf); body.set("mbit", String(mbit)); body.set("mode", mode);
                body.set("idle_ms", idle === null ? "0" : String(idle));
                body.set("load_ms", load === null ? "0" : String(load));
                return fetch("/lantest/result", { method: "POST", body: body, credentials: "same-origin" })
                    .then(function (r) { return r.json(); })
                    .then(function (j) {
                        status.hidden = true; result.hidden = false;
                        var text = "Скорость до сервера: " + mbit + " Мбит/с.";
                        if (idle !== null && load !== null) { text += " Задержка: " + idle.toFixed(1) + " → " + load.toFixed(1) + " мс под нагрузкой."; }
                        if (j && j.verdict) { text += " " + j.verdict; }
                        if (j && j.error) { text += " (" + j.error + ")"; }
                        result.textContent = text;
                    });
            }).catch(function (e) {
                status.hidden = true; result.hidden = false;
                result.textContent = "Тест не удался: " + (e && e.message ? e.message : "нет связи с сервером") + ". Повторите позже.";
            }).then(function () { lock(false); });
        });
    });
})();
