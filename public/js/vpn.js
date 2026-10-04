(function () {
    "use strict";

    var dialog = document.getElementById("direct-dialog");
    var openBtn = document.querySelector("[data-direct-open]");
    if (dialog && openBtn && typeof dialog.showModal === "function") {
        var confirmBtn = dialog.querySelector("[data-direct-confirm]");
        var cancelBtn = dialog.querySelector("[data-direct-cancel]");
        var form = openBtn.closest("form");
        var timer = null;

        openBtn.addEventListener("click", function () {
            var left = 2;
            confirmBtn.disabled = true;
            confirmBtn.textContent = "Подтверждаю (" + left + ")";
            dialog.showModal();
            clearInterval(timer);
            timer = setInterval(function () {
                left -= 1;
                if (left > 0) {
                    confirmBtn.textContent = "Подтверждаю (" + left + ")";
                    return;
                }
                clearInterval(timer);
                confirmBtn.disabled = false;
                confirmBtn.textContent = "Подтверждаю";
            }, 1000);
        });

        cancelBtn.addEventListener("click", function () {
            clearInterval(timer);
            dialog.close();
        });
        confirmBtn.addEventListener("click", function () {
            if (confirmBtn.disabled) { return; }
            clearInterval(timer);
            dialog.close();
            form.submit();
        });
    }

    var running = document.querySelector("[data-vpncheck-running]");
    if (!running) { return; }

    var timer = setInterval(function () {
        fetch("/vpn/check/status", { credentials: "same-origin", cache: "no-store" })
            .then(function (r) { return r.json(); })
            .then(function (st) {
                if (!st.running) {
                    clearInterval(timer);
                    window.location.reload();
                }
            })
            .catch(function () {  });
    }, 3000);
})();
