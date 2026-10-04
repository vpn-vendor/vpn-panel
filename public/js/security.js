

(function () {
    "use strict";
    var roots = document.querySelectorAll('[data-island^="confirm-"]');
    Array.prototype.forEach.call(roots, function (root) {
        var form = root.tagName === "FORM" ? root : root.querySelector("form");
        if (!form) { return; }
        function ask(e) {
            if (!window.confirm(root.getAttribute("data-question") || "Продолжить?")) {
                e.preventDefault();
            }
        }
        form.addEventListener("submit", ask);

        window.addEventListener("pagehide", function () {
            form.removeEventListener("submit", ask);
        }, { once: true });
    });
})();
