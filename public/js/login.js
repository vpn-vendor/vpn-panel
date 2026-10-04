
(function () {
  "use strict";
  window.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("login-form");
    if (!form || form.dataset.autologin !== "1") { return; }

    var button = document.getElementById("login-submit");
    if (button) {
      button.textContent = "Входим…";
      button.disabled = true;
    }

    window.setTimeout(function () {
      if (button) { button.disabled = false; }
      form.submit();
    }, 600);
  });
})();
