
(function () {
  "use strict";
  vp.island("danger-confirm", function (root, h) {
    var word = (root.getAttribute("data-word") || "").toLowerCase();
    var boxes = Array.prototype.slice.call(root.querySelectorAll("input[type='checkbox']"));
    var typed = root.querySelector("#danger-word");
    var submit = root.querySelector("button[type='submit']");
    if (!typed || !submit) { return; }
    function check() {
      var all = boxes.every(function (b) { return b.checked; });
      submit.disabled = !(all && typed.value.trim().toLowerCase() === word);
    }
    boxes.forEach(function (b) { h.on(b, "change", check); });
    h.on(typed, "input", check);
    check();
  });
})();
