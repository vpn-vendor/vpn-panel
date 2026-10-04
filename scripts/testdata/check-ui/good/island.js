// Фикстура: остров по контракту. Слова innerHTML = и addEventListener( в
// комментарии нарушением не считаются.
vp.island("chart", function (root, h) {
  var sheet = h.canvas(root.querySelector("canvas"));
  h.on(root, "toggle", function () { h.redraw(); });
  h.every(1000, function () { h.redraw(); });
  return { draw: function () { sheet.el.getContext("2d").clearRect(0, 0, sheet.cssW, sheet.cssH); } };
});
