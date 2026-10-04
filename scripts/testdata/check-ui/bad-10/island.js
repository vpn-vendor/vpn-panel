// Фикстура: вход острова мимо ядра — предохранитель его не остановит.
vp.island("chart", function (root, h) {
  root.addEventListener("toggle", function () { h.redraw(); });
  return { draw: function () {} };
});
