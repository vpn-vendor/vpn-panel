// Фикстура: остров пересобирает карточку строкой — путь инцидента 2026-09-17.
vp.island("chart", function (root, h) {
  return { draw: function () { root.innerHTML = "<details open><canvas></canvas></details>"; } };
});
