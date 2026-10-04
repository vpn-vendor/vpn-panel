// Фикстура: логика опирается на возможность одного семейства браузеров.
vp.island("chart", function (root, h) {
  var heap = performance.memory.usedJSHeapSize;
  return { draw: function () { root.setAttribute("style", "height:" + heap + "px"); } };
});
