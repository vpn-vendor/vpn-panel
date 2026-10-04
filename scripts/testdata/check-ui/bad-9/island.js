// Фикстура: остров сам создаёт полотно вместо того, чтобы найти отданное сервером.
vp.island("chart", function (root, h) {
  var c = document.createElement("canvas");
  root.appendChild(c);
  return { draw: function () {} };
});
