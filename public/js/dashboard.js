
(function () {
  "use strict";
  var vp = window.vp;
  if (!vp) { return; }

  var TICK_MS = 1000;

  var WINDOWS = { "2h": 7200, "24h": 86400, "7d": 604800 };

  var NOW = "2h";

  var FRESH_MAX_S = 10;

  var BACKOFF_MAX_S = 60;

  var STALE_STEPS = 3;

  var WIDTH_FLOOR = 60;

  var cards = [];
  var groups = {};
  var ticking = false;
  var tip = null;

  var range = null;
  var panel = null;

  function num(v, digits) { return v.toFixed(digits).replace(".", ","); }

  function format(v, unit) {
    if (v === null || v === undefined || v !== v) { return "—"; }
    if (unit === "bits") {
      var bits = v * 8, names = ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с"], i = 0;
      while (bits >= 1000 && i < names.length - 1) { bits /= 1000; i += 1; }
      return num(bits, bits < 10 && i > 0 ? 1 : 0) + " " + names[i];
    }
    if (unit === "ms") { return num(v, v < 10 ? 1 : 0) + " мс"; }
    if (unit === "percent") { return num(v, 0) + " %"; }
    if (unit === "rate") { return num(v, v < 10 ? 1 : 0) + " /с"; }
    return num(v, v < 10 ? 1 : 0);
  }

  function two(n) { return (n < 10 ? "0" : "") + n; }

  function clock(sec, withDate) {
    var d = new Date(sec * 1000);
    var t = two(d.getHours()) + ":" + two(d.getMinutes());
    return withDate ? two(d.getDate()) + "." + two(d.getMonth() + 1) + " " + t : t;
  }

  function nice(v) {
    if (!(v > 0)) { return 1; }
    var p = Math.pow(10, Math.floor(Math.log(v) / Math.LN10)), m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p;
  }

  function latest(points) {
    if (!points) { return null; }
    for (var i = points.length - 1; i >= 0 && i >= points.length - STALE_STEPS; i--) {
      if (points[i] && points[i][1] !== null) { return points[i][1]; }
    }
    return null;
  }

  function stopped(master) { return master === "пауза" || master === "выключен"; }

  function paintChart(o) {
    var ctx = o.ctx, w = o.sheet.cssW, hh = o.sheet.cssH, data = o.data;
    if (!w || !hh) { return null; }
    ctx.setTransform(o.sheet.ratio, 0, 0, o.sheet.ratio, 0, 0);
    ctx.clearRect(0, 0, w, hh);
    if (!data) { return null; }
    var full = o.full, line = full ? parseFloat(o.font) || 12 : 0;
    var box = { l: 1, r: w - 1, t: full ? line + 4 : 2, b: full ? hh - line - 6 : hh - 2 };
    var rows = o.legend.map(function (r) { return r.name; });
    var n = 0, top = o.norm === o.norm ? o.norm : 0;
    rows.forEach(function (name) {
      var pts = data.rows[name] || [];
      if (pts.length > n) { n = pts.length; }
      pts.forEach(function (p) { if (p && p[2] !== null && p[2] > top) { top = p[2]; } });
    });
    if (n < 2) { return null; }
    top = nice(top);
    function x(i) { return box.l + (box.r - box.l) * i / (n - 1); }
    function y(v) { return box.b - (box.b - box.t) * Math.min(v, top) / top; }
    var wide = data.step * (n - 1) > WINDOWS[NOW];

    if (full) {
      if (o.norm === o.norm) {
        ctx.fillStyle = o.token("--ok-soft");
        ctx.fillRect(box.l, y(o.norm), box.r - box.l, box.b - y(o.norm));
      }
      ctx.strokeStyle = o.token("--border");
      ctx.lineWidth = 1;
      ctx.beginPath();
      [top, top / 2, 0].forEach(function (v) {
        var gy = Math.round(y(v)) + 0.5;
        ctx.moveTo(box.l, gy); ctx.lineTo(box.r, gy);
      });
      ctx.stroke();
      ctx.fillStyle = o.token("--text-faint");
      ctx.font = o.font;
      ctx.textBaseline = "top";
      ctx.textAlign = "left";
      ctx.fillText(format(top, o.unit), box.l, 0);
      ctx.fillText(clock(data.from, wide), box.l, box.b + 4);
      ctx.textAlign = "right";
      ctx.fillText(clock(data.from + data.step * (n - 1), wide), box.r, box.b + 4);
    }

    o.legend.forEach(function (r) {
      var pts = data.rows[r.name] || [], i, j, k;
      if (full) {

        ctx.beginPath();
        for (i = 0; i < pts.length; i++) {
          if (!pts[i] || pts[i][1] === null) { continue; }
          for (j = i; j + 1 < pts.length && pts[j + 1] && pts[j + 1][1] !== null; j++) {  }
          ctx.moveTo(x(i), y(pts[i][2]));
          for (k = i + 1; k <= j; k++) { ctx.lineTo(x(k), y(pts[k][2])); }
          for (k = j; k >= i; k--) { ctx.lineTo(x(k), y(pts[k][0])); }
          ctx.closePath();
          i = j;
        }
        ctx.globalAlpha = 0.6;
        ctx.fillStyle = o.token(r.second ? "--series-2-soft" : "--series-1-soft");
        ctx.fill();
        ctx.globalAlpha = 1;
      }
      ctx.beginPath();
      var pen = false;
      for (i = 0; i < pts.length; i++) {
        if (!pts[i] || pts[i][1] === null) { pen = false; continue; }
        if (pen) { ctx.lineTo(x(i), y(pts[i][1])); } else { ctx.moveTo(x(i), y(pts[i][1])); pen = true; }
      }
      ctx.strokeStyle = o.token(r.second ? "--series-2" : "--series-1");
      ctx.lineWidth = 1.5;
      ctx.lineJoin = "round";
      ctx.stroke();
      if (!full) {

        ctx.lineTo(x(pts.length - 1), box.b);
        ctx.lineTo(x(0), box.b);
        ctx.closePath();
        ctx.globalAlpha = 0.35;
        ctx.fillStyle = o.token(r.second ? "--series-2-soft" : "--series-1-soft");
        ctx.fill();
        ctx.globalAlpha = 1;
      }
    });
    return full ? { l: box.l, r: box.r, n: n } : null;
  }

  function group(key) {
    if (!groups[key]) { groups[key] = { nextAt: 0, fails: 0, ctl: null, width: 0 }; }
    return groups[key];
  }

  function wanted(key) {
    return cards.filter(function (c) { return !c.dead && (key === NOW || c.window === key); });
  }

  function widest(key) {
    var width = 0;
    wanted(key).forEach(function (c) {
      var w = c.sheet ? (c.sheet.cssW || c.sheet.el.clientWidth) : 0;
      if (w > width) { width = w; }
    });
    return Math.max(Math.round(width), WIDTH_FLOOR);
  }

  function load(key) {
    var g = group(key), list = wanted(key), rows = [], width = widest(key);
    list.forEach(function (c) {
      c.rows.forEach(function (r) { if (rows.indexOf(r) < 0) { rows.push(r); } });
    });
    if (rows.length === 0) { return; }
    g.width = width;
    var to = Math.floor(Date.now() / 1000), from = to - WINDOWS[key];
    if (range && key !== NOW) { from = range.from; to = range.to; }
    var url = "/metrics/series?rows=" + encodeURIComponent(rows.join(",")) +
      "&from=" + from + "&to=" + to + "&width=" + width;
    g.ctl = new window.AbortController();
    window.fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" }, signal: g.ctl.signal })
      .then(function (r) { if (!r.ok) { throw new Error("status"); } return r.json(); })
      .then(function (data) {
        g.fails = 0;
        var step = Math.max(data.step, 1);
        g.nextAt = Date.now() + (key === NOW ? Math.min(step, FRESH_MAX_S) : step) * 1000;
        wanted(key).forEach(function (c) { c.accept(data, key); });
      })
      .catch(function () {

        g.fails += 1;
        g.nextAt = Date.now() + Math.min(Math.pow(2, g.fails), BACKOFF_MAX_S) * 1000;
        wanted(key).forEach(function (c) { c.fail(); });
      })
      .then(function () { g.ctl = null; });
  }

  function tick() {
    var now = Date.now(), keys = [NOW];
    cards.forEach(function (c) { if (!c.dead && keys.indexOf(c.window) < 0) { keys.push(c.window); } });
    keys.forEach(function (key) {
      var g = group(key);

      if (!g.ctl && (now >= g.nextAt || (g.fails === 0 && widest(key) > g.width))) { load(key); }
    });
  }

  function enroll(card) {
    cards.push(card);
    if (!ticking) { ticking = true; vp.every(TICK_MS, tick); vp.after(0, tick); }
  }

  function retire(card) {
    card.dead = true;
    Object.keys(groups).forEach(function (key) { if (groups[key].ctl) { groups[key].ctl.abort(); } });
  }

  function setWindow(key) {
    if (!WINDOWS[key]) { return; }
    range = null;
    cards.forEach(function (c) { if (c.kind !== "light") { c.window = key; c.series = null; } });
    group(key).nextAt = 0;
    showRange();
    tick();
  }

  function setRange(from, to) {
    range = { from: from, to: to };
    cards.forEach(function (c) { if (c.kind !== "light") { c.series = null; } });
    Object.keys(groups).forEach(function (k) { groups[k].nextAt = 0; });
    showRange();
    tick();
  }

  function showRange() {
    var note = document.querySelector("[data-range-note]");
    var chips = document.querySelector("[data-island='chart-window']");
    var pick = document.querySelector("[data-range-pick]");
    if (!note) { return; }
    var text = note.querySelector("[data-range-text]");
    var window_ = note.querySelector("[data-range-window]");
    note.hidden = !range;
    if (chips) { chips.setAttribute("data-range", range ? "on" : "off"); }
    if (pick) { pick.disabled = !!range; }
    Array.prototype.forEach.call(document.querySelectorAll("[data-window-set]"), function (b) { b.disabled = !!range; });
    if (range && text) {
      var full = range.to - range.from > WINDOWS[NOW];
      text.textContent = clock(range.from, full) + " — " + clock(range.to, full);
    }

    if (range && window_) {
      var cur = document.querySelector('[data-window-set][aria-pressed="true"]');
      if (cur) { window_.textContent = cur.textContent.trim(); }
    }
    if (panel && panel.reset) { panel.reset.hidden = !range; }
  }

  function light(root, h) {
    var text = root.querySelector("[data-status-text]");
    var advice = root.querySelector("[data-status-advice]");
    var warn = parseFloat(root.getAttribute("data-warn")), bad = parseFloat(root.getAttribute("data-bad"));
    var rows = (root.getAttribute("data-rows") || "").split(",");

    var alive = root.getAttribute("data-alive");
    var seen = !root.classList.contains("status-unknown");
    var card = { kind: "light", rows: rows, window: NOW, sheet: null, dead: false, level: null };
    function grade(v) { return (bad === bad && v >= bad) ? "bad" : (warn === warn && v >= warn) ? "warn" : "ok"; }
    card.accept = function (data, key) {
      if (key !== NOW) { return; }
      var level, v = latest(data.rows[rows[0]]);
      if (stopped(data.master)) {
        level = "unknown";
      } else if (!alive) {
        level = v === null ? "unknown" : grade(v);
      } else if (latest(data.rows[alive]) === null) {

        level = seen ? "down" : "unknown";
      } else {
        seen = true;
        level = v === null ? "ok" : grade(v); // жив, а мерить ещё нечем — норма
      }
      if (level !== card.level) { card.level = level; h.redraw(); }
    };
    card.fail = function () {};
    enroll(card);
    return {
      draw: function () {
        if (!card.level || !text) { return; }
        var red = card.level === "bad" || card.level === "down";
        root.className = "status-line status-" + (red ? "error" : card.level);
        text.textContent = root.getAttribute("data-text-" + card.level) || text.textContent;
        if (advice) { advice.textContent = root.getAttribute("data-advice-" + card.level) || advice.textContent; }
      },
      stop: function () { retire(card); }
    };
  }

  function chart(root, h) {
    if (root.getAttribute("data-kind") === "light") { return light(root, h); }
    var canvas = root.querySelector("canvas");
    if (!canvas) { return {}; }
    var ctx = canvas.getContext("2d");
    var note = root.querySelector("[data-chart-note]");
    var unit = root.getAttribute("data-unit") || "";
    var norm = parseFloat(root.getAttribute("data-norm"));

    var warn = parseFloat(root.getAttribute("data-warn")), bad = parseFloat(root.getAttribute("data-bad"));
    var scaled = warn === warn || bad === bad;
    var baseNote = note ? note.textContent : "";
    var font = "";
    var legend = Array.prototype.map.call(root.querySelectorAll("[data-row]"), function (el) {
      return {
        name: el.getAttribute("data-row"), label: el.getAttribute("data-label") || "",
        second: el.classList.contains("chart-series-2"), value: el.querySelector("[data-row-value]")
      };
    });
    var card = {
      kind: "chart", rows: legend.map(function (r) { return r.name; }),
      window: WINDOWS[root.getAttribute("data-window")] ? root.getAttribute("data-window") : NOW,
      sheet: h.canvas(canvas), dead: false, series: null, plot: null, level: ""
    };

    function say(key) {
      if (note) { note.textContent = key ? (root.getAttribute("data-text-" + key) || baseNote) : baseNote; }
    }

    card.accept = function (data, key) {
      if (card.dead) { return; }
      var off = stopped(data.master);
      if (key === NOW) {
        legend.forEach(function (r) {
          if (r.value) { r.value.textContent = format(off ? null : latest(data.rows[r.name]), unit); }
        });
        if (scaled && legend.length) {
          var v = off ? null : latest(data.rows[legend[0].name]);
          var level = v === null ? "" : (bad === bad && v >= bad) ? "error" : (warn === warn && v >= warn) ? "warn" : "";
          if (level !== card.level) { card.level = level; h.redraw(); }
        }
      }
      if (key !== card.window) { return; }
      var any = false;
      card.rows.forEach(function (name) {
        (data.rows[name] || []).forEach(function (p) { if (p && p[1] !== null) { any = true; } });
      });
      card.series = data;
      say(off ? "paused" : any ? "" : "empty");
      h.redraw();
    };
    card.fail = function () { if (!card.dead) { say("busy"); } };

    function mode() {
      return window.getComputedStyle(canvas).getPropertyValue("--chart-mode").trim() === "full" ? "full" : "spark";
    }

    function draw() {
      if (scaled && legend.length) {
        var el = legend[0].value && legend[0].value.parentNode;
        if (el) {
          el.classList.toggle("chart-value-warn", card.level === "warn");
          el.classList.toggle("chart-value-error", card.level === "error");
        }
      }
      card.plot = paintChart({
        ctx: ctx, sheet: card.sheet, data: card.series, legend: legend, unit: unit, norm: norm,
        full: mode() === "full", token: h.token, font: noteFont()
      });
    }

    function noteFont() {
      if (!font && note) {
        var cs = window.getComputedStyle(note);
        font = cs.fontSize + " " + cs.fontFamily;
      }
      return font;
    }

    function hover(e) {
      if (!tip) { tip = document.querySelector("[data-chart-tip]"); }
      var p = card.plot, data = card.series;
      if (!tip || !p || !data) { return; }
      var rect = canvas.getBoundingClientRect();
      var i = Math.round((e.clientX - rect.left - p.l) / (p.r - p.l) * (p.n - 1));
      i = Math.max(0, Math.min(p.n - 1, i));
      var time = tip.querySelector("[data-tip-time]");
      if (time) { time.textContent = clock(data.from + data.step * i, card.window !== NOW); }
      var peak = tip.getAttribute("data-text-peak") || "";
      Array.prototype.forEach.call(tip.querySelectorAll("[data-tip-row]"), function (slot, s) {
        var r = legend[s], pt = r && (data.rows[r.name] || [])[i];
        slot.hidden = !r;
        if (!r) { return; }
        slot.className = "chart-tip-row " + (r.second ? "chart-series-2" : "chart-series-1");
        slot.querySelector("[data-tip-label]").textContent = r.label;
        var val = !pt || pt[1] === null ? "—" : format(pt[1], unit);
        if (pt && pt[1] !== null && pt[2] > pt[1] && peak) { val += " · " + peak + " " + format(pt[2], unit); }
        slot.querySelector("[data-tip-val]").textContent = val;
      });
      tip.hidden = false;
      var tw = tip.offsetWidth, th = tip.offsetHeight;
      var tx = e.clientX + 12 + tw > window.innerWidth ? e.clientX - 12 - tw : e.clientX + 12;
      var ty = Math.max(4, Math.min(window.innerHeight - th - 4, e.clientY - th - 12));
      tip.style.transform = "translate(" + Math.max(4, Math.round(tx)) + "px," + Math.round(ty) + "px)";
    }

    function leave() { if (tip) { tip.hidden = true; } }

    root.tabIndex = 0;
    root.setAttribute("role", "button");
    root.setAttribute("aria-haspopup", "dialog");
    var zoom = root.querySelector("[data-chart-zoom]");
    if (zoom) { zoom.hidden = false; }
    card.expand = function (coach) { expand(card, legend, unit, norm, root, coach); };
    h.on(root, "click", function (e) {
      if (e.target.closest("[data-window-set], a, input")) { return; }
      card.expand(false);
    });
    h.on(root, "keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); card.expand(false); }
    });

    h.on(canvas, "pointermove", hover);
    h.on(canvas, "pointerdown", hover);
    h.on(canvas, "pointerleave", leave);
    h.on(canvas, "pointercancel", leave);
    enroll(card);
    return { draw: draw, stop: function () { retire(card); leave(); } };
  }

  function panelIsland(root, h) {
    var canvas = root.querySelector("canvas");
    if (!canvas || !root.showModal) { return {}; }
    var ctx = canvas.getContext("2d");
    var sel = root.querySelector("[data-chart-select]");
    var titleEl = root.querySelector("[data-panel-title]");
    var subEl = root.querySelector("[data-panel-sub]");
    var valuesEl = root.querySelector("[data-panel-values]");
    var noteEl = root.querySelector("[data-panel-note]");
    var closeBtn = root.querySelector("[data-panel-close]");
    var resetBtn = root.querySelector("[data-panel-reset]");
    var font = "";
    var card = { kind: "panel", rows: [], window: NOW, sheet: h.canvas(canvas), dead: false, series: null, unit: "", norm: NaN, legend: [], plot: null };

    card.accept = function (data, key) {
      if (card.dead || !root.open || key !== card.window) { return; }
      card.series = data;
      h.redraw();
    };
    card.fail = function () {};
    enroll(card);

    var coach = root.querySelector("[data-panel-coach]");
    var coachOk = root.querySelector("[data-coach-ok]");
    function coachSeen() {
      try { return localStorage.getItem("vp-range-coach") === "seen"; } catch (e) { return false; }
    }
    function showCoach(force) {
      if (!coach || (!force && coachSeen())) { return; }
      coach.hidden = false;

      h.after(0, function () { coach.setAttribute("data-shown", "yes"); });
    }
    function hideCoach(remember) {
      if (!coach) { return; }
      coach.removeAttribute("data-shown");
      coach.hidden = true;
      if (remember) {
        try { localStorage.setItem("vp-range-coach", "seen"); } catch (e) {  }
      }
    }
    if (coachOk) { h.on(coachOk, "click", function () { hideCoach(true); }); }

    function show(from) {
      card.rows = from.rows;
      card.unit = from.unit;
      card.norm = from.norm;
      card.legend = from.legend;
      card.window = from.window;
      card.series = from.series;
      if (titleEl) { titleEl.textContent = from.title; }
      if (subEl) { subEl.textContent = from.sub; }
      if (valuesEl) { valuesEl.textContent = ""; }

      from.values.forEach(function (node) { valuesEl.appendChild(node.cloneNode(true)); });
      root.showModal();
      showCoach(from.coach);
      group(card.window).nextAt = 0;
      tick();
      h.redraw();
    }

    function draw() {
      if (!font && noteEl) {
        var cs = window.getComputedStyle(noteEl);
        font = cs.fontSize + " " + cs.fontFamily;
      }
      card.plot = paintChart({
        ctx: ctx, sheet: card.sheet, data: card.series, legend: card.legend,
        unit: card.unit, norm: card.norm, full: true, token: h.token, font: font
      });
    }

    var drag = null;
    function at(e) { return e.clientX - canvas.getBoundingClientRect().left; }
    function paintSel(a, b) {
      if (!sel) { return; }
      sel.hidden = false;
      sel.style.transform = "translateX(" + Math.round(a) + "px) scaleX(" + Math.max(Math.round(b - a), 1) + ")";
    }
    function hideSel() { if (sel) { sel.hidden = true; } }

    h.on(canvas, "pointerdown", function (e) {
      if (!card.plot || !card.series) { return; }
      drag = { x0: at(e) };
      try { canvas.setPointerCapture(e.pointerId); } catch (err) {  }
      paintSel(drag.x0, drag.x0);
    });
    h.on(canvas, "pointermove", function (e) {
      if (!drag) { return; }
      var x = at(e);
      paintSel(Math.min(drag.x0, x), Math.max(drag.x0, x));
    });
    h.on(canvas, "pointerup", function (e) {
      if (!drag) { return; }
      var a = Math.min(drag.x0, at(e)), b = Math.max(drag.x0, at(e));
      drag = null;
      hideSel();
      var p = card.plot, data = card.series;
      if (!p || !data) { return; }
      function stepAt(x) {
        var i = Math.round((x - p.l) / (p.r - p.l) * (p.n - 1));
        return data.from + data.step * Math.max(0, Math.min(p.n - 1, i));
      }
      var from = stepAt(a), to = stepAt(b);

      if (to - from < data.step * 2) { return; }
      hideCoach(true);
      setRange(from, to);
    });
    h.on(canvas, "pointercancel", function () { drag = null; hideSel(); });

    if (closeBtn) { h.on(closeBtn, "click", function () { root.close(); }); }
    if (resetBtn) { h.on(resetBtn, "click", function () { setWindow(currentChip()); }); }

    h.on(root, "close", function () { card.series = null; hideSel(); hideCoach(false); });

    panel = { show: show, reset: resetBtn, coach: showCoach };
    return { draw: draw, stop: function () { retire(card); panel = null; } };
  }

  function currentChip() {
    var b = document.querySelector('[data-window-set][aria-pressed="true"]');
    return b ? b.getAttribute("data-window-set") : NOW;
  }

  function pickRange() {
    var first = cards.filter(function (c) { return c.kind === "chart" && c.expand; })[0];
    if (first) { first.expand(true); }
  }

  function expand(card, legend, unit, norm, root, coach) {
    if (!panel) { return; }
    var head = root.querySelector(".chart-title");
    var sub = root.querySelector(".chart-sub");
    panel.show({
      coach: !!coach,
      rows: card.rows, unit: unit, norm: norm, legend: legend, window: card.window, series: card.series,
      title: head ? head.textContent.trim() : "", sub: sub ? sub.textContent.trim() : "",
      values: Array.prototype.slice.call(root.querySelectorAll(".chart-value"))
    });
  }

  function chips(root, h) {
    var buttons = Array.prototype.slice.call(root.querySelectorAll("[data-window-set]"));
    function choose(key, remember) {
      if (!WINDOWS[key]) { return; }
      buttons.forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-window-set") === key ? "true" : "false"); });
      setWindow(key);
      if (remember) { try { localStorage.setItem("vp-chart-window", key); } catch (e) {  } }
    }
    buttons.forEach(function (b) {
      h.on(b, "click", function () { choose(b.getAttribute("data-window-set"), true); });
    });
    var back = root.querySelector("[data-range-back]");
    if (back) { h.on(back, "click", function () { setWindow(currentChip()); }); }
    var pick = root.querySelector("[data-range-pick]");
    if (pick) { pick.hidden = false; h.on(pick, "click", pickRange); }
    root.hidden = false;
    var saved = null;
    try { saved = localStorage.getItem("vp-chart-window"); } catch (e) {  }
    if (saved && WINDOWS[saved]) { h.after(0, function () { choose(saved, false); }); }
    return {};
  }

  vp.island("chart", chart);
  vp.island("chart-window", chips);
  vp.island("chart-panel", panelIsland);
})();
