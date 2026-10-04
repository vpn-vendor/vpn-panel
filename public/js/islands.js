
(function () {
  "use strict";
  var root = document.documentElement;

  var WINDOW_MS = 1000;

  var REDRAWS_PER_ISLAND = 2;

  var STREAK_WINDOWS = 3;

  var DPR_CAP = 2;

  var BYTES_PER_PIXEL = 4;

  var RESIZE_QUIET_MS = 150;

  var islands = [];   // живые экземпляры: {name, root, dirty, draw, stop}
  var pending = [];   // острова, объявленные до готовности страницы
  var subs = [];      // подписки, сделанные через ядро
  var timers = [];    // таймеры, заведённые через ядро
  var sheets = [];    // учтённые полотна: {el, inst, cssW, cssH, ratio}
  var strangers = []; // полотна, появившиеся после загрузки (до срабатывания)
  var known = null;   // WeakSet полотен, существовавших при вооружении
  var tokens = {};    // кэш значений токенов до смены темы
  var booted = false, armed = false, halted = false, closed = false, reason = "";
  var frame = 0, ticker = 0, held = 0, resizeWait = 0;
  var sizeWatch = null, nodeWatch = null, taskWatch = null, themeWatch = null, seesTasks = false;
  var win = { at: 0, redraws: 0, longTasks: 0 };
  var streak = { redraw: 0, longtask: 0, memory: 0, leak: 0 };
  var total = { created: 0, redraws: 0, longTasks: 0, errors: 0, bytes: 0, ceiling: 0, frames: 0, paintMs: 0, paintMaxMs: 0 };

  function noop() {}

  function fuseNote() { return document.getElementById("island-fuse"); }

  function capable() {
    return typeof window.MutationObserver === "function" &&
      typeof window.ResizeObserver === "function" &&
      typeof window.WeakSet === "function" &&
      typeof window.requestAnimationFrame === "function" &&
      !!fuseNote();
  }

  function drop(list, item) {
    var i = list.indexOf(item);
    if (i >= 0) { list.splice(i, 1); }
  }

  function on(target, type, fn, opts) {
    if (halted || closed) { return noop; }
    var sub = { target: target, type: type, opts: opts, h: function (e) { if (!halted) { fn.call(this, e); } } };
    target.addEventListener(type, sub.h, opts);
    subs.push(sub);
    return function () { target.removeEventListener(type, sub.h, opts); drop(subs, sub); };
  }

  function every(ms, fn) {
    if (halted || closed) { return noop; }
    var t = { id: 0, fn: fn, due: false };
    t.id = window.setInterval(function () {
      if (halted) { return; }
      if (document.hidden) { t.due = true; return; }
      fn();
    }, ms);
    timers.push(t);
    return function () { window.clearInterval(t.id); drop(timers, t); };
  }

  function after(ms, fn) {
    if (halted || closed) { return noop; }
    var t = { id: 0, fn: noop, due: false };
    t.id = window.setTimeout(function () { drop(timers, t); if (!halted) { fn(); } }, ms);
    timers.push(t);
    return function () { window.clearTimeout(t.id); drop(timers, t); };
  }

  function onVisible() {
    if (halted || document.hidden) { return; }
    timers.forEach(function (t) { if (t.due) { t.due = false; t.fn(); } });
  }

  function redraw(inst) {
    if (halted || closed) { return; }
    inst.dirty = true;
    if (!frame) { frame = window.requestAnimationFrame(paint); }
  }

  function fit(rec) {
    var ratio = Math.min(window.devicePixelRatio || 1, DPR_CAP);
    var w = Math.round(rec.cssW * ratio), h = Math.round(rec.cssH * ratio);
    if (rec.el.width !== w) { rec.el.width = w; }
    if (rec.el.height !== h) { rec.el.height = h; }
    rec.ratio = ratio;
  }

  function paint() {
    frame = 0;
    if (halted) { return; }
    var began = window.performance.now();
    islands.forEach(function (inst) {
      if (!inst.dirty) { return; }
      inst.dirty = false;
      sheets.forEach(function (rec) { if (rec.inst === inst) { fit(rec); } });
      try { inst.draw(); } catch (e) { total.errors += 1; }
      win.redraws += 1;
      total.redraws += 1;
    });

    var cost = window.performance.now() - began;
    total.frames += 1;
    total.paintMs += cost;
    if (cost > total.paintMaxMs) { total.paintMaxMs = cost; }
  }

  function onResize(entries) {
    var first = false, changed = false;
    entries.forEach(function (entry) {
      sheets.forEach(function (rec) {
        if (rec.el !== entry.target) { return; }
        var w = entry.contentRect.width, h = entry.contentRect.height;
        if (w === rec.cssW && h === rec.cssH) { return; }
        if (!rec.cssW && !rec.cssH) { first = true; }
        rec.cssW = w; rec.cssH = h;
        rec.dirty = true;
        changed = true;
      });
    });
    if (!changed) { return; }
    if (resizeWait) { window.clearTimeout(resizeWait); resizeWait = 0; }
    if (first) { flushResize(); return; }
    resizeWait = window.setTimeout(flushResize, RESIZE_QUIET_MS);
  }

  function flushResize() {
    resizeWait = 0;
    sheets.forEach(function (rec) {
      if (!rec.dirty) { return; }
      rec.dirty = false;
      redraw(rec.inst);
    });
  }

  function sheet(inst, el) {
    var rec = { el: el, inst: inst, cssW: 0, cssH: 0, ratio: 1, dirty: false };

    el.width = 0; el.height = 0;
    sheets.push(rec);
    if (known) { known.add(el); }
    sizeWatch.observe(el);
    return rec;
  }

  function token(name) {
    if (!(name in tokens)) {
      tokens[name] = window.getComputedStyle(root).getPropertyValue(name).trim();
    }
    return tokens[name];
  }

  function themeChanged() {
    tokens = {};
    islands.forEach(redraw);
  }

  function start(name, setup) {
    var roots = document.querySelectorAll("[data-island]");
    Array.prototype.forEach.call(roots, function (el) {
      if (el.getAttribute("data-island") !== name) { return; }
      var inst = { name: name, root: el, dirty: false, draw: noop, stop: noop };
      var handle = {
        root: el, on: on, every: every, after: after, token: token,
        canvas: function (node) { return sheet(inst, node); },
        redraw: function () { redraw(inst); }
      };
      try {
        var api = setup(el, handle) || {};
        if (typeof api.draw === "function") { inst.draw = api.draw; }
        if (typeof api.stop === "function") { inst.stop = api.stop; }
        islands.push(inst);
      } catch (e) { total.errors += 1; }
    });
    if (islands.length > 0 && !armed) { arm(); }
  }

  function island(name, setup) {
    if (halted || closed) { return; }
    if (!booted) { pending.push([name, setup]); return; }
    start(name, setup);
  }

  function boot() {
    booted = true;
    if (!capable()) { pending = []; return; }
    sizeWatch = new window.ResizeObserver(onResize);
    pending.forEach(function (p) { start(p[0], p[1]); });
    pending = [];
  }

  function arm() {
    armed = true;
    known = new window.WeakSet();
    Array.prototype.forEach.call(document.getElementsByTagName("canvas"), function (el) { known.add(el); });
    nodeWatch = new window.MutationObserver(onNodes);
    nodeWatch.observe(root, { childList: true, subtree: true });

    var kinds = window.PerformanceObserver && window.PerformanceObserver.supportedEntryTypes;
    if (kinds && kinds.indexOf("longtask") >= 0) {
      taskWatch = new window.PerformanceObserver(function (list) {
        list.getEntries().forEach(function (e) {
          if (e.name === "self") { win.longTasks += 1; total.longTasks += 1; }
        });
      });
      taskWatch.observe({ entryTypes: ["longtask"] });
      seesTasks = true;
    }
    win.at = window.performance.now();
    held = subs.length + timers.length;
    ticker = window.setInterval(tick, WINDOW_MS);
    document.addEventListener("visibilitychange", onVisible);

    themeWatch = new window.MutationObserver(themeChanged);
    themeWatch.observe(root, { attributes: true, attributeFilter: ["data-theme"] });
  }

  function fresh(el) {
    if (known.has(el)) { return; }
    known.add(el);
    total.created += 1;
    if (halted) { release(el, true); return; }
    strangers.push(el);
  }

  function onNodes(records) {
    records.forEach(function (rec) {
      Array.prototype.forEach.call(rec.addedNodes, function (node) {
        if (node.nodeType !== 1) { return; }
        if (node.nodeName === "CANVAS") { fresh(node); return; }
        Array.prototype.slice.call(node.getElementsByTagName("canvas")).forEach(fresh);
      });
    });
    if (strangers.length > 0 && !halted) { trip("canvas"); }
  }

  function measure() {
    var bytes = 0, ceiling = 0;
    var ratio = Math.min(window.devicePixelRatio || 1, DPR_CAP);
    Array.prototype.forEach.call(document.getElementsByTagName("canvas"), function (el) {
      bytes += el.width * el.height * BYTES_PER_PIXEL;
    });

    sheets.forEach(function (rec) {
      ceiling += Math.round(rec.cssW * ratio) * Math.round(rec.cssH * ratio) * BYTES_PER_PIXEL;
    });
    total.bytes = bytes;
    total.ceiling = ceiling;
    return bytes > ceiling;
  }

  function tick() {
    var now = window.performance.now();

    var elapsed = Math.max((now - win.at) / WINDOW_MS, 1);
    var budget = REDRAWS_PER_ISLAND * islands.length * elapsed;
    var holding = subs.length + timers.length;
    win.at = now;
    if (document.hidden) {
      win.redraws = 0; win.longTasks = 0;
      streak.redraw = 0; streak.longtask = 0; streak.memory = 0; streak.leak = 0;
      return;
    }
    streak.redraw = win.redraws > budget ? streak.redraw + 1 : 0;
    streak.longtask = win.longTasks > 0 ? streak.longtask + 1 : 0;
    streak.memory = measure() ? streak.memory + 1 : 0;

    streak.leak = holding > held ? streak.leak + 1 : 0;
    held = holding;
    win.redraws = 0; win.longTasks = 0;
    Object.keys(streak).some(function (why) {
      if (streak[why] >= STREAK_WINDOWS) { trip(why); return true; }
      return false;
    });
  }

  function release(el, remove) {
    el.width = 0; el.height = 0;
    if (remove && el.parentNode) { el.parentNode.removeChild(el); }
  }

  function quiet() {
    if (frame) { window.cancelAnimationFrame(frame); frame = 0; }
    if (ticker) { window.clearInterval(ticker); ticker = 0; }
    if (resizeWait) { window.clearTimeout(resizeWait); resizeWait = 0; }
    timers.forEach(function (t) { window.clearInterval(t.id); window.clearTimeout(t.id); });
    timers = [];
    subs.forEach(function (s) { s.target.removeEventListener(s.type, s.h, s.opts); });
    subs = [];
    if (sizeWatch) { sizeWatch.disconnect(); }
    if (taskWatch) { taskWatch.disconnect(); taskWatch = null; }
    if (themeWatch) { themeWatch.disconnect(); themeWatch = null; }
    document.removeEventListener("visibilitychange", onVisible);
    islands.forEach(function (inst) { try { inst.stop(); } catch (e) { total.errors += 1; } });
  }

  function trip(why) {
    if (halted) { return; }
    halted = true; armed = false; reason = why;
    quiet();
    strangers.forEach(function (el) { release(el, true); });
    strangers = [];
    Array.prototype.forEach.call(document.getElementsByTagName("canvas"), function (el) { release(el, false); });
    root.classList.add("islands-halted");
    var note = fuseNote();
    if (note) { note.setAttribute("data-reason", why); note.hidden = false; }
  }

  function close() {
    if (closed) { return; }
    closed = true;
    quiet();
    if (nodeWatch) { nodeWatch.disconnect(); nodeWatch = null; }
  }

  window.vp = {
    island: island, on: on, every: every, after: after, token: token,

    stats: function () {
      measure();
      return {
        armed: armed, halted: halted, reason: reason, islands: islands.length,
        canvases: sheets.length, created: total.created, redraws: total.redraws,
        longTasks: total.longTasks, longTaskSupport: seesTasks, errors: total.errors,
        bytes: total.bytes, ceiling: total.ceiling, holding: subs.length + timers.length,
        frames: total.frames, paintMs: total.paintMs, paintMaxMs: total.paintMaxMs
      };
    }
  };
  window.addEventListener("pagehide", close);
  window.addEventListener("pageshow", function (e) { if (e.persisted && closed) { window.location.reload(); } });

  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", boot, { once: true }); }
  else { boot(); }
})();
