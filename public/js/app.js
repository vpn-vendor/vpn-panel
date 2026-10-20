
(function () {
  "use strict";
  var root = document.documentElement;

  var theme = null;
  try { theme = localStorage.getItem("vp-theme"); } catch (e) {  }
  if (theme === "dark" ||
      (theme === null && window.matchMedia &&
       window.matchMedia("(prefers-color-scheme: dark)").matches)) {
    root.setAttribute("data-theme", "dark");
  }

  try {
    if (localStorage.getItem("vp-nav-pin") === "1") {
      root.classList.add("nav-pinned");
    }
  } catch (e) {  }

  try {
    if (localStorage.getItem("vp-notices") === "closed") {
      root.classList.add("notices-collapsed");
    }
  } catch (e) {  }

  
  function setupNav() {
    var sidebar = document.getElementById("sidebar");
    var burger = document.getElementById("sidebar-toggle");
    if (!sidebar || !burger) { return; }
    var scrim = document.querySelector("[data-scrim]");
    var pin = document.querySelector("[data-nav-pin]");
    var close = document.querySelector("[data-nav-close]");
    var lastFocus = null;

    root.classList.add("js-nav");
    [scrim, pin, close].forEach(function (el) { if (el) { el.hidden = false; } });

    function drawer() {
      return window.getComputedStyle(sidebar).getPropertyValue("--nav-mode").trim() === "drawer";
    }
    function open() { return root.classList.contains("nav-open"); }

    function setDrawer(opened) {
      if (opened) { lastFocus = document.activeElement; }
      root.classList.toggle("nav-open", opened);
      burger.setAttribute("aria-expanded", opened ? "true" : "false");
      if (!opened && lastFocus && lastFocus.focus) { lastFocus.focus(); lastFocus = null; }
    }

    function tellPin() {
      if (!pin) { return; }
      var on = root.classList.contains("nav-pinned");
      var label = on ? "Открепить меню" : "Закрепить меню";
      pin.setAttribute("aria-pressed", on ? "true" : "false");
      pin.setAttribute("aria-label", label);
      pin.setAttribute("title", label);
    }
    function togglePin() {
      var on = root.classList.toggle("nav-pinned");
      try { localStorage.setItem("vp-nav-pin", on ? "1" : "0"); } catch (e) {  }
      tellPin();
    }

    burger.addEventListener("click", function () { setDrawer(!open()); });
    if (pin) { pin.addEventListener("click", togglePin); }
    if (close) { close.addEventListener("click", function () { setDrawer(false); }); }
    if (scrim) { scrim.addEventListener("click", function () { setDrawer(false); }); }

    document.addEventListener("keydown", function (e) {
      if (!drawer() || !open()) { return; }
      if (e.key === "Escape") { setDrawer(false); return; }
      if (e.key !== "Tab") { return; }
      var items = Array.prototype.filter.call(sidebar.querySelectorAll("a, button"), function (el) {
        return el.offsetWidth > 0 || el.offsetHeight > 0;
      });
      if (!items.length) { return; }
      var first = items[0], last = items[items.length - 1];
      if (!sidebar.contains(document.activeElement)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
        return;
      }
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });

    window.addEventListener("resize", function () {
      if (!drawer() && open()) { setDrawer(false); }
    });
    tellPin();
  }

  window.addEventListener("DOMContentLoaded", function () {
    var noticesBtn = document.getElementById("notices-toggle");
    if (noticesBtn) {
      noticesBtn.addEventListener("click", function () {
        var closed = root.classList.toggle("notices-collapsed");
        try { localStorage.setItem("vp-notices", closed ? "closed" : "open"); } catch (e) {  }
      });
    }

    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), function (btn) {
      btn.addEventListener("click", function () {
        var dark = root.getAttribute("data-theme") === "dark";
        if (dark) { root.removeAttribute("data-theme"); }
        else { root.setAttribute("data-theme", "dark"); }
        try { localStorage.setItem("vp-theme", dark ? "light" : "dark"); } catch (e) {  }
      });
    });
    setupNav();

    function openTarget() {
      var id = window.location.hash.slice(1);
      var el = id && document.getElementById(id);
      var d = el && (el.tagName === "DETAILS" ? el : el.closest("details"));
      if (d) { d.open = true; }
    }
    window.addEventListener("hashchange", openTarget);
    openTarget();

    Array.prototype.forEach.call(document.querySelectorAll("[data-filter-for]"), function (bar) {
      var list = document.getElementById(bar.getAttribute("data-filter-for"));
      if (!list) { return; }
      var buttons = bar.querySelectorAll("[data-filter]");
      bar.hidden = false;
      function show(kind) {
        Array.prototype.forEach.call(buttons, function (b) {
          b.setAttribute("aria-pressed", b.getAttribute("data-filter") === kind ? "true" : "false");
        });
        var day = null, any = false;
        Array.prototype.forEach.call(list.children, function (el) {
          if (el.classList.contains("tl-day")) {
            if (day) { day.hidden = !any; }
            day = el; any = false;
            return;
          }
          var hit = !kind || el.getAttribute("data-kind") === kind;
          el.hidden = !hit;
          if (hit) { any = true; }
        });
        if (day) { day.hidden = !any; }
      }
      Array.prototype.forEach.call(buttons, function (b) {
        b.addEventListener("click", function () { show(b.getAttribute("data-filter")); });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll("[data-search-for]"), function (box) {
      var list = document.getElementById(box.getAttribute("data-search-for"));
      if (!list) { return; }
      var wrap = box.closest("[hidden]");
      if (wrap) { wrap.hidden = false; }
      box.addEventListener("input", function () {
        var q = box.value.trim().toLowerCase();
        Array.prototype.forEach.call(list.children, function (row) {
          if (!q || row.textContent.toLowerCase().indexOf(q) >= 0) { row.removeAttribute("data-search-miss"); }
          else { row.setAttribute("data-search-miss", ""); }
        });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
      var src = document.getElementById(btn.getAttribute("data-copy"));
      if (!src || !navigator.clipboard || !window.isSecureContext) { return; }
      btn.hidden = false;
      var label = btn.querySelector("[data-copy-label]");
      var was = label ? label.textContent : "";
      var title = btn.getAttribute("title") || "";
      btn.addEventListener("click", function () {
        navigator.clipboard.writeText(src.textContent.trim()).then(function () {

          btn.classList.add("is-copied");
          btn.setAttribute("title", "Скопировано");
          if (label) { label.textContent = "Скопировано"; }
          window.setTimeout(function () {
            btn.classList.remove("is-copied");
            btn.setAttribute("title", title);
            if (label) { label.textContent = was; }
          }, 1500);
        });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll("[data-checklist]"), function (box) {
      var id = box.getAttribute("data-checklist");
      Array.prototype.forEach.call(box.querySelectorAll("[data-cl-set]"), function (btn) {
        btn.hidden = false;
        btn.addEventListener("click", function () {
          var view = btn.getAttribute("data-cl-set");
          box.setAttribute("data-cl-view", view);
          document.cookie = "vp_cl_" + id + "=" + view + "; path=/; max-age=31536000; SameSite=Strict" +
            (window.location.protocol === "https:" ? "; Secure" : "");
        });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll("[data-pick]"), function (root) {
      var links = root.querySelectorAll("[data-pick-for]");
      var panels = root.querySelectorAll("[data-pick-panel]");
      if (!links.length || !panels.length) { return; }
      function show(id) {
        var known = Array.prototype.some.call(panels, function (p) { return p.id === id; });
        if (!known) { id = panels[0].id; }
        Array.prototype.forEach.call(panels, function (p) { p.hidden = p.id !== id; });
        Array.prototype.forEach.call(links, function (a) {
          if (a.getAttribute("data-pick-for") === id) { a.setAttribute("aria-current", "true"); }
          else { a.removeAttribute("aria-current"); }
        });
        return document.getElementById(id);
      }
      Array.prototype.forEach.call(links, function (a) {
        a.addEventListener("click", function (e) {
          e.preventDefault();
          var id = a.getAttribute("data-pick-for");
          var panel = show(id);
          if (window.history && history.replaceState) { history.replaceState(null, "", "#" + id); }

          var top = panel.getBoundingClientRect().top;
          if (top < 0 || top > window.innerHeight / 2) { panel.scrollIntoView({ block: "start" }); }
        });
      });
      window.addEventListener("hashchange", function () { show(location.hash.slice(1)); });
      show(location.hash.slice(1));
    });

    Array.prototype.forEach.call(document.querySelectorAll("form[data-upload]"), function (form) {
      var input = form.querySelector("input[type=file]");
      var label = form.querySelector("[data-upload-name]");
      var rest = form.querySelector("[data-upload-form]");
      if (!input || !label) { return; }
      var name = rest ? rest.querySelector("input[type=text]") : null;
      var was = label.textContent;
      var auto = "";
      if (rest) { rest.hidden = true; }
      input.addEventListener("change", function () {
        var f = input.files && input.files[0];
        form.classList.toggle("is-chosen", !!f);
        label.textContent = f ? f.name : was;
        if (rest) { rest.hidden = !f; }
        if (name && f && (name.value === "" || name.value === auto)) {
          auto = f.name.replace(/\.[^.]+$/, "").slice(0, 60);
          name.value = auto;
        }
      });
      ["dragenter", "dragover"].forEach(function (t) {
        input.addEventListener(t, function () { form.classList.add("is-over"); });
      });
      ["dragleave", "drop"].forEach(function (t) {
        input.addEventListener(t, function () { form.classList.remove("is-over"); });
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll("form[data-autosubmit]"), function (form) {
      var fallback = form.querySelector("[data-nojs]");
      if (fallback) { fallback.hidden = true; }
      form.addEventListener("change", function (e) {
        var box = e.target;
        if (!box || box.type !== "checkbox") { return; }
        var q = form.getAttribute("data-question");
        if (box.checked && q && !window.confirm(q)) { box.checked = false; return; }
        form.submit();
      });
    });

    var bar = document.querySelector("[data-unsaved-bar]");
    if (bar) {
      var skipType = /^(hidden|submit|button|reset|file|image|password)$/;
      var tracked = [];
      Array.prototype.forEach.call(document.querySelectorAll("form[data-unsaved]"), function (form) {
        var fields = Array.prototype.filter.call(form.elements, function (el) {
          return el.name && !el.disabled && !skipType.test(el.type || "") && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName);
        });
        if (!fields.length) { return; }
        var warn = document.querySelector('[data-switch-warn][data-form="' + form.id + '"]') ||
          form.querySelector("[data-switch-warn]");
        var note = "";
        if (warn) {
          var text = warn.querySelector(".alert-row > div") || warn;
          note = text.textContent.replace(/\s+/g, " ").trim();
          warn.hidden = true;
        }
        tracked.push({ form: form, fields: fields, note: note, seen: 0,
          saved: fields.map(function (el) { return { v: el.value, c: el.checked }; }) });
      });

      var titleEl = bar.querySelector("[data-unsaved-title]");
      var subEl = bar.querySelector("[data-unsaved-sub]");
      var noteEl = bar.querySelector("[data-unsaved-note]");
      var applyBtn = bar.querySelector("[data-unsaved-apply]");
      var resetBtn = bar.querySelector("[data-unsaved-reset]");
      var leaving = false, tick = 0;

      function changes(t) {
        var keys = {}, marks = [];
        t.fields.forEach(function (el, i) {
          var was = t.saved[i];
          var radio = el.type === "radio", box = el.type === "checkbox";
          var moved = radio || box ? el.checked !== was.c : el.value !== was.v;
          if (!moved) { return; }
          keys[radio ? "r:" + el.name : "f:" + i] = true;
          if (radio && !el.checked) { return; }
          marks.push(radio ? (el.closest(".choice-card, .seg-item") || el) :
            box ? (el.closest(".switch-row, .toggle") || el) : el);
        });
        return { count: Object.keys(keys).length, marks: marks };
      }
      function word(n) {
        var d = n % 10, h = n % 100;
        if (d === 1 && h !== 11) { return "изменение"; }
        if (d >= 2 && d <= 4 && (h < 12 || h > 14)) { return "изменения"; }
        return "изменений";
      }
      function refresh() {
        var dirty = [];
        Array.prototype.forEach.call(document.querySelectorAll(".is-changed"), function (el) { el.classList.remove("is-changed"); });
        tracked.forEach(function (t) {
          var c = changes(t);
          c.marks.forEach(function (el) { el.classList.add("is-changed"); });
          if (c.count) { dirty.push({ t: t, count: c.count }); }
        });
        bar.hidden = dirty.length === 0;
        if (!dirty.length) { return; }
        dirty.sort(function (a, b) { return b.t.seen - a.t.seen; });
        var total = dirty.reduce(function (n, d) { return n + d.count; }, 0);
        var one = dirty.length === 1;
        var btn = submitOf(dirty[0].t.form);
        var label = btn ? btn.textContent.replace(/\s+/g, " ").trim() : "Применить";
        titleEl.textContent = "Изменения ещё не действуют";
        subEl.textContent = one ?
          total + " " + word(total) + ". Пока не нажмёте «" + label + "», работает прежнее." :
          "Изменения в нескольких блоках — у каждого своя кнопка.";
        noteEl.textContent = one ? dirty[0].t.note : "";
        noteEl.hidden = !noteEl.textContent;
        applyBtn.textContent = one ? label : "Показать";
        bar.current = dirty;
      }
      function submitOf(form) {
        var own = Array.prototype.filter.call(form.elements, function (el) {
          return el.type === "submit" && !el.closest("[data-switch-warn]");
        });
        return own[own.length - 1] || null;
      }

      tracked.forEach(function (t) {
        t.form.addEventListener("submit", function () { leaving = true; });
      });
      function onEdit(e) {
        var el = e.target;
        tracked.forEach(function (t) { if (t.fields.indexOf(el) >= 0) { t.seen = ++tick; } });
        refresh();
      }
      document.addEventListener("input", onEdit);
      document.addEventListener("change", onEdit);

      applyBtn.addEventListener("click", function () {
        var dirty = bar.current || [];
        if (!dirty.length) { return; }
        var form = dirty[0].t.form, btn = submitOf(form);
        if (dirty.length > 1) {
          (btn || form).scrollIntoView({ block: "center" });
          if (btn) { btn.focus(); }
          return;
        }
        if (form.requestSubmit) { form.requestSubmit(btn || undefined); }
        else if (btn) { btn.click(); }
        else { leaving = true; form.submit(); }
      });

      resetBtn.addEventListener("click", function () {
        tracked.forEach(function (t) {
          t.fields.forEach(function (el, i) {
            var was = t.saved[i];
            var moved = el.type === "radio" || el.type === "checkbox" ? el.checked !== was.c : el.value !== was.v;
            if (!moved) { return; }
            if (el.type === "radio" || el.type === "checkbox") { el.checked = was.c; } else { el.value = was.v; }
            el.dispatchEvent(new Event("change", { bubbles: true }));
          });
        });
        refresh();
      });

      window.addEventListener("beforeunload", function (e) {
        if (leaving || bar.hidden) { return; }
        e.preventDefault();
        e.returnValue = "";
      });
      window.addEventListener("pageshow", function () { leaving = false; });
    }

    var menus = Array.prototype.slice.call(document.querySelectorAll("details.menu"));
    function closeMenus(except) {
      menus.forEach(function (m) { if (m !== except) { m.removeAttribute("open"); } });
    }
    function onToggle(e) { if (e.target.open) { closeMenus(e.target); } }
    function onDocClick(e) {
      menus.forEach(function (m) { if (m.open && !m.contains(e.target)) { m.removeAttribute("open"); } });
    }
    function onEscape(e) { if (e.key === "Escape") { closeMenus(null); } }
    menus.forEach(function (m) { m.addEventListener("toggle", onToggle); });
    document.addEventListener("click", onDocClick);
    document.addEventListener("keydown", onEscape);
    window.addEventListener("pagehide", function () {
      menus.forEach(function (m) { m.removeEventListener("toggle", onToggle); });
      document.removeEventListener("click", onDocClick);
      document.removeEventListener("keydown", onEscape);
    }, { once: true });
  });
})();
