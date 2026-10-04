
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
    if (localStorage.getItem("vp-sidebar") === "closed") {
      root.classList.add("nav-closed");
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
    var edge = document.querySelector("[data-sidebar-edge]");
    var scrim = document.querySelector("[data-scrim]");
    var away = 0, lastFocus = null;

    root.classList.add("js-nav");
    if (edge) { edge.hidden = false; }
    if (scrim) { scrim.hidden = false; }

    function drawer() {
      return window.getComputedStyle(sidebar).getPropertyValue("--nav-mode").trim() === "drawer";
    }

    function calmMs() {
      var v = window.getComputedStyle(root).getPropertyValue("--calm").trim();
      var n = parseFloat(v) || 0;
      return v.indexOf("ms") > 0 ? n : n * 1000;
    }

    function open() {
      if (root.classList.contains("nav-open")) { return true; }
      if (root.classList.contains("nav-closed")) { return false; }
      return !drawer();
    }
    function mark(opened) {
      root.classList.toggle("nav-open", opened);
      root.classList.toggle("nav-closed", !opened);
    }

    function tell(opened) {
      var v = opened ? "true" : "false";
      var label = opened ? "Свернуть меню" : "Развернуть меню";
      burger.setAttribute("aria-expanded", v);
      burger.setAttribute("aria-label", label);
      burger.setAttribute("title", label);
      if (edge) {
        edge.setAttribute("aria-expanded", v);
        edge.setAttribute("title", label);
        var say = edge.querySelector("span");
        if (say) { say.textContent = label; }
      }
    }

    function setDocked(opened) {
      if (away) { window.clearTimeout(away); away = 0; }
      if (opened) {

        mark(true);
        root.classList.add("nav-away");
        window.requestAnimationFrame(function () {
          window.requestAnimationFrame(function () { root.classList.remove("nav-away"); });
        });
      } else {

        root.classList.add("nav-away");
        away = window.setTimeout(function () {
          away = 0;
          mark(false);
          root.classList.remove("nav-away");
        }, calmMs());
      }
      try { localStorage.setItem("vp-sidebar", opened ? "open" : "closed"); } catch (e) {  }
    }

    function setDrawer(opened) {
      if (opened) {
        lastFocus = document.activeElement;
        mark(true);

      } else {
        mark(false);
        if (lastFocus && lastFocus.focus) { lastFocus.focus(); }
        lastFocus = null;
      }
    }

    function set(opened) {
      if (drawer()) { setDrawer(opened); } else { setDocked(opened); }
      tell(opened);
    }
    function toggle() { set(!open()); }

    burger.addEventListener("click", toggle);
    if (edge) { edge.addEventListener("click", toggle); }
    if (scrim) { scrim.addEventListener("click", function () { set(false); }); }

    document.addEventListener("keydown", function (e) {
      if (!drawer() || !open()) { return; }
      if (e.key === "Escape") { set(false); return; }
      if (e.key !== "Tab") { return; }
      var items = sidebar.querySelectorAll("a, button");
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
      root.classList.remove("nav-away");
      if (drawer() && open()) { mark(false); }
      tell(open());
    });
    tell(open());
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
