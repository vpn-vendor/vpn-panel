

(function () {
  "use strict";
  var root = document.querySelector('[data-island="search"]');
  if (!root) { return; }
  var input = root.querySelector("#global-search");
  var pop = root.querySelector("#search-pop");
  var kbd = root.querySelector("[data-search-kbd]");
  if (!input || !pop) { return; }

  var MAX_QUERY = 64;
  var DEBOUNCE_MS = 120;
  var timer = 0;
  var inflight = null;
  var items = [];
  var active = -1;
  var lastQuery = "";

  if (kbd && /Mac|iPhone|iPad/.test(navigator.platform || "")) { kbd.textContent = "⌘ K"; }

  function close() {
    pop.hidden = true;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
    active = -1;
  }

  function setActive(i) {
    items.forEach(function (el, n) {
      el.classList.toggle("is-active", n === i);
      el.setAttribute("aria-selected", n === i ? "true" : "false");
    });
    active = i;
    if (i >= 0 && items[i]) {
      input.setAttribute("aria-activedescendant", items[i].id);
      items[i].scrollIntoView({ block: "nearest" });
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }

  function span(cls, text) {
    var el = document.createElement("span");
    el.className = cls;
    el.textContent = text || "";
    return el;
  }

  function render(list, query) {
    var frag = document.createDocumentFragment();
    items = [];
    list.forEach(function (r) {

      if (typeof r.url !== "string" || r.url.charAt(0) !== "/" || r.url.charAt(1) === "/") { return; }
      var a = document.createElement("a");
      a.className = "search-item";
      a.href = r.url;
      a.id = "search-opt-" + items.length;
      a.setAttribute("role", "option");
      a.appendChild(span("search-item-title", r.title));
      a.appendChild(span("search-item-section", r.section));
      a.appendChild(span("search-item-hint", r.hint));
      frag.appendChild(a);
      items.push(a);
    });
    if (!items.length) {
      var empty = document.createElement("div");
      empty.className = "search-empty";
      empty.textContent = "Ничего не нашлось по «" + query + "». Попробуйте DNS, VPN, PPPoE или «скорость».";
      frag.appendChild(empty);
    }
    pop.replaceChildren(frag);
    pop.hidden = false;
    input.setAttribute("aria-expanded", "true");
    setActive(items.length ? 0 : -1);
  }

  function query(q) {
    if (inflight) { inflight.abort(); }
    inflight = new AbortController();
    fetch("/search?format=json&q=" + encodeURIComponent(q), {
      credentials: "same-origin",
      cache: "no-store",
      signal: inflight.signal,
      headers: { "Accept": "application/json" }
    })
      .then(function (r) { if (!r.ok) { throw new Error("status"); } return r.json(); })
      .then(function (data) {
        if (q !== lastQuery) { return; } // ответ на устаревший запрос
        render(data && Array.isArray(data.items) ? data.items : [], q);
      })
      .catch(function (e) {
        if (e && e.name === "AbortError") { return; }
        close(); // без выдачи под полем форма всё равно работает
      });
  }

  function onInput() {
    var q = input.value.trim().slice(0, MAX_QUERY);
    lastQuery = q;
    clearTimeout(timer);
    if (!q) {
      if (inflight) { inflight.abort(); }
      close();
      return;
    }
    timer = setTimeout(function () { query(q); }, DEBOUNCE_MS);
  }

  function onKey(e) {
    if (pop.hidden) {
      if (e.key === "ArrowDown" && input.value.trim()) { onInput(); }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (items.length) { setActive((active + 1) % items.length); }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (items.length) { setActive((active - 1 + items.length) % items.length); }
    } else if (e.key === "Enter") {
      if (active >= 0 && items[active]) {
        e.preventDefault();
        window.location.assign(items[active].href);
      }
    } else if (e.key === "Escape") {
      close();
    }
  }

  function onGlobalKey(e) {
    var tag = (e.target && e.target.tagName) || "";
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(tag) || (e.target && e.target.isContentEditable);
    if ((e.ctrlKey || e.metaKey) && e.code === "KeyK") {
      e.preventDefault();
      input.focus();
      input.select();
    } else if (e.key === "/" && !typing) {
      e.preventDefault();
      input.focus();
    }
  }

  function onDocClick(e) {
    if (!root.contains(e.target)) { close(); }
  }

  input.addEventListener("input", onInput);
  input.addEventListener("keydown", onKey);
  document.addEventListener("keydown", onGlobalKey);
  document.addEventListener("click", onDocClick);

  window.addEventListener("pagehide", function () {
    clearTimeout(timer);
    if (inflight) { inflight.abort(); }
    input.removeEventListener("input", onInput);
    input.removeEventListener("keydown", onKey);
    document.removeEventListener("keydown", onGlobalKey);
    document.removeEventListener("click", onDocClick);
  }, { once: true });
})();
