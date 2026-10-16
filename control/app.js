/* Admin panel for the AI Chat Saver site.
   Saves through the GitHub contents API with a fine-grained token that is stored only encrypted
   (PBKDF2-SHA256 600000 iterations + AES-GCM-256) in control/vault.json. The plain token lives in memory,
   or in sessionStorage when "Remember on this device" is ticked. It is never logged. */
(function () {
  "use strict";
  var OWNER = "aichatsaver", REPO = "aichatsaver.github.io", BRANCH = "main";
  var API = "https://api.github.com", RP = "/repos/" + OWNER + "/" + REPO;
  var VAULT_PATH = "control/vault.json", ITER = 600000, AAD = "aichatsaver-admin-vault-v1";
  var SS_KEY = "acs_admin_session";
  var Y = window.jsyaml;
  var YOPT = { schema: Y.CORE_SCHEMA };
  var DOPT = { schema: Y.CORE_SCHEMA, lineWidth: -1, noRefs: true, quotingType: "'" };

  var token = null;          // plain token, memory only
  var vault = null;          // {data, sha}
  var failCount = 0;

  function $(id) { return document.getElementById(id); }
  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "class") e.className = attrs[k];
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== false && attrs[k] != null) e.setAttribute(k, attrs[k] === true ? "" : attrs[k]);
    }
    (kids || []).forEach(function (c) { if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return e;
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function show(id) { ["vLoading", "vError", "vLock", "vSetup", "vPanel"].forEach(function (v) { $(v).hidden = v !== id; }); $("lockBtn").hidden = id !== "vPanel"; }
  function deepEq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  /* ---------- theme ---------- */
  function syncThemeLabel() { var d = document.documentElement.getAttribute("data-theme") === "dark"; $("themeBtn").setAttribute("aria-label", d ? "Switch to light mode" : "Switch to dark mode"); }
  $("themeBtn").addEventListener("click", function () {
    var d = document.documentElement, on = d.getAttribute("data-theme") !== "dark";
    if (on) d.setAttribute("data-theme", "dark"); else d.removeAttribute("data-theme");
    try { localStorage.setItem("theme", on ? "dark" : "light"); } catch (e) {}
    syncThemeLabel();
  });
  syncThemeLabel();

  /* ---------- base64 <-> UTF-8 ---------- */
  function bytesToB64(u8) { var s = "", CH = 0x8000; for (var i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH)); return btoa(s); }
  function b64ToBytes(b64) { var s = atob(String(b64).replace(/\s+/g, "")), u8 = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i); return u8; }
  function utf8ToB64(str) { return bytesToB64(new TextEncoder().encode(str)); }
  function b64ToUtf8(b64) { return new TextDecoder("utf-8").decode(b64ToBytes(b64)); }

  /* ---------- crypto ---------- */
  async function deriveKey(pw, salt, iter) {
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iter }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function encryptToken(tok, pw) {
    var salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    var key = await deriveKey(pw, salt, ITER);
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: new TextEncoder().encode(AAD), tagLength: 128 }, key, new TextEncoder().encode(tok));
    return { v: 1, kdf: "PBKDF2-SHA256", iterations: ITER, cipher: "AES-GCM-256", salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)), updated: new Date().toISOString().slice(0, 10) };
  }
  async function decryptToken(v, pw) {
    var key = await deriveKey(pw, b64ToBytes(v.salt), v.iterations || ITER);
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(v.iv), additionalData: new TextEncoder().encode(AAD), tagLength: 128 }, key, b64ToBytes(v.ct));
    return new TextDecoder().decode(pt);
  }

  /* ---------- password strength ---------- */
  function strength(pw) {
    if (!pw) return { s: 0, t: "" };
    var classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(function (r) { return r.test(pw); }).length;
    var uniq = new Set(pw).size;
    var pool = [26, 26, 10, 33].reduce(function (a, n, i) { return a + ([/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/][i].test(pw) ? n : 0); }, 0);
    var bits = Math.min(pw.length, uniq * 2) * Math.log2(Math.max(pool, 2));
    if (/^(.)\1+$/.test(pw) || /(password|qwerty|123456|abcdef|letmein|admin)/i.test(pw)) bits = Math.min(bits, 25);
    var s = pw.length < 12 ? 0 : bits < 50 ? 1 : bits < 70 ? 2 : bits < 90 ? 3 : 4;
    if (pw.length >= 12 && classes === 1 && s > 2) s = 2;
    return { s: s, t: pw.length < 12 ? "Too short" : ["Too short", "Weak", "Fair", "Good", "Strong"][s] };
  }
  function bindMeter(inputId, meterId) {
    var inp = $(inputId), m = $(meterId), bar = m.querySelector("i"), lab = m.querySelector("span");
    var colors = ["#c0322b", "#d9622b", "#e0a100", "#4b9e3f", "#0f8a5f"];
    function upd() { var r = strength(inp.value); bar.style.setProperty("--w", (inp.value ? Math.max(8, r.s * 25) : 0) + "%"); bar.style.setProperty("--c", colors[r.s]); lab.textContent = r.t; }
    inp.addEventListener("input", upd); upd();
  }
  function checkNewPw(a, b) {
    if (a.length < 12) return "Use at least 12 characters.";
    if (strength(a).s < 1) return "Choose a less predictable password.";
    if (a !== b) return "The two passwords don’t match.";
    return "";
  }

  /* ---------- GitHub API ---------- */
  async function gh(path, opts) {
    opts = opts || {};
    var h = { "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
    var t = opts.token !== undefined ? opts.token : token;
    if (t && opts.auth !== false) h["Authorization"] = "Bearer " + t;
    if (opts.body) h["Content-Type"] = "application/json";
    var r = await fetch(API + path, { method: opts.method || "GET", headers: h, body: opts.body ? JSON.stringify(opts.body) : undefined, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
    var data = null; try { data = await r.json(); } catch (e) {}
    return { ok: r.ok, status: r.status, data: data };
  }
  function encPath(p) { return p.split("/").map(encodeURIComponent).join("/"); }
  function apiErr(r) {
    if (r.status === 401) return "GitHub did not accept the token (it may have expired). Use Replace token.";
    if (r.status === 403) return "GitHub refused this (the token may lack Contents: Read and write, or the rate limit was hit).";
    if (r.status === 404) return "Not found, or the token can’t see this repository.";
    if (r.status === 409 || r.status === 422) return "This file changed on GitHub since you opened it. Press Reload, redo your change, then save.";
    if (!r.status) return "Network problem. Check your connection.";
    return "GitHub error " + r.status + (r.data && r.data.message ? ": " + r.data.message : "");
  }
  async function getFile(path) {
    var r = await gh(RP + "/contents/" + encPath(path) + "?ref=" + BRANCH);
    if (!r.ok) throw new Error(apiErr(r));
    return { text: b64ToUtf8(r.data.content || ""), sha: r.data.sha };
  }
  // One commit per save, strictly one at a time.
  var saveChain = Promise.resolve();
  function putFile(path, text, sha, message, tokOverride) {
    var job = saveChain.then(async function () {
      var body = { message: message, content: utf8ToB64(text), branch: BRANCH };
      if (sha) body.sha = sha;
      var r = await gh(RP + "/contents/" + encPath(path), { method: "PUT", body: body, token: tokOverride });
      if (!r.ok) throw new Error(apiErr(r));
      startBuildWatch();
      return r.data.content.sha;
    });
    saveChain = job.catch(function () {});
    return job;
  }
  async function verifyToken(t) {
    if (!/^(github_pat_|ghp_|gho_|ghu_|ghs_)/.test(t)) return "That doesn’t look like a GitHub token. It should start with github_pat_.";
    var r;
    try { r = await gh(RP, { token: t }); } catch (e) { return "Couldn’t reach GitHub. Check your connection."; }
    if (r.status === 401) return "GitHub did not accept this token. Check you copied all of it, and that it hasn’t expired.";
    if (!r.ok) return "This token can’t see the aichatsaver.github.io repository. Set Repository access to that repository.";
    if (r.data && r.data.permissions && r.data.permissions.push === false) return "This token can only read the repository. Give it Contents: Read and write.";
    return "";
  }

  /* ---------- vault ---------- */
  async function loadVault() {
    var r;
    try { r = await gh(RP + "/contents/" + VAULT_PATH + "?ref=" + BRANCH, { auth: false }); } catch (e) { r = { status: 0 }; }
    if (r.ok) return { data: JSON.parse(b64ToUtf8(r.data.content)), sha: r.data.sha };
    if (r.status === 404) return null;
    // Rate-limited or offline: fall back to the published copy.
    var p = await fetch("/control/vault.json", { cache: "no-store" }).catch(function () { return null; });
    if (p && p.ok) return { data: await p.json(), sha: null };
    if (p && p.status === 404 && r.status !== 0) return null;
    throw new Error(r.status === 403 ? "GitHub is limiting requests from this network right now. Wait a few minutes and try again." : "Couldn’t reach GitHub. Check your connection.");
  }
  async function refreshVaultSha() {
    var r = await gh(RP + "/contents/" + VAULT_PATH + "?ref=" + BRANCH);
    return r.ok ? r.data.sha : null;
  }
  function vaultText(v) { return JSON.stringify(v, null, 2) + "\n"; }

  async function boot() {
    show("vLoading");
    try {
      var s = null; try { s = sessionStorage.getItem(SS_KEY); } catch (e) {}
      vault = await loadVault();
      if (!vault) { show("vSetup"); $("suTok").focus(); return; }
      if (s) {
        token = s;
        var ok = await gh(RP);
        if (ok.ok) return openPanel();
        token = null; try { sessionStorage.removeItem(SS_KEY); } catch (e) {}
      }
      show("vLock"); $("lockPw").focus();
    } catch (e) {
      $("errText").textContent = e.message; show("vError");
    }
  }
  $("retryBtn").addEventListener("click", boot);

  // Setup
  bindMeter("suPw", "suMeter");
  $("setupForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var msg = $("suMsg"), btn = $("suSubmit"); msg.className = "cp-msg"; msg.textContent = "";
    var t = $("suTok").value.trim(), p = $("suPw").value, p2 = $("suPw2").value;
    var bad = checkNewPw(p, p2); if (bad) { msg.textContent = bad; return; }
    btn.disabled = true; msg.textContent = "Checking the token…"; msg.className = "cp-msg ok";
    try {
      var e = await verifyToken(t); if (e) { msg.className = "cp-msg"; msg.textContent = e; return; }
      msg.textContent = "Encrypting and saving…";
      var v = await encryptToken(t, p);
      var sha = await putFile(VAULT_PATH, vaultText(v), null, "Admin: set up the admin panel", t);
      vault = { data: v, sha: sha }; token = t;
      $("suTok").value = $("suPw").value = $("suPw2").value = "";
      openPanel("Setup done. Your encrypted token is saved; the site rebuilds in a minute or two.");
    } catch (err) {
      msg.className = "cp-msg";
      msg.textContent = /changed on GitHub/.test(err.message) ? "The panel is already set up. Reload the page to unlock it." : err.message;
    } finally { btn.disabled = false; }
  });

  // Unlock
  $("lockForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var msg = $("lockMsg"), btn = $("lockSubmit"), pw = $("lockPw").value;
    msg.textContent = ""; btn.disabled = true;
    var t0 = Date.now(), t = null;
    try { t = await decryptToken(vault.data, pw); } catch (e) { t = null; }
    if (!t) {
      failCount++;
      var wait = Math.min(1200 + failCount * 600, 6000) + Math.random() * 600 - (Date.now() - t0);
      await sleep(Math.max(wait, 400));
      msg.textContent = "Couldn’t unlock. Check the password and try again.";
      btn.disabled = false; $("lockPw").select(); return;
    }
    failCount = 0; token = t; $("lockPw").value = "";
    var chk = await gh(RP).catch(function () { return { status: 0 }; });
    btn.disabled = false;
    if (chk.status === 401 || chk.status === 404) {
      token = null;
      msg.textContent = "Unlocked, but GitHub no longer accepts the saved token (it may have expired). Replace it below.";
      $("lockReplace").open = true; $("lrTok").focus(); return;
    }
    if ($("lockRemember").checked) { try { sessionStorage.setItem(SS_KEY, token); } catch (e) {} }
    openPanel();
  });

  // Replace token from the lock screen (when the old one expired)
  bindMeter("lrPw", "lrMeter");
  $("lrForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var msg = $("lrMsg"); msg.className = "cp-msg"; msg.textContent = "";
    var t = $("lrTok").value.trim(), p = $("lrPw").value, p2 = $("lrPw2").value;
    var bad = checkNewPw(p, p2); if (bad) { msg.textContent = bad; return; }
    msg.className = "cp-msg ok"; msg.textContent = "Checking the token…";
    var e = await verifyToken(t); if (e) { msg.className = "cp-msg"; msg.textContent = e; return; }
    try {
      var v = await encryptToken(t, p);
      var sha = (await gh(RP + "/contents/" + VAULT_PATH + "?ref=" + BRANCH, { token: t })).data;
      sha = sha && sha.sha;
      var ns = await putFile(VAULT_PATH, vaultText(v), sha, "Admin: replace token", t);
      vault = { data: v, sha: ns }; token = t;
      $("lrTok").value = $("lrPw").value = $("lrPw2").value = "";
      openPanel("Token replaced.");
    } catch (err) { msg.className = "cp-msg"; msg.textContent = err.message; }
  });

  function lock() {
    if (anyDirty() && !confirm("You have unsaved changes. Lock anyway?")) return;
    token = null; try { sessionStorage.removeItem(SS_KEY); } catch (e) {}
    location.reload();
  }
  $("lockBtn").addEventListener("click", lock);

  /* ---------- help blocks ---------- */
  [].forEach.call(document.querySelectorAll("[data-help]"), function (d) { d.appendChild($("helpTpl").content.cloneNode(true)); });

  /* ---------- panel shell ---------- */
  var loaded = {};
  function banner(text, warn) { var b = $("banner"); b.textContent = text || ""; b.hidden = !text; b.className = "cp-banner" + (warn ? " warn" : ""); }
  function openPanel(note) {
    show("vPanel"); banner(note || "");
    selectTab(location.hash.slice(1) || "site");
  }
  function selectTab(name) {
    var btns = document.querySelectorAll(".cp-tabs button");
    if (!document.querySelector('[data-pane="' + name + '"]')) name = "site";
    [].forEach.call(btns, function (b) { b.setAttribute("aria-selected", b.getAttribute("data-tab") === name ? "true" : "false"); });
    [].forEach.call(document.querySelectorAll(".cp-pane"), function (p) { p.hidden = p.getAttribute("data-pane") !== name; });
    if (history.replaceState) history.replaceState(null, "", "#" + name);
    if (!loaded[name]) { loaded[name] = true; LOADERS[name](); }
    else if (name === "status") loadStatus();
  }
  [].forEach.call(document.querySelectorAll(".cp-tabs button"), function (b) { b.addEventListener("click", function () { selectTab(b.getAttribute("data-tab")); }); });

  var dirtyMap = {};
  function setState(id, text, cls) { var s = $(id); s.textContent = text; s.className = "cp-state" + (cls ? " " + cls : ""); }
  function markDirty(sec, on) {
    dirtyMap[sec] = on;
    var tab = document.querySelector('.cp-tabs [data-tab="' + sec + '"]');
    if (tab) { var d = tab.querySelector(".dot"); if (on && !d) tab.appendChild(el("span", { class: "dot", "aria-label": "unsaved" })); if (!on && d) d.remove(); }
  }
  function anyDirty() { for (var k in dirtyMap) if (dirtyMap[k]) return true; return false; }
  window.addEventListener("beforeunload", function (e) { if (anyDirty()) { e.preventDefault(); e.returnValue = ""; } });
  var rsT = null;
  window.addEventListener("resize", function () { clearTimeout(rsT); rsT = setTimeout(function () { [].forEach.call(document.querySelectorAll(".cp-pane:not([hidden]) textarea:not(#polBody):not(#fileBody)"), autosize); }, 120); });
  function autosize(t) { t.style.height = "auto"; t.style.height = Math.min(t.scrollHeight + 2, 600) + "px"; }

  /* ---------- YAML with comments kept (top-level keys) ---------- */
  // Splits a YAML mapping document into chunks: leading comments + the lines of each top-level key.
  function yamlChunks(text) {
    var lines = text.replace(/\r\n/g, "\n").split("\n"), chunks = [], pending = [], cur = null;
    if (lines.length && lines[lines.length - 1] === "") lines.pop();
    lines.forEach(function (ln) {
      var m = /^([A-Za-z0-9_][A-Za-z0-9_.-]*|"[^"]+"|'[^']+'):(\s|$)/.exec(ln);
      if (m) { cur = { key: m[1].replace(/^["']|["']$/g, ""), pre: pending, lines: [ln] }; chunks.push(cur); pending = []; }
      else if (cur && (/^\s/.test(ln) || /^-(\s|$)/.test(ln)) && ln.trim() !== "" && !/^\s*#/.test(ln)) { cur.lines = cur.lines.concat(pending, [ln]); pending = []; }
      else pending.push(ln);
    });
    return { chunks: chunks, tail: pending };
  }
  function dumpKey(k, v) { var o = {}; o[k] = v; return Y.dump(o, DOPT).replace(/\n$/, ""); }
  function writeYamlKeepingComments(origText, newObj) {
    var orig = Y.load(origText, YOPT) || {}, parts = yamlChunks(origText), out = [], seen = {};
    parts.chunks.forEach(function (c) {
      out = out.concat(c.pre);
      if (!(c.key in newObj)) return;
      seen[c.key] = true;
      out.push(deepEq(orig[c.key], newObj[c.key]) ? c.lines.join("\n") : dumpKey(c.key, newObj[c.key]));
    });
    Object.keys(newObj).forEach(function (k) { if (!seen[k]) out.push(dumpKey(k, newObj[k])); });
    out = out.concat(parts.tail);
    var txt = out.join("\n").replace(/\n+$/, "") + "\n";
    if (!deepEq(Y.load(txt, YOPT), newObj)) txt = leadingComments(origText) + Y.dump(newObj, DOPT); // safety net
    return txt;
  }
  function leadingComments(text) { var m = /^(?:[ \t]*#[^\n]*\n|[ \t]*\n)*/.exec(text); return m ? m[0] : ""; }

  /* ---------- list editor ---------- */
  function listEditor(values, onChange, opts) {
    opts = opts || {};
    var box = el("div", { class: "cp-list" }), arr = values.slice();
    function render() {
      box.textContent = "";
      arr.forEach(function (v, i) {
        var ta = el("textarea", { rows: 1, "aria-label": (opts.label || "Item") + " " + (i + 1) });
        ta.value = v;
        ta.addEventListener("input", function () { arr[i] = ta.value; autosize(ta); onChange(arr.slice()); });
        var row = el("div", { class: "cp-list-row" }, [
          el("span", { class: "cp-list-n", text: String(i + 1) }), ta,
          el("button", { type: "button", class: "cp-ico", title: "Move up", "aria-label": "Move up", disabled: i === 0, onclick: function () { var t = arr[i - 1]; arr[i - 1] = arr[i]; arr[i] = t; render(); onChange(arr.slice()); } }, ["↑"]),
          el("button", { type: "button", class: "cp-ico", title: "Move down", "aria-label": "Move down", disabled: i === arr.length - 1, onclick: function () { var t = arr[i + 1]; arr[i + 1] = arr[i]; arr[i] = t; render(); onChange(arr.slice()); } }, ["↓"]),
          el("button", { type: "button", class: "cp-ico", title: "Remove", "aria-label": "Remove", onclick: function () { arr.splice(i, 1); render(); onChange(arr.slice()); } }, ["✕"])
        ]);
        box.appendChild(row);
        requestAnimationFrame(function () { autosize(ta); });
      });
      box.appendChild(el("div", {}, [el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { arr.push(""); render(); onChange(arr.slice()); var all = box.querySelectorAll("textarea"); if (all.length) all[all.length - 1].focus(); } }, ["+ Add item"])]));
    }
    render();
    return box;
  }

  /* ---------- generic field renderer ---------- */
  function fieldFor(key, val, meta, onChange) {
    meta = meta || {};
    var label = meta.label || key.replace(/_/g, " ").replace(/^./, function (c) { return c.toUpperCase(); });
    var wrap = el("div", { class: "cp-field" + (meta.wide || Array.isArray(val) || (typeof val === "string" && val.length > 70) ? " wide" : "") });
    var id = "f_" + key.replace(/[^\w]/g, "_");
    wrap.appendChild(el("label", { class: "cp-label", for: id, text: label }));
    var inp;
    if (Array.isArray(val) && val.every(function (x) { return typeof x === "string" || typeof x === "number"; })) {
      wrap.appendChild(listEditor(val.map(String), function (a) { onChange(a); }, { label: label }));
    } else if (typeof val === "boolean") {
      inp = el("input", { type: "checkbox", id: id }); inp.checked = val;
      inp.addEventListener("change", function () { onChange(inp.checked); });
      wrap.appendChild(inp);
    } else if (val !== null && typeof val === "object") {
      inp = el("textarea", { id: id, class: "cp-mono", rows: 6 }); inp.value = Y.dump(val, DOPT);
      inp.addEventListener("input", function () { try { onChange(Y.load(inp.value, YOPT)); inp.setCustomValidity(""); } catch (e) { inp.setCustomValidity("Not valid YAML"); } });
      wrap.appendChild(inp);
    } else {
      var str = val == null ? "" : String(val);
      if (meta.type === "textarea" || str.length > 70) { inp = el("textarea", { id: id, rows: 2 }); requestAnimationFrame(function () { autosize(inp); }); inp.addEventListener("input", function () { autosize(inp); }); }
      else inp = el("input", { id: id, type: meta.type || "text", spellcheck: meta.type ? "false" : null, placeholder: meta.placeholder || null });
      inp.value = str;
      inp.addEventListener("input", function () {
        var v = inp.value;
        if (typeof val === "number" && /^-?\d+(\.\d+)?$/.test(v.trim())) v = Number(v.trim());
        if (val === null && v === "") v = null;
        onChange(v);
      });
      wrap.appendChild(inp);
    }
    if (meta.help) wrap.appendChild(el("span", { class: "cp-help-text", text: meta.help }));
    return wrap;
  }

  /* ---------- 1. Site settings ---------- */
  var SITE_PATH = "_data/site.yml";
  var SITE_META = {
    product_name: { label: "Product name" },
    tagline: { label: "Tagline", wide: true },
    description: { label: "Short description (search engines and link previews)", type: "textarea", wide: true },
    support_email: { label: "Support / contact email", type: "email" },
    price_monthly: { label: "Pro monthly price", help: "A number such as 4.99, or TBD for “Coming soon”." },
    price_yearly: { label: "Pro yearly price", help: "A number such as 39, or TBD for “Coming soon”." },
    price_currency: { label: "Currency", help: "USD shows a $ sign; anything else is written after the price." },
    pro_status: { label: "Pro status text" },
    refund_days: { label: "Refund days (Yearly plan)", type: "number" },
    command_center_shortcut: { label: "Command Center shortcut" },
    chrome_store_url: { label: "Chrome Web Store link", type: "url", placeholder: "Empty = Coming soon", wide: true },
    edge_store_url: { label: "Microsoft Edge Add-ons link", type: "url", placeholder: "Empty = Coming soon", wide: true },
    policies_updated: { label: "Policies updated (date)", type: "date" },
    free_features: { label: "Free plan features" },
    pro_features: { label: "Pro plan features" }
  };
  var site = { text: "", sha: null, orig: null, cur: null };
  async function loadSite() {
    setState("siteState", "Loading…"); $("siteForm").textContent = "";
    try {
      var f = await getFile(SITE_PATH);
      site.text = f.text; site.sha = f.sha; site.orig = Y.load(f.text, YOPT) || {}; site.cur = clone(site.orig);
      renderSite(); setState("siteState", "Up to date"); markDirty("site", false);
    } catch (e) { setState("siteState", e.message, "err"); loaded.site = false; }
  }
  function renderSite() {
    var form = $("siteForm"); form.textContent = "";
    Object.keys(site.cur).forEach(function (k) {
      form.appendChild(fieldFor(k, site.cur[k], SITE_META[k], function (v) {
        site.cur[k] = v;
        var d = !deepEq(site.cur, site.orig); markDirty("site", d); setState("siteState", d ? "Unsaved changes" : "Up to date", d ? "dirty" : "");
      }));
    });
  }
  function cleanSite(o) {
    var c = clone(o);
    Object.keys(c).forEach(function (k) { if (Array.isArray(c[k])) c[k] = c[k].map(function (s) { return typeof s === "string" ? s.trim() : s; }).filter(function (s) { return s !== ""; }); else if (typeof c[k] === "string" && k !== "price_monthly" && k !== "price_yearly") c[k] = c[k].trim(); });
    return c;
  }
  $("siteSave").addEventListener("click", async function () {
    if (!dirtyMap.site) { setState("siteState", "Nothing to save"); return; }
    var data = cleanSite(site.cur);
    if (data.support_email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(data.support_email)) { setState("siteState", "The support email doesn’t look right.", "err"); return; }
    var bad = ["chrome_store_url", "edge_store_url"].filter(function (k) { return data[k] && !/^https:\/\//.test(data[k]); });
    if (bad.length) { setState("siteState", "Store links must start with https://", "err"); return; }
    var txt = writeYamlKeepingComments(site.text, data);
    await saveFlow("site", "siteState", "siteSave", SITE_PATH, txt, site.sha, function (sha) { site.text = txt; site.sha = sha; site.orig = Y.load(txt, YOPT); site.cur = clone(site.orig); renderSite(); });
  });
  $("siteReload").addEventListener("click", function () { if (!dirtyMap.site || confirm("Discard your unsaved changes?")) loadSite(); });

  async function saveFlow(sec, stateId, btnId, path, text, sha, after) {
    var btn = $(btnId); btn.disabled = true; setState(stateId, "Saving…");
    try {
      var ns = await putFile(path, text, sha, "Admin: update " + path);
      after(ns); markDirty(sec, false);
      setState(stateId, "Saved. The live site updates in a minute or two (see Status).", "ok");
    } catch (e) { setState(stateId, e.message, "err"); }
    finally { btn.disabled = false; }
  }

  /* ---------- 2. Policies ---------- */
  var pol = { name: "privacy", text: "", sha: null, fmText: "", fm: {}, fmCur: {}, body: "", bodyCur: "" };
  function splitFm(text) {
    var t = text.replace(/\r\n/g, "\n"), m = /^---\n([\s\S]*?)\n---\n?/.exec(t);
    if (!m) return { fmText: "", body: t };
    return { fmText: m[1] + "\n", body: t.slice(m[0].length) };
  }
  async function loadPolicy(name) {
    if (dirtyMap.policies && !confirm("Discard your unsaved changes to this policy?")) return;
    markDirty("policies", false);
    pol.name = name;
    [].forEach.call(document.querySelectorAll("#polPick button"), function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-pol") === name ? "true" : "false"); });
    var path = "pages/" + name + ".md"; $("polPath").textContent = path;
    setState("polState", "Loading…");
    try {
      if (!site.orig) await loadSiteQuiet();
      var f = await getFile(path), sp = splitFm(f.text);
      pol.text = f.text; pol.sha = f.sha; pol.fmText = sp.fmText; pol.fm = Y.load(sp.fmText, YOPT) || {}; pol.fmCur = clone(pol.fm);
      pol.body = sp.body; pol.bodyCur = sp.body;
      var form = $("polFm"); form.textContent = "";
      Object.keys(pol.fmCur).forEach(function (k) {
        var meta = { title: { label: "Title" }, description: { label: "Description (search engines)", wide: true, type: "textarea" }, permalink: { label: "Address (permalink)", help: "Changing this breaks existing links." } }[k];
        form.appendChild(fieldFor(k, pol.fmCur[k], meta, function (v) { pol.fmCur[k] = v; polDirty(); }));
      });
      $("polBody").value = pol.bodyCur; preview();
      markDirty("policies", false); setState("polState", "Up to date");
    } catch (e) { setState("polState", e.message, "err"); }
  }
  async function loadSiteQuiet() { try { var f = await getFile(SITE_PATH); site.text = site.text || f.text; site.sha = site.sha || f.sha; site.orig = site.orig || Y.load(f.text, YOPT); if (!site.cur) site.cur = clone(site.orig); } catch (e) {} }
  function polDirty() { var d = pol.bodyCur !== pol.body || !deepEq(pol.fmCur, pol.fm); markDirty("policies", d); setState("polState", d ? "Unsaved changes" : "Up to date", d ? "dirty" : ""); }
  var prevTimer = null;
  $("polBody").addEventListener("input", function () { pol.bodyCur = $("polBody").value; polDirty(); clearTimeout(prevTimer); prevTimer = setTimeout(preview, 150); });
  [].forEach.call(document.querySelectorAll("#polPick button"), function (b) { b.addEventListener("click", function () { if (b.getAttribute("data-pol") !== pol.name) loadPolicy(b.getAttribute("data-pol")); }); });
  $("polReload").addEventListener("click", function () { if (!dirtyMap.policies || confirm("Discard your unsaved changes?")) { markDirty("policies", false); loadPolicy(pol.name); } });
  $("polSave").addEventListener("click", async function () {
    if (!dirtyMap.policies) { setState("polState", "Nothing to save"); return; }
    var body = pol.bodyCur.replace(/\r\n/g, "\n"); if (!/\n$/.test(body)) body += "\n";
    var fmText = deepEq(pol.fmCur, pol.fm) ? pol.fmText : writeYamlKeepingComments(pol.fmText, pol.fmCur);
    var txt = (pol.fmText || !deepEq(pol.fmCur, {}) ? "---\n" + fmText + "---\n" : "") + body;
    await saveFlow("policies", "polState", "polSave", "pages/" + pol.name + ".md", txt, pol.sha, function (sha) { pol.sha = sha; pol.text = txt; pol.fmText = fmText; pol.fm = clone(pol.fmCur); pol.body = body; pol.bodyCur = body; });
  });

  // Small Markdown preview (escapes HTML; Liquid values filled from Site settings).
  function esc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
  function liquid(src) {
    var vars = site.cur || site.orig || {};
    return src.replace(/^\s*\{%[\s\S]*?%\}\s*$/gm, "").replace(/\{%[\s\S]*?%\}/g, "").replace(/\{\{\s*([\w.]+)([^}]*)\}\}/g, function (m, name, rest) {
      var k = name.replace(/^(s|site\.data\.site)\./, ""), v = vars[k];
      if (v == null) return "";
      if (/date/.test(rest)) { var d = new Date(String(v) + "T00:00:00"); if (!isNaN(d)) return d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" }); }
      if (/upcase/.test(rest)) return String(v).toUpperCase();
      return String(v);
    });
  }
  function inline(s) {
    s = esc(s);
    s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/__([^_]+)__/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1<em>$2</em>").replace(/(^|[^_\w])_([^_\n]+)_(?!\w)/g, "$1<em>$2</em>");
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function (m, t, u) { var raw = u.replace(/&amp;/g, "&"); return /^(https?:|mailto:|\/|#)/i.test(raw) ? '<a href="' + u + '" target="_blank" rel="noopener">' + t + "</a>" : t; });
    s = s.replace(/&lt;(https?:\/\/[^\s&]+)&gt;/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    return s;
  }
  function md(src) {
    var lines = liquid(src).replace(/\r\n/g, "\n").split("\n"), out = [], i = 0, para = [];
    function flush() { if (para.length) { out.push("<p>" + inline(para.join(" ")) + "</p>"); para = []; } }
    while (i < lines.length) {
      var ln = lines[i], m;
      if (/^\s*$/.test(ln)) { flush(); i++; continue; }
      if ((m = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(ln))) { flush(); var n = m[1].length; out.push("<h" + n + ">" + inline(m[2].replace(/\s*\{:.*\}$/, "")) + "</h" + n + ">"); i++; continue; }
      if (/^(\*\s*){3,}$|^(-\s*){3,}$/.test(ln)) { flush(); out.push("<hr>"); i++; continue; }
      if (/^```/.test(ln)) { flush(); var code = []; i++; while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]); i++; out.push("<pre><code>" + esc(code.join("\n")) + "</code></pre>"); continue; }
      if (/^>\s?/.test(ln)) { flush(); var q = []; while (i < lines.length && /^>\s?/.test(lines[i])) q.push(lines[i++].replace(/^>\s?/, "")); out.push("<blockquote>" + md(q.join("\n")) + "</blockquote>"); continue; }
      if (/^\|.*\|\s*$/.test(ln) && i + 1 < lines.length && /^\|?\s*:?-{2,}/.test(lines[i + 1])) {
        flush(); var rows = []; while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) rows.push(lines[i++]);
        var cells = function (r) { return r.replace(/^\||\|\s*$/g, "").split("|").map(function (c) { return inline(c.trim()); }); };
        var h = "<table><thead><tr>" + cells(rows[0]).map(function (c) { return "<th>" + c + "</th>"; }).join("") + "</tr></thead><tbody>";
        rows.slice(2).forEach(function (r) { h += "<tr>" + cells(r).map(function (c) { return "<td>" + c + "</td>"; }).join("") + "</tr>"; });
        out.push(h + "</tbody></table>"); continue;
      }
      if ((m = /^(\s*)([-*+]|\d+[.)])\s+/.exec(ln))) {
        flush(); var ordered = /\d/.test(m[2]), items = [];
        while (i < lines.length && (m = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(lines[i]))) {
          var it = [m[3]]; i++;
          while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) it.push(lines[i++].trim());
          items.push("<li>" + inline(it.join(" ")) + "</li>");
        }
        out.push((ordered ? "<ol>" : "<ul>") + items.join("") + (ordered ? "</ol>" : "</ul>")); continue;
      }
      para.push(ln.trim()); i++;
    }
    flush();
    return out.join("\n");
  }
  function preview() { var h = "<h1>" + inline(liquid(String(pol.fmCur.title || ""))) + "</h1>" + md(pol.bodyCur); $("polPrev").innerHTML = h; }

  /* ---------- 3. Translations ---------- */
  var tr = { code: "", text: "", sha: null, data: null, cur: null, en: null, langs: [] };
  function flatten(o, pre, out) {
    out = out || [];
    if (Array.isArray(o)) o.forEach(function (v, i) { flatten(v, pre.concat([i]), out); });
    else if (o && typeof o === "object") Object.keys(o).forEach(function (k) { flatten(o[k], pre.concat([k]), out); });
    else out.push({ path: pre, value: o });
    return out;
  }
  function getAt(o, p) { for (var i = 0; i < p.length; i++) { if (o == null) return undefined; o = o[p[i]]; } return o; }
  function setAt(o, p, v) { for (var i = 0; i < p.length - 1; i++) o = o[p[i]]; o[p[p.length - 1]] = v; }
  async function loadI18nTab() {
    try {
      var lf = await getFile("_data/languages.yml");
      tr.langs = Y.load(lf.text, YOPT) || [];
      var sel = $("langPick"); sel.textContent = "";
      tr.langs.forEach(function (l) { sel.appendChild(el("option", { value: l.code, text: l.name + " (" + l.code + ")" })); });
      var enf = await getFile("_data/i18n/en.yml"); tr.en = Y.load(enf.text, YOPT);
      var first = (tr.langs.filter(function (l) { return l.code !== "en"; })[0] || tr.langs[0]).code;
      sel.value = first; await loadLang(first);
    } catch (e) { setState("i18nState", e.message, "err"); loaded.i18n = false; }
  }
  var lastLang = "";
  $("langPick").addEventListener("change", async function () {
    var c = $("langPick").value;
    if (dirtyMap.i18n && !confirm("Discard your unsaved translation changes?")) { $("langPick").value = lastLang; return; }
    markDirty("i18n", false); await loadLang(c);
  });
  async function loadLang(code) {
    setState("i18nState", "Loading…"); $("i18nForm").textContent = "";
    var path = "_data/i18n/" + code + ".yml"; $("i18nPath").textContent = path;
    try {
      var f = await getFile(path);
      tr.code = code; lastLang = code; tr.text = f.text; tr.sha = f.sha; tr.data = Y.load(f.text, YOPT) || {}; tr.cur = clone(tr.data);
      if (code === "en") tr.en = clone(tr.data);
      renderI18n(); markDirty("i18n", false); setState("i18nState", "Up to date");
    } catch (e) { setState("i18nState", e.message, "err"); }
  }
  function renderI18n() {
    var box = $("i18nForm"); box.textContent = "";
    var lang = tr.langs.filter(function (l) { return l.code === tr.code; })[0] || {};
    var rtl = lang.dir === "rtl", group = null;
    flatten(tr.cur, []).forEach(function (f) {
      var top = f.path[0];
      if (top !== group) { group = top; box.appendChild(el("h3", { text: top })); }
      var key = f.path.join("."), enVal = getAt(tr.en, f.path);
      var ta = el("textarea", { rows: 1, lang: lang.hreflang || tr.code, dir: rtl ? "rtl" : null, "aria-label": key });
      ta.value = f.value == null ? "" : String(f.value);
      var row = el("div", { class: "cp-tr-row", "data-k": (key + " " + ta.value + " " + (enVal || "")).toLowerCase() }, [
        el("div", { class: "cp-tr-key", text: key }),
        el("div", { class: "cp-tr-en", lang: "en", text: enVal == null ? "—" : String(enVal) }),
        ta
      ]);
      ta.addEventListener("input", function () {
        var v = ta.value; if (typeof f.value === "number" && /^\d+$/.test(v)) v = Number(v);
        setAt(tr.cur, f.path, v); autosize(ta);
        row.classList.toggle("changed", getAt(tr.data, f.path) !== v);
        var d = !deepEq(tr.cur, tr.data); markDirty("i18n", d); setState("i18nState", d ? "Unsaved changes" : "Up to date", d ? "dirty" : "");
      });
      box.appendChild(row);
    });
    requestAnimationFrame(function () { [].forEach.call(box.querySelectorAll("textarea"), autosize); });
    applyFilter();
  }
  function applyFilter() {
    var q = $("i18nFilter").value.trim().toLowerCase();
    [].forEach.call($("i18nForm").children, function (c) { if (c.classList.contains("cp-tr-row")) c.hidden = q && c.getAttribute("data-k").indexOf(q) < 0; });
    [].forEach.call($("i18nForm").querySelectorAll("h3"), function (h) { var n = h.nextElementSibling, any = false; while (n && n.tagName !== "H3") { if (!n.hidden) any = true; n = n.nextElementSibling; } h.hidden = !any; });
  }
  $("i18nFilter").addEventListener("input", applyFilter);
  $("i18nReload").addEventListener("click", function () { if (!dirtyMap.i18n || confirm("Discard your unsaved changes?")) loadLang(tr.code); });
  $("i18nSave").addEventListener("click", async function () {
    if (!dirtyMap.i18n) { setState("i18nState", "Nothing to save"); return; }
    var txt = leadingComments(tr.text) + Y.dump(tr.cur, Object.assign({}, DOPT, { noArrayIndent: true }));
    if (!deepEq(Y.load(txt, YOPT), tr.cur)) { setState("i18nState", "Couldn’t write this file safely. Nothing was saved.", "err"); return; }
    var path = "_data/i18n/" + tr.code + ".yml";
    await saveFlow("i18n", "i18nState", "i18nSave", path, txt, tr.sha, function (sha) { tr.sha = sha; tr.text = txt; tr.data = clone(tr.cur); if (tr.code === "en") tr.en = clone(tr.cur); [].forEach.call(document.querySelectorAll(".cp-tr-row.changed"), function (r) { r.classList.remove("changed"); }); });
  });

  /* ---------- 4. Other files ---------- */
  var file = { path: "", sha: null, text: "" };
  var TEXT_EXT = /\.(html?|md|markdown|ya?ml|css|js|json|txt|xml|svg)$/i;
  async function loadFilesTab() {
    var sel = $("filePick"); sel.textContent = "";
    setState("fileState", "Loading…");
    var r = await gh(RP + "/git/trees/" + BRANCH + "?recursive=1");
    if (!r.ok) { setState("fileState", apiErr(r), "err"); loaded.files = false; return; }
    var paths = r.data.tree.filter(function (t) { return t.type === "blob" && TEXT_EXT.test(t.path) && !/^control\//.test(t.path); }).map(function (t) { return t.path; }).sort();
    sel.appendChild(el("option", { value: "", text: "Choose a file…" }));
    paths.forEach(function (p) { sel.appendChild(el("option", { value: p, text: p })); });
    setState("fileState", "");
  }
  var lastFile = "";
  $("filePick").addEventListener("change", async function () {
    var p = $("filePick").value;
    if (dirtyMap.files && !confirm("Discard your unsaved changes to " + lastFile + "?")) { $("filePick").value = lastFile; return; }
    markDirty("files", false); if (!p) return; lastFile = p;
    setState("fileState", "Loading…"); $("fileBody").value = "";
    try { var f = await getFile(p); file = { path: p, sha: f.sha, text: f.text }; $("fileBody").value = f.text; setState("fileState", "Up to date"); }
    catch (e) { setState("fileState", e.message, "err"); }
  });
  $("fileBody").addEventListener("input", function () { if (!file.path) return; var d = $("fileBody").value !== file.text; markDirty("files", d); setState("fileState", d ? "Unsaved changes" : "Up to date", d ? "dirty" : ""); });
  $("fileReload").addEventListener("click", function () { if (!file.path) return; if (!dirtyMap.files || confirm("Discard your unsaved changes?")) { markDirty("files", false); $("filePick").dispatchEvent(new Event("change")); } });
  $("fileSave").addEventListener("click", async function () {
    if (!file.path || !dirtyMap.files) { setState("fileState", "Nothing to save"); return; }
    var txt = $("fileBody").value;
    if (/\.ya?ml$/i.test(file.path)) { try { Y.load(txt.replace(/^---\n|\n---\n?$/g, ""), YOPT); } catch (e) { setState("fileState", "This YAML has an error, so it wasn’t saved: " + e.reason, "err"); return; } }
    if (/\.json$/i.test(file.path)) { try { JSON.parse(txt); } catch (e) { setState("fileState", "This JSON has an error, so it wasn’t saved.", "err"); return; } }
    await saveFlow("files", "fileState", "fileSave", file.path, txt, file.sha, function (sha) { file.sha = sha; file.text = txt; });
  });

  /* ---------- 5. Status ---------- */
  function fmtDate(s) { try { return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }); } catch (e) { return s; } }
  async function loadStatus() {
    var box = $("buildBox");
    var r = await gh(RP + "/pages/builds/latest");
    if (!r.ok) r = await gh(RP + "/pages/builds/latest", { auth: false });
    box.textContent = "";
    if (r.ok && r.data) {
      var st = r.data.status || "unknown", err = r.data.error && r.data.error.message;
      var label = { built: "Live", building: "Building…", queued: "Queued", errored: "Build failed" }[st] || st;
      box.appendChild(el("div", {}, [el("div", { class: "cp-label", text: "Last site build" }), el("span", { class: "cp-pill " + st, text: label })]));
      box.appendChild(el("div", {}, [el("div", { class: "cp-label", text: "Finished" }), el("span", { class: "muted", text: fmtDate(r.data.updated_at || r.data.created_at) })]));
      if (r.data.duration) box.appendChild(el("div", {}, [el("div", { class: "cp-label", text: "Took" }), el("span", { class: "muted", text: Math.round(r.data.duration / 1000) + " s" })]));
      if (err) box.appendChild(el("p", { class: "cp-msg wide", text: "Error: " + err }));
      if (st === "building" || st === "queued") startBuildWatch();
    } else box.appendChild(el("p", { class: "muted", text: "Couldn’t read the build status. " + apiErr(r) }));
    var c = await gh(RP + "/commits?sha=" + BRANCH + "&per_page=10"), list = $("commitList"); list.textContent = "";
    if (c.ok) c.data.forEach(function (x) {
      list.appendChild(el("li", {}, [el("code", { text: x.sha.slice(0, 7) }), el("span", { class: "msg", text: (x.commit.message || "").split("\n")[0] }), el("time", { datetime: x.commit.committer.date, text: fmtDate(x.commit.committer.date) })]));
    });
    else list.appendChild(el("li", { class: "muted", text: apiErr(c) }));
  }
  var watchTimer = null, watchUntil = 0;
  function startBuildWatch() {
    watchUntil = Date.now() + 4 * 60 * 1000;
    if (watchTimer) return;
    watchTimer = setInterval(function () {
      if (Date.now() > watchUntil) { clearInterval(watchTimer); watchTimer = null; return; }
      if (!$("vPanel").hidden && !document.querySelector('[data-pane="status"]').hidden) loadStatus();
    }, 15000);
  }
  $("statusRefresh").addEventListener("click", loadStatus);

  /* ---------- 6. Security ---------- */
  bindMeter("cpwNew", "cpwMeter");
  $("cpwForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var msg = $("cpwMsg"); msg.className = "cp-msg"; msg.textContent = "";
    var old = $("cpwOld").value, a = $("cpwNew").value, b = $("cpwNew2").value;
    var bad = checkNewPw(a, b); if (bad) { msg.textContent = bad; return; }
    msg.className = "cp-msg ok"; msg.textContent = "Checking…";
    var t = null; try { t = await decryptToken(vault.data, old); } catch (e) {}
    if (!t) { await sleep(1200 + Math.random() * 600); msg.className = "cp-msg"; msg.textContent = "The current password isn’t right."; return; }
    try {
      var v = await encryptToken(t, a), sha = await refreshVaultSha() || vault.sha;
      var ns = await putFile(VAULT_PATH, vaultText(v), sha, "Admin: change password");
      vault = { data: v, sha: ns };
      $("cpwOld").value = $("cpwNew").value = $("cpwNew2").value = "";
      msg.className = "cp-msg ok"; msg.textContent = "Password changed. Use the new one next time.";
    } catch (e) { msg.className = "cp-msg"; msg.textContent = e.message; }
  });
  $("rtForm").addEventListener("submit", async function (ev) {
    ev.preventDefault();
    var msg = $("rtMsg"); msg.className = "cp-msg"; msg.textContent = "";
    var nt = $("rtTok").value.trim(), pw = $("rtPw").value;
    var t = null; try { t = await decryptToken(vault.data, pw); } catch (e) {}
    if (!t) { await sleep(1200 + Math.random() * 600); msg.textContent = "The current password isn’t right."; return; }
    msg.className = "cp-msg ok"; msg.textContent = "Checking the new token…";
    var e = await verifyToken(nt); if (e) { msg.className = "cp-msg"; msg.textContent = e; return; }
    try {
      var v = await encryptToken(nt, pw), sha = await refreshVaultSha() || vault.sha;
      var ns = await putFile(VAULT_PATH, vaultText(v), sha, "Admin: replace token", nt);
      vault = { data: v, sha: ns }; token = nt;
      try { if (sessionStorage.getItem(SS_KEY)) sessionStorage.setItem(SS_KEY, nt); } catch (x) {}
      $("rtTok").value = $("rtPw").value = "";
      msg.className = "cp-msg ok"; msg.textContent = "Token replaced. You can delete the old token on GitHub.";
    } catch (err) { msg.className = "cp-msg"; msg.textContent = err.message; }
  });

  var LOADERS = { site: loadSite, policies: function () { loadPolicy("privacy"); }, i18n: loadI18nTab, files: loadFilesTab, status: loadStatus, security: function () {} };

  boot();
})();
