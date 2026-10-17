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
    if (r.status === 403) return "GitHub refused to save" + (r.data && r.data.message ? " (“" + r.data.message + "”)" : "") + ". The token can read but not write this repository. Make the token with Resource owner = aichatsaver, Only select repositories = aichatsaver.github.io, and Contents = Read and write. Or use a classic token with the public_repo scope.";
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
  var saveChain = Promise.resolve(), lastCommitSha = null;
  function putFile(path, text, sha, message, tokOverride) {
    var job = saveChain.then(async function () {
      var body = { message: message, content: utf8ToB64(text), branch: BRANCH };
      if (sha) body.sha = sha;
      var r = await gh(RP + "/contents/" + encPath(path), { method: "PUT", body: body, token: tokOverride });
      if (!r.ok) throw new Error(apiErr(r));
      startBuildWatch();
      lastCommitSha = r.data.commit && r.data.commit.sha;
      return r.data.content.sha;
    });
    saveChain = job.catch(function () {});
    return job;
  }
  async function verifyToken(t) {
    if (!/^(github_pat_|ghp_|gho_|ghu_|ghs_)/.test(t)) return "That doesn’t look like a GitHub token. It should start with github_pat_ or ghp_.";
    var r;
    try { r = await gh(RP, { token: t }); } catch (e) { return "Couldn’t reach GitHub. Check your connection."; }
    if (r.status === 401) return "GitHub did not accept this token. Check you copied all of it, and that it hasn’t expired.";
    if (!r.ok) return "This token can’t see the aichatsaver.github.io repository. Set Repository access to that repository.";
    if (r.data && r.data.permissions && r.data.permissions.push === false) return "This token can only read the repository. Give it Contents: Read and write.";
    // Write probe that changes nothing: an invalid ref name gets 422 when the token may write, 403/404 when it may not.
    var w;
    try { w = await gh(RP + "/git/refs", { method: "POST", token: t, body: { ref: "refs/heads/..invalid..", sha: "0000000000000000000000000000000000000000" } }); } catch (e) { return "Couldn’t reach GitHub. Check your connection."; }
    if (w.status === 403 || w.status === 404) {
      var gm = w.data && w.data.message ? " GitHub says: “" + w.data.message + "”." : "";
      if (/^github_pat_/.test(t)) return "This token can read the repository but GitHub won’t let it write." + gm + " On the token page check: Resource owner = aichatsaver (not your own account), Repository access = Only select repositories → aichatsaver.github.io, Repository permissions → Contents = Read and write. Resource owner can’t be edited later, so make a new token if it’s wrong. A classic token with the public_repo scope also works.";
      return "This token can read the repository but GitHub won’t let it write." + gm + " For a classic token, tick the public_repo (or repo) scope.";
    }
    if (w.status === 401) return "GitHub did not accept this token. Check you copied all of it, and that it hasn’t expired.";
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

  /* =====================================================================
     Infrastructure: help blocks, toasts, documents, edit operations, drafts,
     commits (single file via Contents API, many files as ONE commit via the Git Data API),
     build progress, sidebar shell, sections.
     ===================================================================== */
  [].forEach.call(document.querySelectorAll("[data-help]"), function (d) { d.appendChild($("helpTpl").content.cloneNode(true)); });

  var SITE_URL = "https://aichatsaver.github.io";
  var LIVE_NOTE = "Live in ~1 min; press Ctrl+Shift+R if you don’t see it.";

  /* ---------- toasts ---------- */
  function toast(msg, kind, ms) {
    var t = el("div", { class: "cp-toast" + (kind ? " " + kind : ""), role: kind === "err" ? "alert" : "status" }, [msg]);
    $("toasts").appendChild(t);
    setTimeout(function () { t.classList.add("out"); setTimeout(function () { t.remove(); }, 300); }, ms || (kind === "err" ? 7000 : 3200));
    return t;
  }

  /* ---------- small helpers ---------- */
  function isTextPath(p) { return /\.(html?|md|markdown|ya?ml|css|js|json|txt|xml|svg)$/i.test(p); }
  function isImagePath(p) { return /\.(png|jpe?g|svg|webp|gif)$/i.test(p); }
  function fmtBytes(n) { return n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB" : (n / 1048576).toFixed(2) + " MB"; }
  function debounce(fn, ms) { var t = null; return function () { var a = arguments, s = this; clearTimeout(t); t = setTimeout(function () { fn.apply(s, a); }, ms); }; }
  function setDeep(o, p, v) { for (var i = 0; i < p.length - 1; i++) { if (o[p[i]] == null || typeof o[p[i]] !== "object") o[p[i]] = typeof p[i + 1] === "number" ? [] : {}; o = o[p[i]]; } o[p[p.length - 1]] = v; }
  function slug(s) { return String(s).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "image"; }
  function bustUrl(u) { return SITE_URL + u.replace(/#.*$/, "") + (u.indexOf("?") > -1 ? "&" : "?") + "t=" + Date.now() + (u.indexOf("#") > -1 ? u.slice(u.indexOf("#")) : ""); }

  // Sanitized HTML for previews (texts may contain simple HTML such as <strong>, <kbd>, <a>).
  function safeHtml(s) {
    var d = new DOMParser().parseFromString("<body>" + String(s == null ? "" : s) + "</body>", "text/html");
    [].forEach.call(d.querySelectorAll("script,style,iframe,object,embed,link,meta,base,form,input,button,textarea,select,svg,math"), function (n) { n.remove(); });
    [].forEach.call(d.body.querySelectorAll("*"), function (n) {
      [].slice.call(n.attributes).forEach(function (a) {
        var nm = a.name.toLowerCase();
        if (/^on/.test(nm) || nm === "style" || nm === "srcdoc" || ((nm === "href" || nm === "src" || nm === "xlink:href" || nm === "action") && /^\s*(javascript|data|vbscript):/i.test(a.value))) n.removeAttribute(a.name);
      });
      if (n.tagName === "A") { n.setAttribute("target", "_blank"); n.setAttribute("rel", "noopener"); }
    });
    return d.body.innerHTML;
  }
  function htmlEl(tag, attrs, html) { var e = el(tag, attrs); e.innerHTML = safeHtml(html); return e; }
  // Text an owner types into a field: refuse anything that could run code on the public site.
  function unsafeHtml(s) { return /<\s*(script|iframe|object|embed|style|link|meta|base|form)\b|\son[a-z]+\s*=|javascript\s*:|vbscript\s*:|data\s*:\s*text\/html/i.test(String(s || "")); }
  function badLink(u, allowRelative) {
    u = String(u || "").trim(); if (!u) return "";
    if (/\/control(\/|$|\?|#)/i.test(u) || /^control(\/|$)/i.test(u)) return "The admin panel must never be linked from the public site.";
    if (/^https:\/\/[^\s"'<>]+$/i.test(u)) return "";
    if (allowRelative && /^\/[^\s"'<>]*$/.test(u) && !/^\/\//.test(u)) return "";
    if (allowRelative === "mail" && /^mailto:[^\s"'<>]+$/i.test(u)) return "";
    return allowRelative ? "Links must start with https:// or / (a page on this site)." : "Links must start with https://";
  }
  function placeholders(s) { return (String(s || "").match(/%[a-z_]+%/g) || []).sort(); }

  /* ---------- documents ---------- */
  var DOCS = {}, REV = {};
  function bump(p) { REV[p] = (REV[p] || 0) + 1; }
  async function fetchDoc(path, ref) {
    var r = await gh(RP + "/contents/" + encPath(path) + "?ref=" + (ref || BRANCH));
    var d;
    if (r.status === 404) d = { text: "", b64: "", sha: null, missing: true };
    else if (!r.ok) throw new Error(apiErr(r));
    else { var b = String(r.data.content || "").replace(/\s+/g, ""); d = { text: isTextPath(path) ? b64ToUtf8(b) : null, b64: b, sha: r.data.sha, missing: false }; }
    if (!ref || ref === BRANCH) { DOCS[path] = d; bump(path); }
    return d;
  }
  async function doc(path, force) { return (!force && DOCS[path]) || fetchDoc(path); }

  /* ---------- edit operations (serializable, re-applied on the newest copy) ---------- */
  function yamlSetKeys(text, keys) {
    var o = (text ? Y.load(text, YOPT) : null) || {};
    Object.keys(keys).forEach(function (k) { o[k] = keys[k]; });
    return writeYamlKeepingComments(text || "", o);
  }
  function yamlSetPaths(text, sets) {
    var o = (text ? Y.load(text, YOPT) : null) || {};
    sets.forEach(function (s) { setDeep(o, s[0], clone(s[1])); });
    var out = leadingComments(text || "") + Y.dump(o, Object.assign({}, DOPT, { noArrayIndent: true }));
    if (!deepEq(Y.load(out, YOPT), o)) throw new Error("Couldn’t write this file safely. Nothing was saved.");
    return out;
  }
  function fmSet(text, key, value) {
    var t = text.replace(/\r\n/g, "\n"), m = /^---\n([\s\S]*?\n)?---\n?/.exec(t);
    if (!m) return value == null ? t : "---\n" + key + ": " + value + "\n---\n" + t;
    var lines = (m[1] || "").split("\n").filter(function (l, i, a) { return !(i === a.length - 1 && l === ""); });
    lines = lines.filter(function (l) { return l.indexOf(key + ":") !== 0; });
    if (value != null) lines.push(key + ": " + value);
    return "---\n" + lines.join("\n") + (lines.length ? "\n" : "") + "---\n" + t.slice(m[0].length);
  }
  function langEnabledSet(text, code, on) {
    var lines = text.replace(/\r\n/g, "\n").split("\n"), out = [], inBlock = false;
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i], m = /^-\s+code:\s*["']?([\w-]+)["']?\s*$/.exec(ln);
      if (m) { inBlock = m[1] === code; out.push(ln); if (inBlock && !on) out.push("  enabled: false"); continue; }
      if (/^\S/.test(ln)) inBlock = false;
      if (inBlock && /^\s+enabled:/.test(ln)) continue;
      out.push(ln);
    }
    return out.join("\n");
  }
  function applyOps(text, ops) {
    (ops || []).forEach(function (op) {
      if (op.t === "text") text = op.text;
      else if (op.t === "yset") text = yamlSetKeys(text, op.keys);
      else if (op.t === "ypath") text = yamlSetPaths(text, op.sets);
      else if (op.t === "fm") text = fmSet(text, op.key, op.value);
      else if (op.t === "lang") text = langEnabledSet(text, op.code, op.on);
    });
    return text;
  }
  function touchesEnglish(ch) {
    return ch.some(function (c) {
      if (c.path === "_data/i18n/en.yml" || ["_data/navigation.yml", "_data/home.yml", "_data/announcement.yml", "_data/seo.yml", "_data/coupon.yml"].indexOf(c.path) > -1) return true;
      return c.path === "_data/site.yml" && c.ops.some(function (o) { return o.t === "yset" && Object.keys(o.keys).some(function (k) { return ["tagline", "description", "pro_status", "free_features", "pro_features"].indexOf(k) > -1; }); });
    });
  }
  function isFullOp(o) { return o.t === "text" || o.t === "b64" || o.t === "del"; }
  function mergeOps(a, b) { var last = -1; b.forEach(function (o, i) { if (isFullOp(o)) last = i; }); return last > -1 ? b.slice(last) : a.concat(b); }

  /* ---------- drafts (kept in this browser until published) ---------- */
  var DRAFT_KEY = "acs_admin_drafts_v1", DRAFTS = {};
  try { DRAFTS = JSON.parse(localStorage.getItem(DRAFT_KEY) || "{}") || {}; } catch (e) { DRAFTS = {}; }
  var draftsPersistWarned = false;
  function saveDrafts() {
    try { localStorage.setItem(DRAFT_KEY, JSON.stringify(DRAFTS)); }
    catch (e) { if (!draftsPersistWarned) { draftsPersistWarned = true; toast("Drafts are too large to keep after a reload (big images). Publish them before closing this tab.", "warn", 9000); } }
    updateDraftUI();
  }
  function draftCount() { return Object.keys(DRAFTS).length; }
  function stageOps(path, ops, label) {
    var d = DRAFTS[path] || (DRAFTS[path] = { ops: [], labels: [], base: DOCS[path] ? DOCS[path].sha : null });
    d.ops = mergeOps(d.ops, ops);
    if (ops.some(function (o) { return o.t === "b64"; })) delete PENDING[path];
    if (d.labels.indexOf(label) < 0) d.labels.push(label);
    d.at = Date.now(); bump(path); saveDrafts();
  }
  function dropDraft(path) { if (DRAFTS[path]) { delete DRAFTS[path]; bump(path); saveDrafts(); } }
  function updateDraftUI() {
    var n = draftCount(), c = $("draftCount"), p = $("draftPill");
    c.textContent = String(n); c.hidden = !n;
    p.textContent = n + (n === 1 ? " draft" : " drafts"); p.hidden = !n || $("vPanel").hidden;
  }
  // The text an editor should show: the copy on GitHub with this browser's drafts applied.
  function effText(path) {
    var d = DOCS[path], t = d ? d.text : "";
    var dr = DRAFTS[path]; if (!dr) return t;
    if (dr.ops.some(function (o) { return o.t === "del"; })) return "";
    return applyOps(t, dr.ops.filter(function (o) { return o.t !== "b64"; }));
  }
  async function effYaml(path, force) { await doc(path, force); var t = effText(path); return (t ? Y.load(t, YOPT) : null); }
  function effB64(path) { var dr = DRAFTS[path], b = dr && dr.ops.filter(function (o) { return o.t === "b64"; }).pop(); return b ? b.b64 : null; }

  /* ---------- commits ---------- */
  function queueWrite(fn) { var job = saveChain.then(fn); saveChain = job.catch(function () {}); return job; }
  async function finalFor(path, ops, ref) {
    var d = await fetchDoc(path, ref);
    ops.forEach(function (o) {
      if (o.t === "text" && "base" in o && o.base !== d.sha && !(o.base == null && d.missing)) {
        if (d.text !== o.text) throw new Error(path + " changed on GitHub since you opened it. Reload that section, redo your change, then save.");
      }
    });
    if (ops.some(function (o) { return o.t === "del"; })) return { path: path, del: true, missing: d.missing, sha: d.sha };
    var b = ops.filter(function (o) { return o.t === "b64"; }).pop();
    if (b && b.isNew && !d.missing && b.b64 !== d.b64) throw new Error(path + " already exists on GitHub, so it wasn’t overwritten. Reload and upload again (it gets a new name).");
    if (b) return { path: path, b64: b.b64, sha: d.sha, same: b.b64 === d.b64 };
    var text = applyOps(d.text || "", ops);
    if (/\.ya?ml$/i.test(path)) { try { Y.load(text, YOPT); } catch (e) { throw new Error("The result for " + path + " isn’t valid YAML, so nothing was saved."); } }
    return { path: path, text: text, sha: d.sha, same: !d.missing && text === d.text };
  }
  function afterCommit(fin, newSha) {
    if (fin.del) DOCS[fin.path] = { text: "", b64: "", sha: null, missing: true };
    else DOCS[fin.path] = { text: fin.text != null ? fin.text : null, b64: fin.b64 != null ? fin.b64 : (fin.text != null ? utf8ToB64(fin.text) : ""), sha: newSha, missing: false };
    if (DRAFTS[fin.path]) delete DRAFTS[fin.path];
    delete PENDING[fin.path];
    if (typeof TREE !== "undefined" && TREE) {
      TREE = TREE.filter(function (t) { return t.path !== fin.path; });
      if (!fin.del) TREE.push({ path: fin.path, type: "blob", sha: newSha, size: fin.b64 != null ? Math.floor(fin.b64.length * 3 / 4) : new TextEncoder().encode(fin.text || "").length });
    }
    bump(fin.path);
  }
  // changes: [{path, ops}]. Drafts already queued for the same files are published with them.
  function commitChanges(changes, message, pageUrl) {
    var merged = {}, order = [];
    changes.forEach(function (c) {
      if (!merged[c.path]) { merged[c.path] = DRAFTS[c.path] ? DRAFTS[c.path].ops.slice() : []; order.push(c.path); }
      merged[c.path] = mergeOps(merged[c.path], c.ops);
    });
    var list = order.map(function (p) { return { path: p, ops: merged[p] }; });
    return queueWrite(async function () {
      var res = list.length === 1 ? await commitOne(list[0], message) : await commitMany(list, message);
      saveDrafts();
      if (res.commit) { startBuildWatch(); trackBuild(res.commit, pageUrl); }
      toast(res.commit ? "Saved ✓" : "No changes to save — the site already has this.", res.commit ? "ok" : "", 2600);
      return res;
    });
  }
  async function commitOne(c, message) {
    var attempt = 0;
    for (;;) {
      var fin = await finalFor(c.path, c.ops);
      if (fin.del && fin.missing) { afterCommit(fin, null); return { commit: null }; }
      if (fin.same) { afterCommit(fin, fin.sha); return { commit: null }; }
      var r;
      if (fin.del) r = await gh(RP + "/contents/" + encPath(c.path), { method: "DELETE", body: { message: message || "Admin: delete " + c.path, sha: fin.sha, branch: BRANCH } });
      else {
        var body = { message: message || "Admin: update " + c.path, content: fin.b64 != null ? fin.b64 : utf8ToB64(fin.text), branch: BRANCH };
        if (fin.sha) body.sha = fin.sha;
        r = await gh(RP + "/contents/" + encPath(c.path), { method: "PUT", body: body });
      }
      if (r.ok) { afterCommit(fin, fin.del ? null : r.data.content.sha); return { commit: r.data.commit && r.data.commit.sha }; }
      if ((r.status === 409 || r.status === 422) && attempt++ < 1) continue; // changed underneath: rebuild from the newest copy once
      throw new Error(apiErr(r));
    }
  }
  async function commitMany(list, message) {
    for (var attempt = 0; ; attempt++) {
      var ref = await gh(RP + "/git/ref/heads/" + BRANCH); if (!ref.ok) throw new Error(apiErr(ref));
      var head = ref.data.object.sha;
      var hc = await gh(RP + "/git/commits/" + head); if (!hc.ok) throw new Error(apiErr(hc));
      var fins = [], tree = [];
      for (var i = 0; i < list.length; i++) {
        var fin = await finalFor(list[i].path, list[i].ops, head);
        if (fin.same || (fin.del && fin.missing)) { fins.push({ fin: fin, sha: fin.sha, skip: true }); continue; }
        if (fin.del) { tree.push({ path: fin.path, mode: "100644", type: "blob", sha: null }); fins.push({ fin: fin, sha: null }); continue; }
        var bl = await gh(RP + "/git/blobs", { method: "POST", body: fin.b64 != null ? { content: fin.b64, encoding: "base64" } : { content: fin.text, encoding: "utf-8" } });
        if (!bl.ok) throw new Error(apiErr(bl));
        tree.push({ path: fin.path, mode: "100644", type: "blob", sha: bl.data.sha }); fins.push({ fin: fin, sha: bl.data.sha });
      }
      if (!tree.length) { fins.forEach(function (f) { afterCommit(f.fin, f.sha); }); return { commit: null }; }
      var nt = await gh(RP + "/git/trees", { method: "POST", body: { base_tree: hc.data.tree.sha, tree: tree } }); if (!nt.ok) throw new Error(apiErr(nt));
      var nc = await gh(RP + "/git/commits", { method: "POST", body: { message: message || "Admin: publish " + tree.length + " changes", tree: nt.data.sha, parents: [head] } }); if (!nc.ok) throw new Error(apiErr(nc));
      var up = await gh(RP + "/git/refs/heads/" + BRANCH, { method: "PATCH", body: { sha: nc.data.sha, force: false } });
      if (up.ok) { fins.forEach(function (f) { afterCommit(f.fin, f.sha); }); return { commit: nc.data.sha }; }
      if (up.status === 422 && attempt < 1) continue; // someone saved in between (not a fast-forward): start again from the new head
      if (up.status === 422) throw new Error("The site changed on GitHub while publishing. Nothing was changed; press Publish again.");
      throw new Error(apiErr(up));
    }
  }

  /* ---------- build progress after each save ---------- */
  var buildTrack = null, buildPollT = null, buildTick = null;
  function pubBar() {
    var b = $("pubbar");
    if (!b) { b = el("div", { class: "cp-pub", id: "pubbar", role: "status" }); $("banner").parentNode.insertBefore(b, $("banner")); }
    return b;
  }
  function renderPub(state, text, link, retry) {
    var b = pubBar(); b.textContent = ""; b.hidden = false; b.className = "cp-pub " + state;
    var row = el("div", { class: "cp-pub-row" }, [el("span", { class: "cp-pub-text", id: "pubText", text: text })]);
    if (link) row.appendChild(el("a", { class: "cp-btn small", href: link, target: "_blank", rel: "noopener", id: "pubOpen" }, ["Open page"]));
    if (retry) row.appendChild(el("button", { type: "button", class: "cp-btn small", id: "rebuildBtn", onclick: rebuildSite }, ["Retry build"]));
    row.appendChild(el("button", { type: "button", class: "cp-ico cp-pub-x", "aria-label": "Hide", onclick: function () { b.hidden = true; } }, ["✕"]));
    b.appendChild(row);
    if (state === "busy") b.appendChild(el("div", { class: "cp-pub-bar" }, [el("i", { id: "pubFill" })]));
  }
  function trackBuild(sha, pageUrl) {
    buildTrack = { sha: sha, t0: Date.now(), url: pageUrl || "/" };
    renderPub("busy", "Publishing… (usually 30–60 s)");
    clearInterval(buildTick);
    buildTick = setInterval(function () {
      if (!buildTrack) { clearInterval(buildTick); return; }
      var s = Math.round((Date.now() - buildTrack.t0) / 1000), f = $("pubFill"), t = $("pubText");
      if (f) f.style.setProperty("--p", Math.min(95, s * 1.6) + "%");
      if (t) t.textContent = "Publishing… " + s + " s (usually 30–60 s)";
    }, 1000);
    clearTimeout(buildPollT); buildPollT = setTimeout(pollBuild, 3000);
  }
  async function getBuildsFor(sha) {
    var r = await gh(RP + "/pages/builds/latest");
    if (!r.ok) r = await gh(RP + "/pages/builds/latest", { auth: false });
    if (r.ok && r.data && r.data.commit === sha) return { mine: r.data, list: [r.data] };
    var l = await gh(RP + "/pages/builds?per_page=10");
    if (!l.ok) l = await gh(RP + "/pages/builds?per_page=10", { auth: false });
    var list = l.ok && Array.isArray(l.data) ? l.data : [];
    return { mine: list.filter(function (b) { return b.commit === sha; })[0], list: list };
  }
  function buildErr(b) { return (b && b.error && b.error.message) || "GitHub didn’t give a reason."; }
  async function pollBuild() {
    var bt = buildTrack; if (!bt) return;
    var got = null; try { got = await getBuildsFor(bt.sha); } catch (e) {}
    if (bt !== buildTrack) return;
    var mine = got && got.mine;
    if (mine && mine.status === "built") {
      buildTrack = null; clearInterval(buildTick);
      renderPub("ok", "Live ✓ — published" + (mine.duration ? " in " + Math.round(mine.duration / 1000) + " s" : "") + ". If the page still looks old, press Ctrl+Shift+R.", bustUrl(bt.url));
      if (!$("vPanel").hidden && !document.querySelector('[data-pane="status"]').hidden) loadStatus();
      return;
    }
    if (mine && mine.status === "errored") {
      var newer = got.list.filter(function (b) { return b !== mine && new Date(b.created_at) > new Date(mine.created_at); })[0];
      if (newer && newer.status !== "errored") { bt.sha = newer.commit; }
      else {
        buildTrack = null; clearInterval(buildTick);
        renderPub("err", "The site build failed: " + buildErr(mine) + " Your change is saved, but the live site still shows the previous version. This often happens after several quick saves in a row (use Drafts → Publish all to make one change). Press Retry build.", null, true);
        return;
      }
    }
    if (Date.now() - bt.t0 > 8 * 60 * 1000) { buildTrack = null; clearInterval(buildTick); renderPub("err", "Publishing is taking longer than usual. Check Status in a few minutes."); return; }
    buildPollT = setTimeout(pollBuild, 5000);
  }
  // A commit without file changes makes GitHub Pages build the site again.
  function rebuildSite() {
    var btn = $("rebuildBtn"); if (btn) btn.disabled = true;
    queueWrite(async function () {
      var ref = await gh(RP + "/git/ref/heads/" + BRANCH); if (!ref.ok) throw new Error(apiErr(ref));
      var head = ref.data.object.sha, c = await gh(RP + "/git/commits/" + head); if (!c.ok) throw new Error(apiErr(c));
      var nc = await gh(RP + "/git/commits", { method: "POST", body: { message: "Admin: rebuild the site", tree: c.data.tree.sha, parents: [head] } }); if (!nc.ok) throw new Error(apiErr(nc));
      var u = await gh(RP + "/git/refs/heads/" + BRANCH, { method: "PATCH", body: { sha: nc.data.sha, force: false } }); if (!u.ok) throw new Error(apiErr(u));
      startBuildWatch(); trackBuild(nc.data.sha, "/");
    }).catch(function (e) { renderPub("err", "Couldn’t start a new build: " + e.message, null, true); });
  }

  /* ---------- shell: sidebar, sections, dirty guard, Ctrl+S ---------- */
  var loaded = {}, dirtyMap = {}, SECS = {};
  function banner(text, warn) { var b = $("banner"); b.textContent = text || ""; b.hidden = !text; b.className = "cp-banner" + (warn ? " warn" : ""); }
  function openPanel(note) {
    show("vPanel"); banner(note || ""); $("menuBtn").hidden = false; updateDraftUI();
    selectTab(location.hash.slice(1) || "dash");
  }
  function selectTab(name) {
    if (!document.querySelector('[data-pane="' + name + '"]') || !LOADERS[name]) name = "dash";
    [].forEach.call(document.querySelectorAll(".cp-tabs button"), function (b) { b.setAttribute("aria-selected", b.getAttribute("data-tab") === name ? "true" : "false"); });
    [].forEach.call(document.querySelectorAll(".cp-pane"), function (p) { p.hidden = p.getAttribute("data-pane") !== name; });
    if (history.replaceState) history.replaceState(null, "", "#" + name);
    document.body.classList.remove("cp-side-open"); $("menuBtn").setAttribute("aria-expanded", "false");
    var s = SECS[name];
    if (!loaded[name]) { loaded[name] = true; LOADERS[name](); }
    else if (s && !s.dirty && s.stale()) s.reload();
    else if (name === "status" || name === "dash" || name === "drafts" || name === "media") LOADERS[name]();
    var pane = document.querySelector('[data-pane="' + name + '"]'); if (pane && window.scrollY > 200) window.scrollTo(0, 0);
  }
  [].forEach.call(document.querySelectorAll(".cp-tabs button"), function (b) { b.addEventListener("click", function () { selectTab(b.getAttribute("data-tab")); }); });
  $("menuBtn").addEventListener("click", function () { var on = !document.body.classList.contains("cp-side-open"); document.body.classList.toggle("cp-side-open", on); $("menuBtn").setAttribute("aria-expanded", on ? "true" : "false"); });
  $("draftPill").addEventListener("click", function () { selectTab("drafts"); });

  function setState(id, text, cls) { var s = $(id); if (!s) return; s.textContent = text; s.className = "cp-state" + (cls ? " " + cls : ""); }
  function markDirty(sec, on) {
    dirtyMap[sec] = on;
    var tab = document.querySelector('.cp-tabs [data-tab="' + sec + '"]');
    if (tab) { var d = tab.querySelector(".dot"); if (on && !d) tab.appendChild(el("span", { class: "dot", "aria-label": "unsaved" })); if (!on && d) d.remove(); }
  }
  function anyDirty() { for (var k in dirtyMap) if (dirtyMap[k]) return true; return false; }
  window.addEventListener("beforeunload", function (e) { if (token && (anyDirty() || draftCount())) { e.preventDefault(); e.returnValue = ""; } });
  document.addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "s" || e.key === "S")) {
      if ($("vPanel").hidden) return;
      e.preventDefault();
      var b = document.querySelector(".cp-pane:not([hidden]) [data-save]");
      if (b && !b.disabled) b.click();
    } else if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "") && !$("vPanel").hidden) { e.preventDefault(); $("gSearch").focus(); }
  });
  var rsT = null;
  window.addEventListener("resize", function () { clearTimeout(rsT); rsT = setTimeout(function () { [].forEach.call(document.querySelectorAll(".cp-pane:not([hidden]) textarea:not(#polBody):not(#fileBody)"), autosize); }, 120); });
  function autosize(t) { t.style.height = "auto"; t.style.height = Math.min(t.scrollHeight + 2, 600) + "px"; }

  // Savebars for sections marked data-sec in the page.
  [].forEach.call(document.querySelectorAll(".cp-savebar[data-sec]"), function (bar) {
    var n = bar.getAttribute("data-sec");
    bar.appendChild(el("span", { class: "cp-state", id: n + "State" }));
    bar.appendChild(el("button", { class: "cp-btn ghost small", type: "button", id: n + "History" }, ["History"]));
    bar.appendChild(el("button", { class: "cp-btn ghost", type: "button", id: n + "Reload" }, ["Reload"]));
    bar.appendChild(el("button", { class: "cp-btn ghost", type: "button", id: n + "Draft" }, ["Add to drafts"]));
    bar.appendChild(el("button", { class: "cp-btn", type: "button", id: n + "Save", "data-save": "" }, ["Save"]));
  });

  /* A section: o = {prefix, label, files(): [paths], load(force), changes(): [{path, ops}], validate(): "" | message, page(): url, history(): path} */
  function defineSection(name, o) {
    var P = o.prefix || name, s = { name: name, o: o, dirty: false, revs: {} };
    SECS[name] = s;
    s.setDirty = function (d) { s.dirty = d; markDirty(name, d); setState(P + "State", d ? "Unsaved changes" : "Up to date", d ? "dirty" : ""); };
    s.check = function () { var ch = []; try { ch = o.changes().filter(function (c) { return c.ops.length; }); } catch (e) {} s.setDirty(ch.length > 0); };
    s.snap = function () { s.revs = {}; o.files().forEach(function (f) { s.revs[f] = REV[f] || 0; }); };
    s.stale = function () { return o.files().some(function (f) { return (REV[f] || 0) !== s.revs[f]; }); };
    s.reload = async function (force) {
      setState(P + "State", "Loading…");
      try { await o.load(!!force); s.snap(); s.dirty = false; markDirty(name, false); setState(P + "State", "Up to date"); }
      catch (e) { setState(P + "State", e.message, "err"); loaded[name] = false; }
    };
    async function run(draft) {
      var btn = $(P + (draft ? "Draft" : "Save"));
      if (!s.dirty) { setState(P + "State", "Nothing to save"); return; }
      var err = o.validate ? o.validate() : "";
      if (err) { setState(P + "State", err, "err"); toast(err, "err"); return; }
      var ch; try { ch = o.changes().filter(function (c) { return c.ops.length; }); } catch (e) { setState(P + "State", e.message, "err"); return; }
      if (!ch.length) { s.setDirty(false); setState(P + "State", "Nothing to save"); return; }
      if (autoOn() && touchesEnglish(ch)) startTranslators(TR_LANGS); // inside the click: a first model download needs it
      btn.disabled = true;
      var sm = null;
      try { var tres = await translateChanges(ch); ch = tres.changes; sm = tres.summary; }
      catch (e) { renderTrBar(""); sm = { done: [], skipped: [{ lang: "all", why: e.message || String(e) }] }; }
      finally { btn.disabled = false; }
      var note = translationNote(sm);
      if (note) toast(note, sm && (sm.unsupported || sm.skipped.length) ? "warn" : "ok", 9000);
      if (draft) {
        ch.forEach(function (c) { stageOps(c.path, c.ops, o.label); });
        await o.load(false); s.snap(); s.dirty = false; markDirty(name, false);
        setState(P + "State", "Added to drafts. Publish them together from Drafts." + (note ? " " + note : ""), "ok");
        toast("Added to drafts (" + draftCount() + " file" + (draftCount() === 1 ? "" : "s") + " waiting). Publish all at once from Drafts.", "ok");
        return;
      }
      btn.disabled = true; setState(P + "State", "Saving…");
      try {
        var msg = ch.length === 1 ? "Admin: update " + ch[0].path : "Admin: update " + o.label.toLowerCase();
        await commitChanges(ch, msg, o.page ? o.page() : "/");
        await o.load(false); s.snap(); s.dirty = false; markDirty(name, false);
        setState(P + "State", "Saved. " + LIVE_NOTE + (note ? " " + note : ""), "ok");
      } catch (e) { setState(P + "State", e.message, "err"); toast(e.message, "err"); }
      finally { btn.disabled = false; }
    }
    $(P + "Save").addEventListener("click", function () { run(false); });
    $(P + "Draft").addEventListener("click", function () { run(true); });
    $(P + "Reload").addEventListener("click", function () { if (!s.dirty || confirm("Discard your unsaved changes?")) s.reload(true); });
    var hb = $(P + "History"); if (hb) hb.addEventListener("click", function () { openHistory(o.history ? o.history() : o.files()[0]); });
    return s;
  }
  [].forEach.call(document.querySelectorAll("[data-history]"), function (b) { b.addEventListener("click", function () { openHistory(b.getAttribute("data-history")); }); });

  /* ---------- form building blocks ---------- */
  var uid = 0;
  function fieldRow(label, input, help, wide) {
    var id = input.id || ("u" + (++uid)); input.id = id;
    var w = el("div", { class: "cp-field" + (wide ? " wide" : "") }, [el("label", { class: "cp-label", for: id, text: label }), input]);
    if (help) w.appendChild(el("span", { class: "cp-help-text", text: help }));
    return w;
  }
  function textInput(val, onInput, attrs) {
    var long = attrs && attrs.multiline;
    var i = long ? el("textarea", Object.assign({ rows: 2 }, attrs, { multiline: null })) : el("input", Object.assign({ type: "text" }, attrs || {}));
    i.value = val == null ? "" : String(val);
    i.addEventListener("input", function () { if (long) autosize(i); onInput(i.value); });
    if (long) requestAnimationFrame(function () { autosize(i); });
    return i;
  }
  function checkInput(val, onChange, label) {
    var i = el("input", { type: "checkbox" }); i.checked = !!val;
    i.addEventListener("change", function () { onChange(i.checked); });
    return el("label", { class: "cp-switch" }, [i, el("span", { text: label || "" })]);
  }
  function selectInput(val, options, onChange, attrs) {
    var s = el("select", attrs || {});
    options.forEach(function (o) { s.appendChild(el("option", { value: o[0], text: o[1] })); });
    s.value = val; s.addEventListener("change", function () { onChange(s.value); });
    return s;
  }
  function moveBtns(arr, i, rerender, onChange) {
    return [
      el("button", { type: "button", class: "cp-ico", title: "Move up", "aria-label": "Move up", disabled: i === 0, onclick: function () { var t = arr[i - 1]; arr[i - 1] = arr[i]; arr[i] = t; rerender(); onChange(); } }, ["↑"]),
      el("button", { type: "button", class: "cp-ico", title: "Move down", "aria-label": "Move down", disabled: i === arr.length - 1, onclick: function () { var t = arr[i + 1]; arr[i + 1] = arr[i]; arr[i] = t; rerender(); onChange(); } }, ["↓"]),
      el("button", { type: "button", class: "cp-ico", title: "Remove", "aria-label": "Remove", onclick: function () { arr.splice(i, 1); rerender(); onChange(); } }, ["✕"])
    ];
  }
  // Editable list of strings (reuses the classic list editor).
  function stringList(arr, onChange, label) { return listEditor(arr.map(String), function (a) { arr.length = 0; a.forEach(function (x) { arr.push(x); }); onChange(); }, { label: label }); }

  /* ---------- languages ---------- */
  var LANGS = [];
  async function loadLangs(force) { var l = await effYaml("_data/languages.yml", force); LANGS = Array.isArray(l) ? l : []; return LANGS; }
  function fillLangSelect(sel, keep) {
    var cur = keep || sel.value || "en"; sel.textContent = "";
    LANGS.forEach(function (l) { sel.appendChild(el("option", { value: l.code, text: l.name + " (" + l.code + ")" + (l.enabled === false ? " — off" : "") })); });
    sel.value = LANGS.some(function (l) { return l.code === cur; }) ? cur : "en";
  }
  function langDir(code) { var l = LANGS.filter(function (x) { return x.code === code; })[0]; return l && l.dir === "rtl" ? "rtl" : null; }
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

  /* =====================================================================
     Classic sections: Site settings, Policies, Translations, Other files
     ===================================================================== */
  var TREE = null;
  async function getTree(force) {
    if (TREE && !force) return TREE;
    var r = await gh(RP + "/git/trees/" + BRANCH + "?recursive=1");
    if (!r.ok) throw new Error(apiErr(r));
    TREE = r.data.tree.filter(function (t) { return t.type === "blob"; });
    return TREE;
  }
  function treePaths(filter) {
    var set = {};
    (TREE || []).forEach(function (t) { set[t.path] = 1; });
    Object.keys(DRAFTS).forEach(function (p) { if (DRAFTS[p].ops.some(function (o) { return o.t === "del"; })) delete set[p]; else set[p] = 1; });
    return Object.keys(set).filter(filter || function () { return true; }).sort();
  }

  /* ---------- Site settings ---------- */
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
    extension_version: { label: "Extension version shown on the homepage", placeholder: "Empty = hidden" },
    policies_updated: { label: "Policies updated (date)", type: "date" },
    free_features: { label: "Free plan features" },
    pro_features: { label: "Pro plan features" }
  };
  var site = { orig: null, cur: null };
  function cleanSite(o) {
    var c = clone(o);
    Object.keys(c).forEach(function (k) { if (Array.isArray(c[k])) c[k] = c[k].map(function (s) { return typeof s === "string" ? s.trim() : s; }).filter(function (s) { return s !== ""; }); else if (typeof c[k] === "string" && k !== "price_monthly" && k !== "price_yearly") c[k] = c[k].trim(); });
    return c;
  }
  function priceErr(v, label) { var s = v == null ? "" : String(v).trim(); return s === "" || /^tbd$/i.test(s) || /^\d+(\.\d{1,2})?$/.test(s) ? "" : label + " must be a number such as 4.99, or TBD."; }
  function yamlKeyChanges(path, cur, orig) {
    var keys = {}, n = 0;
    Object.keys(cur).forEach(function (k) { if (!deepEq(cur[k], orig[k])) { keys[k] = cur[k]; n++; } });
    return n ? [{ path: path, ops: [{ t: "yset", keys: keys }] }] : [];
  }
  var secSite = defineSection("site", {
    label: "Site settings", files: function () { return [SITE_PATH]; }, page: function () { return "/pricing.html"; },
    load: async function (force) { site.orig = (await effYaml(SITE_PATH, force)) || {}; site.cur = clone(site.orig); renderSite(); },
    validate: function () {
      var d = cleanSite(site.cur);
      if (d.support_email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(d.support_email)) return "The support email doesn’t look right.";
      if (["chrome_store_url"].some(function (k) { return d[k] && !/^https:\/\//.test(d[k]); })) return "Store links must start with https://";
      return priceErr(d.price_monthly, "The monthly price") || priceErr(d.price_yearly, "The yearly price") || (d.product_name ? "" : "The product name can’t be empty.") || "";
    },
    changes: function () { return yamlKeyChanges(SITE_PATH, cleanSite(site.cur), site.orig); }
  });
  function renderSite() {
    var form = $("siteForm"); form.textContent = "";
    Object.keys(site.cur).forEach(function (k) {
      if (k === "edge_store_url") return; /* Chrome Web Store only */
      form.appendChild(fieldFor(k, site.cur[k], SITE_META[k], function (v) { site.cur[k] = v; secSite.check(); }));
    });
  }

  /* ---------- Policies ---------- */
  var pol = { name: "privacy", sha: null, fmText: "", fm: {}, fmCur: {}, body: "", bodyCur: "" };
  function splitFm(text) {
    var t = text.replace(/\r\n/g, "\n"), m = /^---\n([\s\S]*?)\n---\n?/.exec(t);
    if (!m) return { fmText: "", body: t };
    return { fmText: m[1] + "\n", body: t.slice(m[0].length) };
  }
  function polPath() { return "pages/" + pol.name + ".md"; }
  function polText() {
    var body = pol.bodyCur.replace(/\r\n/g, "\n"); if (!/\n$/.test(body)) body += "\n";
    var fmText = deepEq(pol.fmCur, pol.fm) ? pol.fmText : writeYamlKeepingComments(pol.fmText, pol.fmCur);
    return (pol.fmText || !deepEq(pol.fmCur, {}) ? "---\n" + fmText + "---\n" : "") + body;
  }
  var secPol = defineSection("policies", {
    prefix: "pol", label: "Policies", files: function () { return [polPath()]; }, page: function () { return "/" + pol.name + ".html"; },
    load: async function (force) {
      if (!site.orig) { try { site.orig = (await effYaml(SITE_PATH)) || {}; site.cur = site.cur || clone(site.orig); } catch (e) {} }
      [].forEach.call(document.querySelectorAll("#polPick button"), function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-pol") === pol.name ? "true" : "false"); });
      $("polPath").textContent = polPath();
      var d = await doc(polPath(), force), sp = splitFm(effText(polPath()));
      pol.sha = d.sha; pol.fmText = sp.fmText; pol.fm = Y.load(sp.fmText, YOPT) || {}; pol.fmCur = clone(pol.fm); pol.body = sp.body; pol.bodyCur = sp.body;
      var form = $("polFm"); form.textContent = "";
      Object.keys(pol.fmCur).forEach(function (k) {
        var meta = { title: { label: "Title" }, description: { label: "Description (search engines)", wide: true, type: "textarea" }, permalink: { label: "Address (permalink)", help: "Changing this breaks existing links." } }[k];
        form.appendChild(fieldFor(k, pol.fmCur[k], meta, function (v) { pol.fmCur[k] = v; secPol.check(); }));
      });
      $("polBody").value = pol.bodyCur; preview();
    },
    validate: function () { return pol.fmCur.permalink != null && !/^\/[\w\-./]*$/.test(String(pol.fmCur.permalink)) ? "The address must start with / and use only letters, numbers, - . and /." : (unsafeHtml(pol.bodyCur) ? "Scripts aren’t allowed in policy text." : ""); },
    changes: function () {
      if (pol.bodyCur === pol.body && deepEq(pol.fmCur, pol.fm)) return [];
      return [{ path: polPath(), ops: [{ t: "text", text: polText(), base: pol.sha }] }];
    }
  });
  var prevTimer = null;
  $("polBody").addEventListener("input", function () { pol.bodyCur = $("polBody").value; secPol.check(); clearTimeout(prevTimer); prevTimer = setTimeout(preview, 150); });
  [].forEach.call(document.querySelectorAll("#polPick button"), function (b) {
    b.addEventListener("click", function () {
      var n = b.getAttribute("data-pol"); if (n === pol.name) return;
      if (secPol.dirty && !confirm("Discard your unsaved changes to this policy?")) return;
      pol.name = n; secPol.reload(false);
    });
  });
  function preview() { var h = "<h1>" + inline(liquid(String(pol.fmCur.title || ""))) + "</h1>" + md(pol.bodyCur); $("polPrev").innerHTML = h; }

  /* ---------- Translations ---------- */
  var tr = { code: "", sha: null, data: null, cur: null, en: null, auto: {}, autoAdd: {}, autoDel: {} }, TR_LANG_KEY = "acs_admin_i18n_lang";
  function flatten(o, pre, out) {
    out = out || [];
    if (Array.isArray(o)) o.forEach(function (v, i) { flatten(v, pre.concat([i]), out); });
    else if (o && typeof o === "object") Object.keys(o).forEach(function (k) { flatten(o[k], pre.concat([k]), out); });
    else out.push({ path: pre, value: o });
    return out;
  }
  function getAt(o, p) { for (var i = 0; i < p.length; i++) { if (o == null) return undefined; o = o[p[i]]; } return o; }
  function setAt(o, p, v) { for (var i = 0; i < p.length - 1; i++) o = o[p[i]]; o[p[p.length - 1]] = v; }
  function i18nPath(c) { return "_data/i18n/" + c + ".yml"; }
  var secI18n = defineSection("i18n", {
    label: "Translations", files: function () { return tr.code ? [i18nPath(tr.code), i18nPath("en")] : []; },
    page: function () { return tr.code === "en" ? "/" : "/" + tr.code + "/"; }, history: function () { return i18nPath(tr.code); },
    load: async function (force) {
      await loadLangs(force);
      var sel = $("langPick");
      if (!tr.code) { var saved = null; try { saved = localStorage.getItem(TR_LANG_KEY); } catch (e) {} tr.code = LANGS.some(function (l) { return l.code === saved; }) ? saved : "en"; }
      if (!LANGS.some(function (l) { return l.code === tr.code; })) tr.code = "en";
      try { localStorage.setItem(TR_LANG_KEY, tr.code); } catch (e) {}
      fillLangSelect(sel, tr.code);
      tr.en = (await effYaml(i18nPath("en"), force)) || {};
      var d = await doc(i18nPath(tr.code), force);
      tr.sha = d.sha; tr.data = (effText(i18nPath(tr.code)) ? Y.load(effText(i18nPath(tr.code)), YOPT) : null) || {}; tr.cur = clone(tr.data);
      $("i18nPath").textContent = i18nPath(tr.code);
      var lg = LANGS.filter(function (l) { return l.code === tr.code; })[0] || { name: tr.code };
      var ed = $("i18nEditing"); ed.textContent = "Editing: " + lg.name + " (" + tr.code + ") — shows on " + (tr.code === "en" ? "the English pages (/ and /pricing.html)" : "/" + tr.code + "/ pages") + (lg.enabled === false ? " (this language is switched off)" : "");
      ed.setAttribute("lang", lg.hreflang || tr.code); if (lg.dir) ed.setAttribute("dir", lg.dir); else ed.removeAttribute("dir");
      tr.auto = (await readAuto())[tr.code] || []; tr.autoAdd = {}; tr.autoDel = {};
      renderI18n();
    },
    validate: function () {
      var bad = flatten(tr.cur, []).filter(function (f) { return typeof f.value === "string" && unsafeHtml(f.value); })[0];
      return bad ? "“" + bad.path.join(".") + "” contains a script or event handler, which isn’t allowed." : "";
    },
    changes: function () {
      var sets = flatten(tr.cur, []).filter(function (f) { return getAt(tr.data, f.path) !== f.value; }).map(function (f) { return [f.path, f.value]; });
      var out = sets.length ? [{ path: i18nPath(tr.code), ops: [{ t: "ypath", sets: sets }] }] : [];
      // Keys filled by "Translate now" stay marked auto; every other edited key counts as a hand edit (handled when saving).
      if (out[0] && tr.code !== "en") out[0].fromAutoKeys = Object.keys(tr.autoAdd);
      return out;
    }
  });
  function renderI18n() {
    var box = $("i18nForm"); box.textContent = "";
    var lang = LANGS.filter(function (l) { return l.code === tr.code; })[0] || {};
    var rtl = lang.dir === "rtl", group = null;
    flatten(tr.cur, []).forEach(function (f) {
      var top = f.path[0];
      if (top !== group) { group = top; box.appendChild(el("h3", { text: top })); }
      var key = f.path.join("."), enVal = getAt(tr.en, f.path);
      var ta = el("textarea", { rows: 1, lang: lang.hreflang || tr.code, dir: rtl ? "rtl" : null, "aria-label": key });
      ta.value = f.value == null ? "" : String(f.value);
      var isAuto = tr.code !== "en" && tr.auto.indexOf(key) > -1;
      var keyCell = el("div", { class: "cp-tr-key" }, [el("span", { text: key })]);
      var badge = el("span", { class: "cp-auto", title: "Translated automatically — check it reads well", text: "auto", hidden: !isAuto }); keyCell.appendChild(badge);
      if (typeof f.value === "string" && typeof enVal === "string" && /[A-Za-z]{2}/.test(enVal)) keyCell.appendChild(el("button", { type: "button", class: "cp-link cp-trnow", "data-trnow": key, onclick: function () { translateNow(f.path, ta, badge); } }, [tr.code === "en" ? "Translate now (all languages)" : "Translate now"]));
      var row = el("div", { class: "cp-tr-row", "data-key": key, "data-k": (key + " " + ta.value + " " + (enVal || "")).toLowerCase() }, [
        keyCell,
        el("div", { class: "cp-tr-en", lang: "en", text: enVal == null ? "—" : String(enVal) }),
        ta
      ]);
      ta.addEventListener("input", function () {
        var v = ta.value; if (typeof f.value === "number" && /^\d+$/.test(v)) v = Number(v);
        setAt(tr.cur, f.path, v); autosize(ta);
        if (tr.code !== "en") { delete tr.autoAdd[key]; if (tr.auto.indexOf(key) > -1) tr.autoDel[key] = 1; badge.hidden = true; }
        row.classList.toggle("changed", getAt(tr.data, f.path) !== v);
        secI18n.check();
      });
      box.appendChild(row);
    });
    requestAnimationFrame(function () { [].forEach.call(box.querySelectorAll("textarea"), autosize); });
    applyFilter();
  }
  function applyFilter() {
    var q = $("i18nFilter").value.trim().toLowerCase();
    [].forEach.call($("i18nForm").children, function (c) { if (c.classList.contains("cp-tr-row")) c.hidden = q && c.getAttribute("data-k").indexOf(q) < 0 && c.getAttribute("data-key").toLowerCase() !== q; });
    [].forEach.call($("i18nForm").querySelectorAll("h3"), function (h) { var n = h.nextElementSibling, any = false; while (n && n.tagName !== "H3") { if (!n.hidden) any = true; n = n.nextElementSibling; } h.hidden = !any; });
  }
  $("i18nFilter").addEventListener("input", applyFilter);
  // "Translate now": in another language, fills this key from English (unsaved, marked auto).
  // In English, translates this key into every language except ones edited by hand, and adds them to Drafts.
  function translateNow(path, ta, badge) {
    var key = path.join("."), enVal = getAt(tr.en, path);
    if (!trSupported()) { toast("Automatic translation needs Google Chrome 138 or newer on a computer.", "warn", 7000); return; }
    if (tr.code !== "en") {
      startTranslators([tr.code]);
      translateText(tr.code, getAt(tr.cur, path) === enVal || tr.code === "en" ? enVal : enVal, function (why) { toast("Couldn’t translate " + key + ": " + why + ". Nothing changed.", "warn"); }).then(function (v) {
        if (v == null) return;
        setAt(tr.cur, path, v); ta.value = v; autosize(ta);
        tr.autoAdd[key] = 1; delete tr.autoDel[key]; badge.hidden = false;
        ta.closest(".cp-tr-row").classList.toggle("changed", getAt(tr.data, path) !== v); secI18n.check();
      }).catch(function (e) { toast("Couldn’t translate: " + (e.message || e), "err"); });
      return;
    }
    startTranslators(TR_LANGS);
    (async function () {
      var auto = await readAuto(), staged = [], kept = [], failed = [];
      for (var i = 0; i < TR_LANGS.length; i++) {
        var L = TR_LANGS[i], cur = getAt((await effYaml(i18nPath(L))) || {}, path), marks = auto[L] || [];
        var hand = ((auto.hand || {})[L] || []).some(function (k) { return k === key || key.indexOf(k + ".") === 0; });
        if (hand) { kept.push(L); continue; }
        try {
          var v = await translateText(L, enVal, function (why) { failed.push(L + " (" + why + ")"); });
          if (v == null || v === cur) continue;
          stageOps(i18nPath(L), [{ t: "ypath", sets: [[path, v]] }], "Translations");
          var k = {}; k[L] = (marks.indexOf(key) < 0 ? marks.concat([key]) : marks).slice().sort(); stageOps(AUTO_PATH, [{ t: "yset", keys: k }], "Translations"); auto[L] = k[L];
          staged.push(L);
        } catch (e) { failed.push(L + " (" + (e.message || e) + ")"); }
      }
      toast((staged.length ? "Added " + staged.length + " translation" + (staged.length === 1 ? "" : "s") + " of " + key + " to Drafts." : "No translations changed.") + (kept.length ? " Kept hand-edited: " + kept.join(", ") + "." : "") + (failed.length ? " Skipped: " + failed.join(", ") + "." : ""), failed.length ? "warn" : "ok", 9000);
    })();
  }
  var lastLang = "";
  $("langPick").addEventListener("focus", function () { lastLang = $("langPick").value; });
  $("langPick").addEventListener("change", function () {
    var c = $("langPick").value;
    if (secI18n.dirty && !confirm("Discard your unsaved translation changes?")) { $("langPick").value = tr.code; return; }
    tr.code = c; try { localStorage.setItem(TR_LANG_KEY, c); } catch (e) {} secI18n.reload(false);
  });
  // Open Translations at a language with the filter set (used by reports and search).
  async function gotoTranslation(code, key) {
    if (SECS.i18n.dirty && tr.code !== code && !confirm("Discard your unsaved translation changes?")) return;
    tr.code = code; try { localStorage.setItem(TR_LANG_KEY, code); } catch (e) {} $("i18nFilter").value = key || "";
    if (!loaded.i18n) { loaded.i18n = true; selectTab("i18n"); await secI18n.reload(false); }
    else { selectTab("i18n"); if (tr.code !== $("langPick").value || secI18n.stale() || !tr.cur) await secI18n.reload(false); }
    $("langPick").value = code; applyFilter();
    var row = key && document.querySelector('.cp-tr-row[data-key="' + key.replace(/"/g, "") + '"] textarea'); if (row) { row.focus(); row.scrollIntoView({ block: "center" }); }
  }

  /* ---------- Other files (raw editor, the escape hatch) ---------- */
  var file = { path: "", sha: null, text: "" };
  var TEXT_EXT = /\.(html?|md|markdown|ya?ml|css|js|json|txt|xml|svg)$/i;
  var secFiles = defineSection("files", {
    prefix: "file", label: "Other files", files: function () { return file.path ? [file.path] : []; },
    page: function () { return "/"; }, history: function () { return file.path; },
    load: async function (force) {
      if (!file.path) { $("fileBody").value = ""; return; }
      var d = await doc(file.path, force); file.sha = d.sha; file.text = effText(file.path); $("fileBody").value = file.text;
    },
    validate: function () {
      var txt = $("fileBody").value;
      if (/\.ya?ml$/i.test(file.path)) { try { Y.load(txt.replace(/^---\n|\n---\n?$/g, ""), YOPT); } catch (e) { return "This YAML has an error, so it wasn’t saved: " + e.reason; } }
      if (/\.json$/i.test(file.path)) { try { JSON.parse(txt); } catch (e) { return "This JSON has an error, so it wasn’t saved."; } }
      if (/^control\//.test(file.path)) return "Files of the admin panel can’t be edited here.";
      return "";
    },
    changes: function () { var t = $("fileBody").value; return file.path && t !== file.text ? [{ path: file.path, ops: [{ t: "text", text: t, base: file.sha }] }] : []; }
  });
  async function loadFilesTab() {
    var sel = $("filePick"); setState("fileState", "Loading…");
    try { await getTree(); } catch (e) { setState("fileState", e.message, "err"); loaded.files = false; return; }
    sel.textContent = ""; sel.appendChild(el("option", { value: "", text: "Choose a file…" }));
    treePaths(function (p) { return TEXT_EXT.test(p) && !/^control\//.test(p); }).forEach(function (p) { sel.appendChild(el("option", { value: p, text: p })); });
    if (file.path) sel.value = file.path;
    setState("fileState", "");
  }
  $("filePick").addEventListener("change", function () {
    var p = $("filePick").value;
    if (secFiles.dirty && !confirm("Discard your unsaved changes to " + file.path + "?")) { $("filePick").value = file.path; return; }
    file.path = p; if (!p) { $("fileBody").value = ""; secFiles.setDirty(false); return; }
    secFiles.reload(false);
  });
  $("fileBody").addEventListener("input", function () { if (file.path) secFiles.check(); });
  async function gotoFile(path) {
    if (secFiles.dirty && file.path !== path && !confirm("Discard your unsaved changes to " + file.path + "?")) return;
    file.path = path; selectTab("files"); if (!TREE) await loadFilesTab(); $("filePick").value = path; await secFiles.reload(false);
  }

  /* =====================================================================
     Automatic translation with Chrome's on-device Translator API (Chrome 138+ on a computer).
     Only English strings that changed are translated; placeholders, Liquid, HTML, URLs, emails,
     prices and product names are masked first and must all come back, or that language keeps
     its old value and is listed as skipped. Results go into the same commit as the English edit.
     Auto-translated keys are listed in _data/i18n_auto.yml so the Translations tab can badge them.
     ===================================================================== */
  var TR_LANGS = ["es", "pt", "fr", "de", "hi", "ru", "ar", "zh", "ja"];
  var AUTO_PATH = "_data/i18n_auto.yml", AUTO_KEY = "acs_admin_autotr";
  var META_KEYS = ["tagline", "description", "pro_status", "free_features", "pro_features"];
  var TERMS = ["AI Chat Saver", "Chrome Web Store", "Google Chrome", "Chrome", "Freemius", "PayPal", "Markdown", "PDF", "DOCX", "HTML", "JSON", "TXT", "PNG", "JPG", "Pro", "Free"];
  var AI_NAMES = [];
  function autoOn() { try { return localStorage.getItem(AUTO_KEY) !== "off"; } catch (e) { return true; } }
  (function () {
    var cb = $("autoTr"); if (!cb) return;
    cb.checked = autoOn();
    cb.addEventListener("change", function () { try { localStorage.setItem(AUTO_KEY, cb.checked ? "on" : "off"); } catch (e) {} toast(cb.checked ? "Auto-translate is on: English edits are translated into the other languages when you save." : "Auto-translate is off: other languages show your new English text until you translate them.", "", 4500); });
  })();
  function trSupported() { return !!(self.Translator && typeof self.Translator.create === "function"); }
  var translators = {}, trProg = {};
  // Must be called synchronously inside the click (a model download needs a user gesture).
  // A model download that makes no progress for STALL ms (or takes longer than MAXDL ms) is given up for this save,
  // so saving never hangs; the English is saved and the language is listed as skipped.
  function stallMs() { return self.__acsTrStallMs || 25000; }
  function startTranslators(codes) {
    if (!trSupported()) return;
    codes.forEach(function (c) {
      if (translators[c]) return;
      var p, last = Date.now();
      try {
        p = self.Translator.create({ sourceLanguage: "en", targetLanguage: c, monitor: function (m) { m.addEventListener("downloadprogress", function (e) { last = Date.now(); trProg[c] = e.loaded; renderTrBar("Downloading the translation model (first use only)… " + Math.round(avgProgress() * 100) + "%"); }); } });
      } catch (e) { p = Promise.reject(e); }
      var started = Date.now();
      var guard = new Promise(function (res) {
        var t = setInterval(function () {
          if (Date.now() - last > stallMs() || Date.now() - started > Math.max(stallMs() * 6, 150000)) { clearInterval(t); res({ error: "the translation model didn’t download (check your connection, then save again)", stalled: true }); }
        }, 500);
        Promise.resolve(p).then(function () { clearInterval(t); }, function () { clearInterval(t); });
      });
      translators[c] = Promise.race([Promise.resolve(p), guard]).then(function (r) { if (r && r.error) delete translators[c]; return r; }, function (e) { delete translators[c]; return { error: (e && e.message) || String(e) }; });
    });
  }
  function timeout(pr, ms, msg) { return Promise.race([pr, new Promise(function (_, rej) { setTimeout(function () { rej(new Error(msg)); }, ms); })]); }
  function avgProgress() { var k = Object.keys(trProg); if (!k.length) return 0; return k.reduce(function (a, c) { return a + (trProg[c] || 0); }, 0) / k.length; }
  function renderTrBar(text, done) {
    var b = $("trbar");
    if (!b) { b = el("div", { class: "cp-pub busy", id: "trbar", role: "status" }); $("banner").parentNode.insertBefore(b, $("banner")); }
    b.hidden = !text; b.textContent = text || ""; b.className = "cp-pub " + (done ? "ok" : "busy");
  }
  function escRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
  function maskRe() {
    var terms = TERMS.concat(AI_NAMES).filter(Boolean).sort(function (a, b) { return b.length - a.length; }).map(function (t) { return "(?<![\\w-])" + escRe(t) + "(?![\\w-])"; }).join("|");
    return new RegExp("<(kbd|code)\\b[^>]*>[\\s\\S]*?<\\/\\1>|<[^>]+>|\\{\\{[\\s\\S]*?\\}\\}|\\{%[\\s\\S]*?%\\}|%[a-z_]+%|https?:\\/\\/[^\\s<>\"']+|mailto:[^\\s<>\"']+|[\\w.+-]+@[\\w-]+\\.[\\w.-]+|[$€£]\\s?\\d+(?:[.,]\\d+)?|\\b\\d+(?:\\.\\d+)+\\b|[A-Z][a-z]*\\+[A-Za-z+]+|Downloads\\/AI Chat Saver" + (terms ? "|" + terms : ""), "g");
  }
  function mask(s) { var toks = []; var out = s.replace(maskRe(), function (m) { toks.push(m); return "{" + (toks.length - 1) + "}"; }); return { text: out, toks: toks }; }
  function unmask(t, toks) {
    var seen = {}, bad = false;
    var out = t.replace(/\{\s*(\d+)\s*\}/g, function (m, n) { n = +n; if (n >= toks.length || seen[n]) { bad = true; return m; } seen[n] = 1; return toks[n]; });
    if (bad || Object.keys(seen).length !== toks.length) return null;
    return out;
  }
  async function translateText(code, s, onFail) {
    if (typeof s !== "string" || !/[A-Za-z]{2}/.test(s)) return s;
    var m = mask(s);
    if (!/[A-Za-z]{2}/.test(m.text.replace(/\{\d+\}/g, ""))) return s;
    var tr = await translators[code];
    if (!tr || tr.error) throw new Error((tr && tr.error) || "no translator");
    var out = await timeout(tr.translate(m.text), self.__acsTrTimeoutMs || 30000, "translation timed out");
    var back = unmask(String(out), m.toks);
    if (back == null) { onFail("placeholders or links didn’t survive"); return null; }
    return back;
  }
  // newEn may be a string, list or object. Unchanged English leaves keep their existing translation.
  async function translateValue(code, oldEn, oldL, newEn, basePath, marks, fail) {
    var reuse = {};
    flatten(oldEn == null ? {} : oldEn, []).forEach(function (f) { var t = getAt(oldL, f.path); if (typeof f.value === "string" && typeof t === "string" && !(f.value in reuse)) reuse[f.value] = t; });
    if (typeof newEn !== "object" || newEn === null) {
      if (typeof newEn !== "string") return newEn;
      if (newEn === oldEn && typeof oldL === "string") return oldL;
      var r = await translateText(code, newEn, function (why) { fail(basePath.join("."), why); });
      if (r == null) return typeof oldL === "string" ? oldL : newEn;
      if (r !== newEn) marks.push(basePath.join("."));
      return r;
    }
    var out = clone(newEn), leaves = flatten(newEn, []);
    for (var i = 0; i < leaves.length; i++) {
      var f = leaves[i]; if (typeof f.value !== "string") continue;
      var key = basePath.concat(f.path).join(".");
      if (f.value in reuse) { setAt(out, f.path, reuse[f.value]); continue; }
      var t = await translateText(code, f.value, function (why) { fail(key, why); });
      if (t == null) { var old = getAt(oldL, f.path); setAt(out, f.path, typeof old === "string" ? old : f.value); continue; }
      setAt(out, f.path, t); if (t !== f.value) marks.push(key);
    }
    return out;
  }
  async function readAuto() { var a = (await effYaml(AUTO_PATH)) || {}; return a && typeof a === "object" ? a : {}; }
  function underAny(k, prefixes) { return prefixes.some(function (p) { return k === p || k.indexOf(p + ".") === 0; }); }
  function autoOps(changesByLang, base) {
    var keys = {}, n = 0, hand = clone(base.hand || {}), handChanged = false;
    Object.keys(changesByLang).forEach(function (L) {
      var c = changesByLang[L], h = (hand[L] || []).slice();
      var nh = h.filter(function (k) { return !underAny(k, c.handDelPrefix); });
      c.handAdd.forEach(function (k) { if (nh.indexOf(k) < 0) nh.push(k); });
      nh.sort();
      if (!deepEq(nh, h.slice().sort())) { hand[L] = nh; handChanged = true; }
    });
    if (handChanged) { Object.keys(hand).forEach(function (L) { if (!hand[L].length) delete hand[L]; }); keys.hand = hand; n++; }
    Object.keys(changesByLang).forEach(function (L) {
      var cur = (base[L] || []).slice(), c = changesByLang[L];
      cur = cur.filter(function (k) { return c.del.indexOf(k) < 0 && !c.delPrefix.some(function (p) { return k === p || k.indexOf(p + ".") === 0; }); });
      c.add.forEach(function (k) { if (cur.indexOf(k) < 0) cur.push(k); });
      cur.sort();
      if (!deepEq(cur, (base[L] || []).slice().sort())) { keys[L] = cur; n++; }
    });
    return n ? [{ path: AUTO_PATH, ops: [{ t: "yset", keys: keys }] }] : [];
  }
  function lc(o, L) { return o[L] || (o[L] = { add: [], del: [], delPrefix: [], handAdd: [], handDelPrefix: [] }); }

  /* Called by every section on Save / Add to drafts with its changes. Returns {changes, summary}. */
  async function translateChanges(ch, opts) {
    opts = opts || {};
    var enPath = i18nPath("en"), want = opts.force || autoOn();
    var enOld = (await effYaml(enPath)) || {}, deltas = [], extra = [], embedded = [], markCh = {};
    try { var a = (await effYaml("_data/ais.yml")) || {}; AI_NAMES = (a.ais || []).map(function (x) { return String(x.name || ""); }); } catch (e) {}
    ch.forEach(function (c) {
      c.ops.forEach(function (op) {
        if (c.path === enPath && op.t === "ypath") op.sets.forEach(function (s) { deltas.push({ p: s[0], o: getAt(enOld, s[0]), n: s[1] }); });
        if (c.path === SITE_PATH && op.t === "yset") Object.keys(op.keys).forEach(function (k) { if (META_KEYS.indexOf(k) > -1 && !deepEq(op.keys[k], getAt(enOld, ["meta", k]))) deltas.push({ p: ["meta", k], o: getAt(enOld, ["meta", k]), n: op.keys[k], site: true }); });
        if (op.t === "yset" && ["_data/navigation.yml", "_data/home.yml", "_data/announcement.yml", "_data/seo.yml", "_data/coupon.yml"].indexOf(c.path) > -1) embedded.push({ path: c.path, op: op });
        // hand edits in another language clear the 'auto' badge of what was edited
        var m = /^_data\/i18n\/([\w-]+)\.yml$/.exec(c.path);
        if (m && m[1] !== "en" && op.t === "ypath") op.sets.forEach(function (s) {
          var k = s[0].join(".");
          if ((c.fromAutoKeys || []).indexOf(k) > -1) lc(markCh, m[1]).add.push(k);
          else { lc(markCh, m[1]).delPrefix.push(k); lc(markCh, m[1]).handAdd.push(k); }
        });
      });
    });
    var summary = null;
    var needs = deltas.length || embedded.length;
    if (want && needs) {
      if (!trSupported()) summary = { unsupported: true };
      else {
        var langs = TR_LANGS.filter(function (L) { return LANGS.length ? LANGS.some(function (x) { return x.code === L; }) : true; });
        startTranslators(langs);
        var done = [], skipped = [], doneEmbedded = false;
        // English meta keys follow site.yml so the translations are used on the other languages.
        var siteSets = deltas.filter(function (d) { return d.site; }).map(function (d) { return [d.p, d.n]; });
        for (var li = 0; li < langs.length; li++) {
          var L = langs[li], tr0 = await translators[L];
          if (!tr0 || tr0.error) { skipped.push({ lang: L, why: "the translation model isn’t available (" + ((tr0 && tr0.error) || "unknown") + ")" }); continue; }
          renderTrBar("Translating into " + langs.length + " languages… " + (li + 1) + "/" + langs.length + " (" + L + ")");
          var fails = [], fail = function (k, why) { fails.push(k + ": " + why); };
          var Lold = (await effYaml(i18nPath(L))) || {}, sets = [], marks = [];
          for (var di = 0; di < deltas.length; di++) {
            var d = deltas[di];
            var nv = await translateValue(L, d.o, getAt(Lold, d.p), d.n, d.p, marks, fail);
            if (!deepEq(nv, getAt(Lold, d.p))) sets.push([d.p, nv]);
            lc(markCh, L).delPrefix.push(d.p.join(".")); lc(markCh, L).handDelPrefix.push(d.p.join("."));
          }
          lc(markCh, L).add = lc(markCh, L).add.concat(marks);
          if (sets.length) extra.push({ path: i18nPath(L), ops: [{ t: "ypath", sets: sets }] });
          for (var ei = 0; ei < embedded.length; ei++) await translateEmbedded(embedded[ei], L, fail);
          if (fails.length) skipped.push({ lang: L, why: fails.slice(0, 3).join("; ") + (fails.length > 3 ? " (+" + (fails.length - 3) + " more)" : "") + " — kept the old text" });
          done.push(L);
        }
        if (siteSets.length) extra.push({ path: enPath, ops: [{ t: "ypath", sets: siteSets }] });
        summary = { done: done, skipped: skipped };
        renderTrBar("");
      }
    }
    var out = ch.concat(extra);
    var base = await readAuto(); out = out.concat(autoOps(markCh, base));
    return { changes: mergeChangeList(out), summary: summary };
  }
  function mergeChangeList(list) {
    var m = {}, order = [];
    list.forEach(function (c) { if (!m[c.path]) { m[c.path] = []; order.push(c.path); } m[c.path] = mergeOps(m[c.path], c.ops); });
    return order.map(function (p) { return { path: p, ops: m[p] }; });
  }
  // Per-language texts stored inside other data files (custom nav labels, hero buttons, announcement, SEO).
  async function translateEmbedded(e, L, fail) {
    var old = (await effYaml(e.path)) || {}, k = e.op.keys;
    async function tx(s, oldEnText, oldMap, key) {
      if (!s) return undefined;
      if (s === oldEnText && oldMap && oldMap[L]) return oldMap[L];
      var r = await translateText(L, s, function (why) { fail(key, why); });
      return r == null ? (oldMap && oldMap[L]) || undefined : r;
    }
    if (e.path === "_data/navigation.yml") for (var area of ["header", "footer"]) {
      if (!Array.isArray(k[area])) continue;
      for (var i = 0; i < k[area].length; i++) {
        var it = k[area][i]; if (!it.label) continue;
        var prev = (old[area] || []).filter(function (o) { return o.label === it.label; })[0] || {};
        var v = await tx(it.label, prev.label, prev.labels, "navigation." + area + "." + i);
        if (v) { it.labels = Object.assign({}, it.labels || prev.labels || {}); it.labels[L] = v; }
      }
    }
    if (e.path === "_data/home.yml" && Array.isArray(k.hero_buttons)) for (var j = 0; j < k.hero_buttons.length; j++) {
      var b = k.hero_buttons[j], pb = (old.hero_buttons || []).filter(function (o) { return o.text === b.text; })[0] || {};
      if (b.texts && b.texts[L] && b.text === pb.text) continue; // typed by hand for this language
      var hv = await tx(b.text, pb.text, pb.texts, "hero_buttons." + j);
      if (hv) { b.texts = Object.assign({}, b.texts || {}); b.texts[L] = hv; }
    }
    if (e.path === "_data/announcement.yml") {
      if ("text" in k && k.text !== old.text && k.text) { var av = await tx(k.text, old.text, old.texts, "announcement.text"); if (av) { k.texts = Object.assign({}, k.texts || old.texts || {}); k.texts[L] = av; } }
      if ("link_text" in k && k.link_text !== old.link_text && k.link_text) { var lv = await tx(k.link_text, old.link_text, old.link_texts, "announcement.link_text"); if (lv) { k.link_texts = Object.assign({}, k.link_texts || old.link_texts || {}); k.link_texts[L] = lv; } }
    }
    if (e.path === "_data/coupon.yml") for (var cm of [["deal_text", "deal_texts"], ["button_text", "button_texts"], ["note_text", "note_texts"]]) {
      if (!(cm[0] in k) || !k[cm[0]] || k[cm[0]] === old[cm[0]]) continue;
      var cmap = k[cm[1]] || {};
      if (cmap[L]) continue; // typed by hand for this language in this edit
      var cv = await tx(k[cm[0]], old[cm[0]], null, "coupon." + cm[0]);
      if (cv) { k[cm[1]] = Object.assign({}, cmap); k[cm[1]][L] = cv; }
    }
    if (e.path === "_data/seo.yml" && k.pages) for (var pg of ["home", "pricing"]) {
      var np = k.pages[pg], op = (old.pages || {})[pg] || {}; if (!np || !np.en) continue;
      for (var f of ["title", "description"]) {
        var ne = np.en[f], oe = (op.en || {})[f]; if (!ne || ne === oe) continue;
        var sv = await translateText(L, ne, function (why) { fail("seo." + pg + "." + f, why); });
        if (sv != null) { np[L] = Object.assign({}, np[L] || {}); np[L][f] = sv; }
      }
    }
  }
  function translationNote(sm) {
    if (!sm) return "";
    if (sm.unsupported) return "Automatic translation isn’t available in this browser (it needs Google Chrome 138 or newer on a computer). Only the English was saved; the other languages show English until you translate them.";
    if (!sm.done.length && sm.skipped.length) return "Couldn’t translate this time: " + sm.skipped[0].why.replace(/^the translation model isn’t available \((.*)\)$/, "$1") + ". Only the English was saved; the other languages show English until they’re translated.";
    var n = sm.done.length - sm.skipped.filter(function (s) { return sm.done.indexOf(s.lang) > -1; }).length;
    var s = n === TR_LANGS.length ? "Translated into " + TR_LANGS.length + " languages ✓" : "Translated into " + n + " of " + TR_LANGS.length + " languages.";
    if (sm.skipped.length) s += " Skipped: " + sm.skipped.map(function (x) { return x.lang + " (" + x.why + ")"; }).join("; ") + ".";
    return s;
  }

  /* =====================================================================
     Page editors: Homepage, Pricing, FAQ, Supported AIs
     ===================================================================== */
  function fillPh(s, vars) { return String(s == null ? "" : s).replace(/%([a-z_]+)%/g, function (m, k) { return k in vars ? vars[k] : m; }); }
  function phWarn(enVal, val, label) {
    var a = placeholders(enVal).join(), b = placeholders(val).join();
    return a && a !== b ? label + ": the English text uses " + placeholders(enVal).join(" ") + "; check the same placeholders are here." : "";
  }
  function langSelectBind(id, getCode, setCode, sec) {
    var sel = $(id);
    sel.addEventListener("change", function () {
      if (sec.dirty && !confirm("Discard your unsaved changes in this language?")) { sel.value = getCode(); return; }
      setCode(sel.value); sec.reload(false);
    });
  }
  function previewVars(siteData, code) {
    return { name: esc(siteData.product_name || ""), email: esc(siteData.support_email || ""), shortcut: esc(siteData.command_center_shortcut || ""), pro_status: esc(siteData.pro_status || ""), privacy_url: "/privacy.html", pricing_url: (code === "en" ? "" : "/" + code) + "/pricing.html", terms_url: "/terms.html", currency: esc(siteData.price_currency || "") };
  }

  /* ---------- Images: pending uploads, picker, validation ---------- */
  var MAX_IMG = 1024 * 1024;
  function svgProblem(txt) {
    var t = txt.replace(/&#x([0-9a-f]+);?/gi, function (m, h) { return String.fromCharCode(parseInt(h, 16)); }).replace(/&#(\d+);?/g, function (m, d) { return String.fromCharCode(+d); });
    if (!/<svg[\s>]/i.test(t)) return "This isn’t an SVG image.";
    if (/<script/i.test(t)) return "This SVG contains a script, so it was refused.";
    if (/\son[a-z]+\s*=/i.test(t)) return "This SVG contains event handlers (code), so it was refused.";
    if (/javascript\s*:|vbscript\s*:/i.test(t)) return "This SVG contains a javascript: link, so it was refused.";
    if (/<(foreignObject|iframe|embed|object|audio|video|handler|listener)\b/i.test(t)) return "This SVG contains embedded content, so it was refused.";
    if (/<!ENTITY|<!DOCTYPE/i.test(t)) return "This SVG contains a DOCTYPE or entities, so it was refused.";
    if (/(?:href|src)\s*=\s*["']\s*(?!#|data:image\/(?:png|jpe?g|gif|webp);)/i.test(t)) return "This SVG links to an outside file, so it was refused.";
    if (/@import|url\(\s*["']?\s*(?!#|data:image\/)/i.test(t)) return "This SVG loads outside styles or files, so it was refused.";
    return "";
  }
  // file -> Promise<{name, ext, b64, dataUrl, size}>; rejects with a readable message.
  function readImage(f) {
    return new Promise(function (res, rej) {
      var ext = (/\.([a-z0-9]+)$/i.exec(f.name || "") || [])[1]; ext = ext ? ext.toLowerCase() : "";
      if (ext === "jpeg") ext = "jpg";
      if (["png", "jpg", "svg", "webp"].indexOf(ext) < 0) return rej(f.name + ": only PNG, JPG, SVG and WebP images can be uploaded.");
      if (f.size > MAX_IMG) return rej(f.name + " is " + fmtBytes(f.size) + "; the limit is 1 MB. Make it smaller first.");
      if (!f.size) return rej(f.name + " is empty.");
      var rd = new FileReader();
      rd.onerror = function () { rej("Couldn’t read " + f.name + "."); };
      rd.onload = function () {
        var u8 = new Uint8Array(rd.result), ok = true;
        if (ext === "png") ok = u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4e && u8[3] === 0x47;
        else if (ext === "jpg") ok = u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff;
        else if (ext === "webp") ok = String.fromCharCode.apply(null, u8.subarray(0, 4)) === "RIFF" && String.fromCharCode.apply(null, u8.subarray(8, 12)) === "WEBP";
        else { var p; try { p = svgProblem(new TextDecoder("utf-8", { fatal: true }).decode(u8)); } catch (e) { p = "This SVG isn’t valid text."; } if (p) return rej(f.name + ": " + p); }
        if (!ok) return rej(f.name + " isn’t really a " + ext.toUpperCase() + " image.");
        var b64 = bytesToB64(u8), mime = { png: "image/png", jpg: "image/jpeg", svg: "image/svg+xml", webp: "image/webp" }[ext];
        res({ name: f.name, ext: ext, b64: b64, size: f.size, dataUrl: "data:" + mime + ";base64," + b64 });
      };
      rd.readAsArrayBuffer(f);
    });
  }
  var PENDING = {}; // path -> {b64, dataUrl}: images chosen in an editor but not saved yet
  function uniqueUploadPath(name, ext) {
    var base = "assets/images/uploads/" + slug(name.replace(/\.[^.]+$/, "")), p = base + "." + ext, n = 2;
    var taken = {}; treePaths().forEach(function (x) { taken[x] = 1; }); Object.keys(PENDING).forEach(function (x) { taken[x] = 1; });
    while (taken[p]) p = base + "-" + (n++) + "." + ext;
    return p;
  }
  function mimeOf(p) { return /\.svg$/i.test(p) ? "image/svg+xml" : /\.png$/i.test(p) ? "image/png" : /\.webp$/i.test(p) ? "image/webp" : /\.gif$/i.test(p) ? "image/gif" : "image/jpeg"; }
  function imgSrc(sitePath) {
    if (!sitePath) return "";
    var rp = String(sitePath).replace(/^\//, "");
    if (PENDING[rp]) return PENDING[rp].dataUrl;
    var b = effB64(rp) || (DOCS[rp] && !DOCS[rp].missing && DOCS[rp].b64); if (b) return "data:" + mimeOf(rp) + ";base64," + b;
    return /^https?:/i.test(sitePath) ? "" : "/" + rp;
  }
  function pendingOps(paths) { return paths.filter(function (p) { return PENDING[p]; }).map(function (p) { return { path: p, ops: [{ t: "b64", b64: PENDING[p].b64, isNew: true }] }; }); }
  function clearPending(paths) { paths.forEach(function (p) { delete PENDING[p]; }); }
  var pickerCb = null;
  async function pickImage(cb) {
    pickerCb = cb; $("pickerMsg").textContent = "";
    var g = $("pickerGrid"); g.textContent = ""; g.appendChild(el("p", { class: "muted", text: "Loading…" }));
    if (!$("picker").open) $("picker").showModal();
    try { await getTree(); } catch (e) { g.textContent = e.message; return; }
    g.textContent = "";
    var imgs = treePaths(function (p) { return /^assets\/images\//.test(p) && isImagePath(p); }).concat(Object.keys(PENDING).filter(function (p) { return !(TREE || []).some(function (t) { return t.path === p; }); }));
    imgs.forEach(function (p) {
      g.appendChild(el("button", { type: "button", class: "cp-media-item", title: "/" + p, onclick: function () { $("picker").close(); var c = pickerCb; pickerCb = null; if (c) c("/" + p); } }, [el("img", { src: imgSrc("/" + p), alt: "", loading: "lazy" }), el("span", { text: p.replace(/^assets\/images\//, "") })]));
    });
  }
  $("pickerFile").addEventListener("change", async function () {
    var f = $("pickerFile").files[0]; $("pickerFile").value = ""; if (!f) return;
    try {
      var im = await readImage(f), p = uniqueUploadPath(im.name, im.ext);
      PENDING[p] = { b64: im.b64, dataUrl: im.dataUrl };
      $("picker").close(); var c = pickerCb; pickerCb = null; if (c) c("/" + p);
      toast("Image ready. It’s uploaded when you save this section.", "ok");
    } catch (e) { $("pickerMsg").textContent = String(e.message || e); }
  });
  function imageField(val, onChange, attrs) {
    var wrap = el("div", { class: "cp-imgfield" }), img = el("img", { alt: "", class: "cp-thumb" });
    var inp = el("input", Object.assign({ type: "text", spellcheck: "false", placeholder: "/assets/images/…" }, attrs || {}));
    inp.value = val || "";
    function upd() { var s = imgSrc(inp.value.trim()); if (s) { img.src = s; img.hidden = false; } else img.hidden = true; }
    inp.addEventListener("input", function () { upd(); onChange(inp.value.trim()); });
    wrap.appendChild(img); wrap.appendChild(inp);
    wrap.appendChild(el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { pickImage(function (p) { inp.value = p; upd(); onChange(p); }); } }, ["Choose…"]));
    upd(); return wrap;
  }

  /* ---------- Homepage ---------- */
  var HOME_SECTIONS = {
    hero: { title: "Hero (top of the page)", fields: [["h1_a", "Headline, first part"], ["h1_b", "Headline, highlighted part (gradient)"], ["h1_c", "Headline, last part"], ["lede", "Text under the headline", 1], ["hero_note", "Small note under the buttons"], ["logo_alt", "Logo description (for screen readers)"]] },
    ais: { title: "Supported AIs", fields: [["ais_h2", "Heading"], ["ais_p", "Text", 1]], extra: "ais" },
    features: { title: "Features (one demo video per row, title + short line beside it)", fields: [["features_h2", "Heading"], ["features_p", "Text", 1], ["feat_save", "Row 1 title · one-click save"], ["feat_save_d", "Row 1 short line · one-click save"], ["feat_reader", "Row 2 title · reader"], ["feat_reader_d", "Row 2 short line · reader"], ["feat_pdf", "Row 3 title · PDF export"], ["feat_pdf_d", "Row 3 short line · PDF export"], ["feat_formats", "Row 4 title · other formats"], ["feat_formats_d", "Row 4 short line · other formats"], ["feat_search", "Row 5 title · search"], ["feat_search_d", "Row 5 short line · search"], ["feat_folders", "Row 6 title · folders and tags"], ["feat_folders_d", "Row 6 short line · folders and tags"], ["feat_highlights", "Row 7 title · highlights and notes"], ["feat_highlights_d", "Row 7 short line · highlights and notes"], ["feat_studio", "Row 8 title · Export Studio"], ["feat_studio_d", "Row 8 short line · Export Studio"], ["feat_looks", "Row 9 title · each AI's look (Pro)"], ["feat_looks_d", "Row 9 short line · each AI's look (Pro)"], ["feat_sync", "Row 10 title · sync everything (Pro)"], ["feat_sync_d", "Row 10 short line · sync everything (Pro)"], ["feat_grok", "Row 11 title · Grok media and deleted chats (Pro)"], ["feat_grok_d", "Row 11 short line · Grok media and deleted chats (Pro)"], ["feat_ais", "Row 12 title · supported AIs"], ["feat_ais_d", "Row 12 short line · supported AIs"], ["pro_label", "Pro badge tooltip"]], extra: "features" },
    help: { title: "Help (how to get Pro + tutorial video)", fields: [["help_eyebrow", "Small label above"], ["help_h2", "Heading"], ["help_p", "Text", 1], ["help_steps", "Steps", "steps"], ["help_more", "Contact line (%email% = support email)", 1], ["help_video", "Video description (for screen readers)"]], extra: "help" },
    how: { title: "How it works", fields: [["how_h2", "Heading"], ["steps", "Steps", "steps"]] },
    privacy: { title: "Privacy", fields: [["priv_eyebrow", "Small label above"], ["priv_h2", "Heading"], ["priv_p", "Text (%privacy_url% = link to the policy)", 1], ["priv_items", "Check list", "list"]] },
    faq: { title: "Questions (FAQ)", fields: [["faq_h2", "Heading"]], extra: "faq" },
    cta: { title: "Closing call to action", fields: [["cta_h2", "Heading"]], extra: "cta" }
  };
  var hm = { code: "en", t: null, cur: null, en: null, cfg: null, cfgCur: null, site: {}, open: { hero: true } };
  function homeKeys() { var k = []; Object.keys(HOME_SECTIONS).forEach(function (s) { HOME_SECTIONS[s].fields.forEach(function (f) { k.push(f[0]); }); }); return k; }
  var secHome = defineSection("home", {
    label: "Homepage", files: function () { return [i18nPath(hm.code), "_data/home.yml", SITE_PATH, i18nPath("en")]; },
    page: function () { return hm.code === "en" ? "/" : "/" + hm.code + "/"; }, history: function () { return "_data/home.yml"; },
    load: async function (force) {
      await loadLangs(force); fillLangSelect($("homeLang"), hm.code);
      var t = (await effYaml(i18nPath(hm.code), force)) || {}, en = (await effYaml(i18nPath("en"), force)) || {};
      hm.t = t.home || {}; hm.cur = clone(hm.t); hm.en = en.home || {}; hm.tFull = t;
      hm.cfg = (await effYaml("_data/home.yml", force)) || {}; if (!Array.isArray(hm.cfg.sections)) hm.cfg.sections = ["ais", "features", "how", "help", "privacy", "faq", "cta"].map(function (id) { return { id: id, show: true }; });
      if (!Array.isArray(hm.cfg.hero_buttons)) hm.cfg.hero_buttons = [];
      hm.cfgCur = clone(hm.cfg); hm.site = (await effYaml(SITE_PATH, force)) || {};
      renderHome(); homePreview();
    },
    validate: function () {
      var bad = homeKeys().filter(function (k) { var v = hm.cur[k]; return JSON.stringify(v || "").match(/<\s*script|\son[a-z]+\s*=|javascript\s*:/i); })[0];
      if (bad) return "“" + bad + "” contains a script or event handler, which isn’t allowed.";
      for (var i = 0; i < hm.cfgCur.hero_buttons.length; i++) {
        var b = hm.cfgCur.hero_buttons[i];
        if (!String(b.text || "").trim()) return "Hero button " + (i + 1) + " needs a text.";
        if (!String(b.url || "").trim()) return "Hero button " + (i + 1) + " needs a link.";
        var e = badLink(b.url, true); if (e) return "Hero button " + (i + 1) + ": " + e;
      }
      if (!hm.cfgCur.sections.some(function (s) { return s.show !== false; })) return "Keep at least one section visible.";
      return "";
    },
    changes: function () {
      var out = [], sets = [];
      homeKeys().forEach(function (k) { if (!deepEq(hm.cur[k], hm.t[k]) && hm.cur[k] !== undefined) sets.push([["home", k], hm.cur[k]]); });
      if (sets.length) out.push({ path: i18nPath(hm.code), ops: [{ t: "ypath", sets: sets }] });
      var keys = {};
      if (!deepEq(hm.cfgCur.sections, hm.cfg.sections)) keys.sections = hm.cfgCur.sections;
      if (!deepEq(cleanButtons(hm.cfgCur.hero_buttons), cleanButtons(hm.cfg.hero_buttons))) keys.hero_buttons = cleanButtons(hm.cfgCur.hero_buttons);
      if (Object.keys(keys).length) out.push({ path: "_data/home.yml", ops: [{ t: "yset", keys: keys }] });
      return out;
    }
  });
  langSelectBind("homeLang", function () { return hm.code; }, function (c) { hm.code = c; }, secHome);
  function cleanButtons(list) {
    return (list || []).map(function (b) {
      var o = { text: String(b.text || "").trim(), url: String(b.url || "").trim(), style: b.style === "ghost" ? "ghost" : "primary" };
      var tx = {}; Object.keys(b.texts || {}).forEach(function (k) { var v = String(b.texts[k] || "").trim(); if (v) tx[k] = v; });
      if (Object.keys(tx).length) o.texts = tx;
      return o;
    });
  }
  function homeChanged() { secHome.check(); homePreviewSoon(); }
  function homeFieldInput(key, label, kind) {
    var dir = langDir(hm.code), enV = hm.en[key];
    if (kind === "list") { if (!Array.isArray(hm.cur[key])) hm.cur[key] = []; return fieldRow(label, stringList(hm.cur[key], homeChanged, label), "", true); }
    if (kind === "steps") {
      if (!Array.isArray(hm.cur[key])) hm.cur[key] = [];
      var box = el("div", { class: "cp-rows" });
      var draw = function () {
        box.textContent = "";
        hm.cur[key].forEach(function (st, i) {
          box.appendChild(el("div", { class: "cp-row-item" }, [
            el("span", { class: "cp-list-n", text: String(i + 1) }),
            el("div", { class: "cp-row-fields" }, [
              textInput(st.t, function (v) { st.t = v; homeChanged(); }, { "aria-label": "Step " + (i + 1) + " title", dir: dir, placeholder: "Title" }),
              textInput(st.d, function (v) { st.d = v; homeChanged(); }, { multiline: true, "aria-label": "Step " + (i + 1) + " text", dir: dir, placeholder: "Text" })
            ])
          ].concat(moveBtns(hm.cur[key], i, draw, homeChanged))));
        });
        box.appendChild(el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { hm.cur[key].push({ t: "", d: "" }); draw(); homeChanged(); } }, ["+ Add step"]));
      };
      draw(); return fieldRow(label, box, "", true);
    }
    var inp = textInput(hm.cur[key], function (v) { hm.cur[key] = v; homeChanged(); }, { multiline: !!kind, dir: dir, "data-key": key });
    var help = hm.code !== "en" && enV != null ? "English: " + String(enV).replace(/<[^>]+>/g, "") : "";
    return fieldRow(label, inp, help, true);
  }
  function renderHome() {
    var box = $("homeForm"); box.textContent = "";
    var secs = [{ id: "hero", fixed: true }].concat(hm.cfgCur.sections);
    secs.forEach(function (sc, idx) {
      var def = HOME_SECTIONS[sc.id]; if (!def) return;
      var d = el("details", { class: "cp-sec", "data-sec-id": sc.id }); if (hm.open[sc.id]) d.open = true;
      d.addEventListener("toggle", function () { hm.open[sc.id] = d.open; });
      var head = el("summary", { class: "cp-sec-head" }, [el("span", { class: "cp-sec-title", text: def.title })]);
      if (!sc.fixed) {
        var i = idx - 1, arr = hm.cfgCur.sections;
        var sw = checkInput(sc.show !== false, function (v) { sc.show = v; d.classList.toggle("off", !v); homeChanged(); }, "Show");
        sw.addEventListener("click", function (e) { e.stopPropagation(); });
        head.appendChild(sw);
        head.appendChild(el("button", { type: "button", class: "cp-ico", title: "Move up", "aria-label": "Move " + def.title + " up", disabled: i === 0, onclick: function (e) { e.preventDefault(); var t = arr[i - 1]; arr[i - 1] = arr[i]; arr[i] = t; renderHome(); homeChanged(); } }, ["↑"]));
        head.appendChild(el("button", { type: "button", class: "cp-ico", title: "Move down", "aria-label": "Move " + def.title + " down", disabled: i === arr.length - 1, onclick: function (e) { e.preventDefault(); var t = arr[i + 1]; arr[i + 1] = arr[i]; arr[i] = t; renderHome(); homeChanged(); } }, ["↓"]));
        if (sc.show === false) d.classList.add("off");
      }
      d.appendChild(head);
      var body = el("div", { class: "cp-sec-body" });
      def.fields.forEach(function (f) { body.appendChild(homeFieldInput(f[0], f[1], f[2])); });
      if (sc.id === "hero") body.appendChild(heroButtonsEditor());
      if (def.extra === "ais") body.appendChild(el("p", { class: "muted small" }, ["The logos themselves: ", el("button", { type: "button", class: "cp-link", onclick: function () { selectTab("ais"); } }, ["Supported AIs"]), "."]));
      if (def.extra === "faq") body.appendChild(el("p", { class: "muted small" }, ["The questions and answers: ", el("button", { type: "button", class: "cp-link", onclick: function () { selectTab("faq"); } }, ["FAQ editor"]), "."]));
      if (def.extra === "features") body.appendChild(el("p", { class: "muted small", text: "Each row shows one looping demo video (files in /assets/media/) with its title and one short line beside it, sides alternating as visitors scroll. Keep titles short: 2 to 6 words; the line under 10 words. An empty title hides that row." }));
      if (def.extra === "help") body.appendChild(el("p", { class: "muted small", text: "The top-bar Help link (Navigation) opens this section. The tutorial video is /assets/media/help.mp4." }));
      if (def.extra === "cta") body.appendChild(el("p", { class: "muted small", text: "The text under this heading is the tagline (Site settings), followed by the store buttons." }));
      d.appendChild(body); box.appendChild(d);
    });
  }
  function heroButtonsEditor() {
    var arr = hm.cfgCur.hero_buttons, box = el("div", { class: "cp-rows" }), en = hm.code === "en";
    var draw = function () {
      box.textContent = "";
      arr.forEach(function (b, i) {
        var txt = en ? b.text : ((b.texts || {})[hm.code] || "");
        box.appendChild(el("div", { class: "cp-row-item" }, [
          el("span", { class: "cp-list-n", text: String(i + 1) }),
          el("div", { class: "cp-row-fields cp-row-3" }, [
            textInput(txt, function (v) { if (en) b.text = v; else { b.texts = b.texts || {}; b.texts[hm.code] = v; } homeChanged(); }, { placeholder: en ? "Button text" : "Text in this language (empty = English: " + (b.text || "") + ")", "aria-label": "Hero button " + (i + 1) + " text", dir: langDir(hm.code) }),
            textInput(b.url, function (v) { b.url = v; homeChanged(); }, { placeholder: "/pricing.html or https://…", "aria-label": "Hero button " + (i + 1) + " link", spellcheck: "false" }),
            selectInput(b.style || "primary", [["primary", "Filled"], ["ghost", "Outline"]], function (v) { b.style = v; homeChanged(); }, { "aria-label": "Hero button " + (i + 1) + " style" })
          ])
        ].concat(moveBtns(arr, i, draw, homeChanged))));
      });
      box.appendChild(el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { arr.push({ text: "", url: "", style: "ghost" }); draw(); homeChanged(); } }, ["+ Add hero button"]));
    };
    draw();
    return fieldRow("Extra buttons under the store badges (optional)", box, en ? "The link is the same in every language; the text can be translated by switching the language above." : "Only the text is per language.", true);
  }
  var homePreviewSoon = debounce(function () { homePreview(); }, 120);
  function homePreview() {
    var p = $("homePrev"), c = hm.cur, v = previewVars(hm.site, hm.code), dir = langDir(hm.code);
    p.textContent = "";
    var root = el("div", { class: "cp-prev-root", dir: dir, lang: hm.code });
    var hero = el("section", { class: "hero" }, [el("div", { class: "wrap" }, [
      el("img", { class: "hero-logo", src: "/assets/images/logo.svg", width: "96", height: "96", alt: "" }),
      (function () { var h = el("h1"); h.appendChild(htmlEl("span", {}, c.h1_a)); h.appendChild(htmlEl("span", { class: "grad-text" }, c.h1_b)); h.appendChild(htmlEl("span", {}, c.h1_c)); return h; })(),
      htmlEl("p", { class: "lede" }, fillPh(c.lede, v)),
      el("div", { class: "stores" }, [el("span", { class: "store soon" }, [el("span", {}, [el("small", { text: "Chrome Web Store" }), "…"])])]),
      (function () {
        var bs = cleanButtons(hm.cfgCur.hero_buttons); if (!bs.length) return null;
        return el("div", { class: "hero-buttons" }, bs.map(function (b) { return el("span", { class: "btn" + (b.style === "ghost" ? " ghost" : "") , text: (b.texts && b.texts[hm.code]) || b.text }); }));
      })(),
      htmlEl("p", { class: "hero-note" }, c.hero_note)
    ])]);
    root.appendChild(hero);
    var vis = 0;
    hm.cfgCur.sections.forEach(function (sc) {
      if (sc.show === false) return;
      var alt = vis++ % 2 === 0, s;
      if (sc.id === "ais") s = el("section", { class: alt ? "alt" : null }, [el("div", { class: "wrap" }, [el("div", { class: "section-head" }, [htmlEl("h2", {}, c.ais_h2), htmlEl("p", {}, fillPh(c.ais_p, v))]), el("p", { class: "muted small cp-center", text: "(logo tiles)" })])]);
      else if (sc.id === "features") {
        var FIDS = ["save", "reader", "pdf", "formats", "search", "folders", "highlights", "studio", "looks", "sync", "grok", "ais"], FPRO = { looks: 1, sync: 1, grok: 1 };
        var fn = 0, cards = FIDS.filter(function (id) { return String(c["feat_" + id] || "").trim(); }).map(function (id) {
          fn++; var h = htmlEl("h3", { class: "feat-title" }, c["feat_" + id]); if (FPRO[id]) h.appendChild(el("span", { class: "pro-chip", text: "Pro" }));
          var d = String(c["feat_" + id + "_d"] || "").trim();
          return el("li", { class: "frow" + (fn % 2 ? "" : " flip"), "data-feat": id }, [
            el("div", { class: "frow-text" }, [el("div", { class: "frow-tin" }, [el("span", { class: "frow-num", text: (fn < 10 ? "0" : "") + fn }), h, d ? htmlEl("p", { class: "feat-desc" }, d) : null])]),
            el("div", { class: "frow-media" }, [el("div", { class: "frow-vin" }, [el("span", { class: "frow-glow" }), el("span", { class: "feat-media" }, [el("span", { class: "feat-bar" }, [el("i"), el("i"), el("i")]), el("img", { class: "feat-video", src: "/assets/media/" + id + ".webp", alt: "", loading: "lazy" })])])])]);
        });
        s = el("section", { class: "feat-sec" + (alt ? " alt" : "") }, [el("div", { class: "wrap" }, [el("div", { class: "section-head" }, [htmlEl("h2", {}, c.features_h2), htmlEl("p", {}, c.features_p)])]), el("ol", { class: "wrap feat-rows" }, cards)]);
      } else if (sc.id === "help") {
        s = el("section", { class: "help" + (alt ? " alt" : "") }, [el("div", { class: "wrap help-grid" }, [
          el("div", { class: "help-video" }, [el("img", { src: "/assets/media/help.webp", alt: "", style: "display:block;width:100%;height:100%;object-fit:cover" })]),
          el("div", { class: "help-text" }, [htmlEl("p", { class: "eyebrow" }, c.help_eyebrow), htmlEl("h2", {}, c.help_h2), htmlEl("p", { class: "muted" }, c.help_p),
            el("ol", { class: "help-steps" }, (c.help_steps || []).map(function (st) { return el("li", {}, [htmlEl("b", {}, st.t), htmlEl("span", {}, st.d)]); })),
            c.help_more ? htmlEl("p", { class: "help-more" }, fillPh(c.help_more, v)) : null])])]);
      } else if (sc.id === "how") s = el("section", { class: alt ? "alt" : null }, [el("div", { class: "wrap" }, [el("div", { class: "section-head" }, [htmlEl("h2", {}, c.how_h2)]), el("ol", { class: "steps" }, (c.steps || []).map(function (st) { return el("li", {}, [htmlEl("strong", {}, st.t), htmlEl("span", {}, st.d)]); }))])]);
      else if (sc.id === "privacy") s = el("section", { class: alt ? "alt" : null }, [el("div", { class: "wrap privacy-band" }, [el("div", {}, [htmlEl("p", { class: "eyebrow" }, c.priv_eyebrow), htmlEl("h2", {}, c.priv_h2), htmlEl("p", { class: "muted" }, fillPh(c.priv_p, v))]), el("ul", {}, (c.priv_items || []).map(function (x) { return htmlEl("li", {}, x); }))])]);
      else if (sc.id === "faq") s = el("section", { class: (alt ? "alt " : "") + "faq" }, [el("div", { class: "wrap narrow" }, [el("div", { class: "section-head" }, [htmlEl("h2", {}, c.faq_h2)]), el("p", { class: "muted small cp-center", text: "(questions from the FAQ editor)" })])]);
      else if (sc.id === "cta") s = el("section", { class: (alt ? "alt " : "") + "cta" }, [el("div", { class: "wrap" }, [htmlEl("h2", {}, c.cta_h2), el("p", { class: "muted", text: hm.site.tagline || "" })])]);
      if (s) root.appendChild(s);
    });
    p.appendChild(root);
  }

  /* ---------- Pricing ---------- */
  var PLAN_KEYS = {
    free: { h: "free_h", sub: "free_sub", per: "forever", cta: "get_free", badge: "free_badge", title: "Free" },
    yearly: { h: "yearly_h", sub: "yearly_sub", per: "per_year", cta: "yearly_cta", badge: "yearly_badge", price: "price_yearly", url: "checkout_yearly", title: "Pro Yearly" },
    monthly: { h: "monthly_h", sub: "monthly_sub", per: "per_month", cta: "monthly_cta", badge: "monthly_badge", price: "price_monthly", url: "checkout_monthly", title: "Pro Monthly" },
    lifetime: { h: "lifetime_h", sub: "lifetime_sub", per: "per_lifetime", cta: "lifetime_cta", badge: "lifetime_badge", price: "price_lifetime", url: "checkout_lifetime", title: "Pro Lifetime (optional)" }
  };
  var SITE_PRICE_KEYS = ["price_monthly", "price_yearly", "price_currency", "free_features", "pro_features", "pro_status"];
  var pr = { code: "en", site: null, siteCur: null, pz: null, pzCur: null, t: null, tCur: null, meta: null, metaCur: null };
  var PZ_DEFAULT = { launched: false, checkout_yearly: "", checkout_monthly: "", checkout_lifetime: "", highlighted: "yearly", lifetime_enabled: false, price_lifetime: "TBD", free_url: "", show_save: true };
  var secPricing = defineSection("pricing", {
    label: "Pricing", files: function () { return [SITE_PATH, "_data/pricing.yml", i18nPath(pr.code)]; },
    page: function () { return (pr.code === "en" ? "" : "/" + pr.code) + "/pricing.html"; }, history: function () { return "_data/pricing.yml"; },
    load: async function (force) {
      await loadLangs(force); fillLangSelect($("pricingLang"), pr.code);
      pr.site = (await effYaml(SITE_PATH, force)) || {}; pr.siteCur = clone(pr.site);
      pr.pz = Object.assign({}, PZ_DEFAULT, (await effYaml("_data/pricing.yml", force)) || {}); pr.pzCur = clone(pr.pz);
      var t = (await effYaml(i18nPath(pr.code), force)) || {}, en = (await effYaml(i18nPath("en"), force)) || {};
      pr.t = t.pricing || {}; pr.tCur = clone(pr.t); pr.en = en.pricing || {}; pr.meta = t.meta || {}; pr.metaCur = clone(pr.meta);
      renderPricing(); pricingPreview();
    },
    validate: function () {
      var s = pr.siteCur, z = pr.pzCur;
      var e = priceErr(s.price_yearly, "The yearly price") || priceErr(s.price_monthly, "The monthly price") || (z.lifetime_enabled ? priceErr(z.price_lifetime, "The lifetime price") : "");
      if (e) return e;
      if (!/^[A-Z]{3}$/.test(String(s.price_currency || "").trim())) return "The currency must be a 3-letter code such as USD or EUR.";
      var u = ["checkout_yearly", "checkout_monthly", "checkout_lifetime"].filter(function (k) { return String(z[k] || "").trim() && badLink(z[k], false); })[0];
      if (u) return "Checkout links must start with https:// (paste the Freemius checkout link).";
      if (z.free_url && badLink(z.free_url, true)) return "Free plan button: " + badLink(z.free_url, true);
      if (z.highlighted === "lifetime" && !z.lifetime_enabled) return "Turn the Lifetime plan on, or highlight another plan.";
      var bad = Object.keys(pr.tCur).filter(function (k) { return unsafeHtml(pr.tCur[k]); })[0]; if (bad) return "“" + bad + "” contains a script, which isn’t allowed.";
      return "";
    },
    changes: function () {
      var out = [], sk = {}, en = pr.code === "en";
      SITE_PRICE_KEYS.forEach(function (k) {
        if ((k === "free_features" || k === "pro_features" || k === "pro_status") && !en) return;
        var v = pr.siteCur[k]; if (Array.isArray(v)) v = v.map(function (x) { return String(x).trim(); }).filter(Boolean); else if (typeof v === "string" && k !== "price_monthly" && k !== "price_yearly") v = v.trim();
        if (!deepEq(v, pr.site[k])) sk[k] = v;
      });
      if (Object.keys(sk).length) out.push({ path: SITE_PATH, ops: [{ t: "yset", keys: sk }] });
      var zk = {};
      Object.keys(PZ_DEFAULT).forEach(function (k) { var v = typeof pr.pzCur[k] === "string" ? pr.pzCur[k].trim() : pr.pzCur[k]; if (!deepEq(v, pr.pz[k])) zk[k] = v; });
      if (Object.keys(zk).length) out.push({ path: "_data/pricing.yml", ops: [{ t: "yset", keys: zk }] });
      var sets = [];
      Object.keys(pr.tCur).forEach(function (k) { if (!deepEq(pr.tCur[k], pr.t[k])) sets.push([["pricing", k], pr.tCur[k]]); });
      if (!en) ["free_features", "pro_features", "pro_status"].forEach(function (k) { var v = pr.metaCur[k]; if (Array.isArray(v)) v = v.map(function (x) { return String(x).trim(); }).filter(Boolean); if (!deepEq(v, pr.meta[k]) && v !== undefined) sets.push([["meta", k], v]); });
      if (sets.length) out.push({ path: i18nPath(pr.code), ops: [{ t: "ypath", sets: sets }] });
      return out;
    }
  });
  langSelectBind("pricingLang", function () { return pr.code; }, function (c) { pr.code = c; }, secPricing);
  function prChanged() { secPricing.check(); pricingPreviewSoon(); }
  function renderPricing() {
    var box = $("pricingForm"); box.textContent = ""; var en = pr.code === "en", dir = langDir(pr.code), z = pr.pzCur, s = pr.siteCur;
    var g = el("div", { class: "cp-form" });
    g.appendChild(fieldRow("Currency", textInput(s.price_currency, function (v) { s.price_currency = v.toUpperCase(); prChanged(); }, { id: "prCurrency", maxlength: "3", spellcheck: "false" }), "USD shows a $ sign; other codes are written after the price."));
    g.appendChild(fieldRow("Highlighted plan (side glow)", selectInput(z.highlighted, [["yearly", "Pro Yearly"], ["monthly", "Pro Monthly"], ["free", "Free"], ["lifetime", "Pro Lifetime"]], function (v) { z.highlighted = v; prChanged(); }, { id: "prHighlight" })));
    var launch = checkInput(z.launched, function (v) { z.launched = v; prChanged(); }, "Pro is on sale: Pro buttons open the checkout links");
    launch.querySelector("input").id = "prLaunched";
    g.appendChild(el("div", { class: "cp-field wide" }, [el("span", { class: "cp-label", text: "Launch" }), launch, el("span", { class: "cp-help-text", text: "Off: Pro cards show the Pro status text on a disabled button. On: buttons become checkout links (paste them from Freemius below)." })]));
    if (en) g.appendChild(fieldRow("Pro status text (shown on Pro cards until launch)", textInput(s.pro_status, function (v) { s.pro_status = v; prChanged(); }, { id: "prStatus" }), "", true));
    else g.appendChild(fieldRow("Pro status text in this language", textInput(pr.metaCur.pro_status, function (v) { pr.metaCur.pro_status = v; prChanged(); }, { id: "prStatus", dir: dir }), "English: " + (s.pro_status || ""), true));
    g.appendChild(fieldRow("Page heading", textInput(pr.tCur.h1, function (v) { pr.tCur.h1 = v; prChanged(); }, { dir: dir, id: "prH1" })));
    g.appendChild(fieldRow("Intro (%currency% = the currency)", textInput(pr.tCur.intro, function (v) { pr.tCur.intro = v; prChanged(); }, { dir: dir, id: "prIntro" })));
    box.appendChild(g);
    ["free", "yearly", "monthly", "lifetime"].forEach(function (id) {
      var k = PLAN_KEYS[id], card = el("div", { class: "cp-plan-ed", "data-plan": id }), f = el("div", { class: "cp-form" });
      var head = el("div", { class: "cp-titlebar" }, [el("h3", { class: "cp-h3first", text: k.title })]);
      if (id === "lifetime") { var lt = checkInput(z.lifetime_enabled, function (v) { z.lifetime_enabled = v; card.classList.toggle("off", !v); prChanged(); }, "Show the Lifetime card (after Monthly)"); lt.querySelector("input").id = "prLifetime"; head.appendChild(lt); if (!z.lifetime_enabled) card.classList.add("off"); }
      card.appendChild(head);
      function tf(key, label, attrs) { return fieldRow(label, textInput(pr.tCur[key], function (v) { pr.tCur[key] = v; prChanged(); }, Object.assign({ dir: dir, id: "pr_" + key }, attrs || {})), !en && pr.en[key] != null ? "English: " + pr.en[key] : ""); }
      f.appendChild(tf(k.h, "Plan name"));
      f.appendChild(tf(k.sub, "Subtitle"));
      if (k.price) {
        var src = id === "lifetime" ? z : s;
        f.appendChild(fieldRow("Price", textInput(src[k.price], function (v) { src[k.price] = v.trim(); prChanged(); }, { id: "pr_" + k.price, spellcheck: "false", placeholder: "TBD" }), "A number such as 4.99, or TBD for “Coming soon”."));
      } else f.appendChild(fieldRow("Price", el("input", { type: "text", value: "0", disabled: true, id: "pr_free_price" }), "The Free plan is always 0."));
      f.appendChild(tf(k.per, "Period text"));
      f.appendChild(tf(k.badge, "Badge (optional, small label on the card)"));
      if (id === "yearly") {
        var sv = checkInput(z.show_save !== false, function (v) { z.show_save = v; prChanged(); }, "Show save % on Yearly"); sv.querySelector("input").id = "prShowSave";
        f.appendChild(el("div", { class: "cp-field wide" }, [el("span", { class: "cp-label", text: "Save badge" }), sv, el("span", { class: "cp-help-text", id: "prSaveInfo", text: saveInfo() })]));
        f.appendChild(tf("yearly_save", "Save badge text (%pct% = the percent)"));
      }
      f.appendChild(tf(k.cta, id === "free" ? "Button text" : "Button text (after launch)"));
      if (id === "free") f.appendChild(fieldRow("Button link", textInput(z.free_url, function (v) { z.free_url = v; prChanged(); }, { id: "pr_free_url", spellcheck: "false", placeholder: s.chrome_store_url ? "Empty = " + s.chrome_store_url : "Empty = the homepage install section (until the Chrome Web Store link is set)" }), "Leave empty to use the Chrome Web Store link (until it is set: the homepage install section, /#how)."));
      else f.appendChild(fieldRow("Checkout link (Freemius)", textInput(z[k.url], function (v) { z[k.url] = v; prChanged(); }, { id: "pr_" + k.url, spellcheck: "false", placeholder: "https://checkout.freemius.com/…" }), "Used only when “Pro is on sale” is on.", true));
      card.appendChild(f);
      if (id === "free" || id === "yearly") {
        var fk = id === "free" ? "free_features" : "pro_features", arr;
        if (en) { if (!Array.isArray(s[fk])) s[fk] = []; arr = s[fk]; } else { if (!Array.isArray(pr.metaCur[fk])) pr.metaCur[fk] = clone(s[fk] || []); arr = pr.metaCur[fk]; }
        card.appendChild(fieldRow(id === "free" ? "Free plan features" : "Pro features (shared by every Pro plan)", stringList(arr, prChanged, id === "free" ? "Free feature" : "Pro feature"), en ? "Other languages show this English list until their translation is updated (switch the language above)." : "Translation of the English list.", true));
      }
      box.appendChild(card);
    });
  }
  /* Same rule as _includes/plan-pro.html: plain numbers only, pct = round((monthly*12 - yearly) / (monthly*12) * 100), shown when > 0. */
  function savePct(m, y) {
    var ok = function (x) { return /^\d+(\.\d+)?$/.test(x); };
    m = String(m == null ? "" : m).trim(); y = String(y == null ? "" : y).trim();
    if (!ok(m) || !ok(y)) return 0; var m12 = parseFloat(m) * 12, yn = parseFloat(y);
    if (!(m12 > 0) || !(yn > 0)) return 0; var p = Math.round((m12 - yn) * 100 / m12 + 1e-9); return p > 0 ? p : 0;
  }
  function saveInfo() { var p = savePct(pr.siteCur.price_monthly, pr.siteCur.price_yearly); return p ? "Worked out from the prices: Save " + p + "% (12 × monthly vs yearly). Off hides it." : "Hidden right now: both prices must be numbers and Yearly must cost less than 12 × Monthly."; }
  var pricingPreviewSoon = debounce(function () { var i = $("prSaveInfo"); if (i) i.textContent = saveInfo(); pricingPreview(); }, 120);
  function pricingPreview() {
    var p = $("pricingPrev"), s = pr.siteCur, z = pr.pzCur, t = pr.tCur, en = pr.code === "en", dir = langDir(pr.code);
    var soon = "Coming soon", cur = String(s.price_currency || "USD");
    var status = en ? s.pro_status : (pr.metaCur.pro_status || s.pro_status);
    function price(v, per) { var x = String(v == null ? "" : v).trim(); if (!x || /^tbd$/i.test(x)) return el("div", { class: "price" }, [el("span", { class: "price-soon", text: soon })]); return el("div", { class: "price" }, [el("span", { class: "price-num", text: cur === "USD" ? "$" + x : x + " " + cur }), el("span", { class: "price-per", text: per || "" })]); }
    var ff = en ? s.free_features : (pr.metaCur.free_features || s.free_features), pf = en ? s.pro_features : (pr.metaCur.pro_features || s.pro_features);
    function plan(id) {
      var k = PLAN_KEYS[id], kids = [];
      if (t[k.badge]) kids.push(el("span", { class: "badge", text: t[k.badge] }));
      if (id === "yearly" && z.show_save !== false) { var sp = savePct(s.price_monthly, s.price_yearly); if (sp) kids.push(el("span", { class: "save-pill" + (t[k.badge] ? " side" : ""), text: String(t.yearly_save || pr.en.yearly_save || "Save %pct%").split("%pct%").join(sp + "%") })); }
      if (id !== "free" && !z.launched) kids.push(el("span", { class: "status", text: status || "" }));
      kids.push(el("h2", { text: t[k.h] || "" }), el("p", { class: "sub", text: t[k.sub] || "" }));
      kids.push(id === "free" ? price("0", t[k.per]) : price(id === "lifetime" ? z.price_lifetime : s[k.price], t[k.per]));
      if (id === "free") kids.push(el("span", { class: "btn ghost", text: t.get_free || "" }));
      else kids.push(el("span", { class: "btn", text: z.launched && String(z[k.url] || "").trim() ? t[k.cta] : status }));
      kids.push(el("ul", {}, ((id === "free" ? ff : pf) || []).filter(Boolean).map(function (x) { return el("li", { text: x }); })));
      return el("div", { class: "plan" + (z.highlighted === id ? " featured" : "") }, kids);
    }
    var ids = ["free", "yearly", "monthly"].concat(z.lifetime_enabled ? ["lifetime"] : []);
    p.textContent = "";
    p.appendChild(el("div", { class: "cp-prev-root", dir: dir }, [el("section", {}, [el("div", { class: "wrap" }, [
      el("div", { class: "section-head" }, [el("h1", { text: t.h1 || "" }), el("p", { text: fillPh(t.intro, { currency: cur }) })]),
      el("div", { class: "plans" + (z.lifetime_enabled ? " plans-4" : "") }, ids.map(plan))
    ])])]));
  }

  /* ---------- FAQ ---------- */
  var fq = { code: "en", list: null, cur: null, h2: "", h2Cur: "", en: null, site: {} };
  var secFaq = defineSection("faq", {
    label: "FAQ", files: function () { return [i18nPath(fq.code), SITE_PATH]; },
    page: function () { return (fq.code === "en" ? "/" : "/" + fq.code + "/") + "#faq"; }, history: function () { return i18nPath(fq.code); },
    load: async function (force) {
      await loadLangs(force); fillLangSelect($("faqLang"), fq.code);
      var t = (await effYaml(i18nPath(fq.code), force)) || {}, h = t.home || {};
      fq.list = Array.isArray(h.faq) ? h.faq : []; fq.cur = clone(fq.list); fq.h2 = h.faq_h2 || ""; fq.h2Cur = fq.h2;
      fq.site = (await effYaml(SITE_PATH, force)) || {};
      renderFaq(); faqPreview();
    },
    validate: function () {
      for (var i = 0; i < fq.cur.length; i++) {
        if (!String(fq.cur[i].q || "").trim()) return "Question " + (i + 1) + " is empty.";
        if (!String(fq.cur[i].a || "").trim()) return "The answer to question " + (i + 1) + " is empty.";
        if (unsafeHtml(fq.cur[i].q) || unsafeHtml(fq.cur[i].a)) return "Question " + (i + 1) + " contains a script, which isn’t allowed.";
      }
      return "";
    },
    changes: function () {
      var sets = [], cl = fq.cur.map(function (x) { return { q: String(x.q).trim(), a: String(x.a).trim() }; });
      if (!deepEq(cl, fq.list)) sets.push([["home", "faq"], cl]);
      if (fq.h2Cur !== fq.h2) sets.push([["home", "faq_h2"], fq.h2Cur]);
      return sets.length ? [{ path: i18nPath(fq.code), ops: [{ t: "ypath", sets: sets }] }] : [];
    }
  });
  langSelectBind("faqLang", function () { return fq.code; }, function (c) { fq.code = c; }, secFaq);
  function faqChanged() { secFaq.check(); faqPreviewSoon(); }
  function renderFaq() {
    var box = $("faqForm"); box.textContent = ""; var dir = langDir(fq.code);
    box.appendChild(fieldRow("Section heading", textInput(fq.h2Cur, function (v) { fq.h2Cur = v; faqChanged(); }, { id: "faqH2", dir: dir }), "", true));
    var rows = el("div", { class: "cp-rows" });
    var draw = function () {
      rows.textContent = "";
      fq.cur.forEach(function (it, i) {
        rows.appendChild(el("div", { class: "cp-row-item cp-faq-item" }, [
          el("span", { class: "cp-list-n", text: String(i + 1) }),
          el("div", { class: "cp-row-fields" }, [
            textInput(it.q, function (v) { it.q = v; faqChanged(); }, { placeholder: "Question", "aria-label": "Question " + (i + 1), dir: dir, class: "faq-q" }),
            textInput(it.a, function (v) { it.a = v; faqChanged(); }, { multiline: true, placeholder: "Answer", "aria-label": "Answer " + (i + 1), dir: dir, class: "faq-a" })
          ])
        ].concat(moveBtns(fq.cur, i, draw, faqChanged))));
      });
      rows.appendChild(el("button", { type: "button", class: "cp-btn ghost small", id: "faqAdd", onclick: function () { fq.cur.push({ q: "", a: "" }); draw(); faqChanged(); var q = rows.querySelectorAll(".faq-q"); if (q.length) q[q.length - 1].focus(); } }, ["+ Add question"]));
    };
    draw(); box.appendChild(rows);
  }
  var faqPreviewSoon = debounce(function () { faqPreview(); }, 120);
  function faqPreview() {
    var v = previewVars(fq.site, fq.code), p = $("faqPrev"); p.textContent = "";
    p.appendChild(el("div", { class: "cp-prev-root", dir: langDir(fq.code) }, [el("section", { class: "alt faq" }, [el("div", { class: "wrap narrow" }, [el("div", { class: "section-head" }, [el("h2", { text: fq.h2Cur })])].concat(fq.cur.map(function (it, i) {
      var d = el("details", {}, [htmlEl("summary", {}, it.q), htmlEl("p", {}, fillPh(it.a, v))]); if (i === 0) d.open = true; return d;
    })))])]));
  }

  /* ---------- Supported AIs ---------- */
  var ai = { list: null, cur: null, raw: null };
  var secAis = defineSection("ais", {
    label: "Supported AIs", files: function () { return ["_data/ais.yml"]; }, page: function () { return "/#ais"; },
    load: async function (force) {
      ai.raw = (await effYaml("_data/ais.yml", force)) || {}; ai.list = Array.isArray(ai.raw.ais) ? ai.raw.ais : []; ai.cur = clone(ai.list);
      try { await getTree(); } catch (e) {}
      renderAis(); aisPreview();
    },
    validate: function () {
      for (var i = 0; i < ai.cur.length; i++) {
        var a = ai.cur[i];
        if (!String(a.name || "").trim()) return "Logo " + (i + 1) + " needs a name.";
        var l = String(a.logo || "").trim();
        if (!/^\/[\w\-./]+\.(svg|png|jpe?g|webp|gif)$/i.test(l) || /\.\./.test(l)) return "Logo " + (i + 1) + " (" + a.name + ") needs an image from this site — use Choose….";
      }
      return "";
    },
    changes: function () {
      var cl = ai.cur.map(function (a) { return { name: String(a.name).trim(), logo: String(a.logo).trim() }; });
      var out = deepEq(cl, ai.list) ? [] : [{ path: "_data/ais.yml", ops: [{ t: "yset", keys: { ais: cl } }] }];
      return out.concat(pendingOps(cl.map(function (a) { return a.logo.replace(/^\//, ""); })));
    }
  });
  function aisChanged() { secAis.check(); aisPreviewSoon(); }
  function renderAis() {
    var box = $("aisForm"); box.textContent = "";
    var rows = el("div", { class: "cp-rows" });
    var draw = function () {
      rows.textContent = "";
      ai.cur.forEach(function (a, i) {
        rows.appendChild(el("div", { class: "cp-row-item cp-ai-item" }, [
          el("span", { class: "cp-list-n", text: String(i + 1) }),
          el("div", { class: "cp-row-fields cp-row-2" }, [
            textInput(a.name, function (v) { a.name = v; aisChanged(); }, { placeholder: "Name shown on hover", "aria-label": "AI " + (i + 1) + " name", class: "ai-name" }),
            imageField(a.logo, function (v) { a.logo = v; aisChanged(); }, { "aria-label": "AI " + (i + 1) + " logo", class: "ai-logo" })
          ])
        ].concat(moveBtns(ai.cur, i, draw, aisChanged))));
      });
      rows.appendChild(el("button", { type: "button", class: "cp-btn ghost small", id: "aiAdd", onclick: function () { ai.cur.push({ name: "", logo: "" }); draw(); aisChanged(); var n = rows.querySelectorAll(".ai-name"); if (n.length) n[n.length - 1].focus(); } }, ["+ Add AI"]));
    };
    draw(); box.appendChild(rows);
  }
  var aisPreviewSoon = debounce(function () { aisPreview(); }, 120);
  function aisPreview() {
    var p = $("aisPrev"); p.textContent = "";
    p.appendChild(el("div", { class: "cp-prev-root" }, [el("section", { class: "alt" }, [el("div", { class: "wrap" }, [el("ul", { class: "ai-list" }, ai.cur.map(function (a) {
      return el("li", { tabindex: "0", "data-name": a.name || "" }, [el("img", { src: imgSrc(a.logo), alt: a.name || "", title: a.name || "", width: "36", height: "36" })]);
    }))])])]));
  }

  /* =====================================================================
     Site-wide editors: Navigation, Announcement, Store links, SEO, Languages, Maintenance
     ===================================================================== */

  /* ---------- Navigation & footer ---------- */
  var NAV_KEYS = [["product", "Product"], ["pricing", "Pricing"], ["help", "Help"], ["privacy", "Privacy"], ["terms", "Terms"], ["privacy_policy", "Privacy Policy"], ["terms_of_service", "Terms of Service"], ["refund_policy", "Refund Policy"], ["contact", "Contact"]];
  var NAV_LINKS = [["home", "Home page"], ["pricing", "Pricing page"], ["help", "Help section (homepage)"], ["/privacy.html", "Privacy Policy"], ["/terms.html", "Terms of Service"], ["/refund.html", "Refund Policy"], ["email", "Email (support address)"], ["custom", "Other address…"]];
  var nv = { orig: null, cur: null, en: {} };
  var secNav = defineSection("nav", {
    label: "Navigation", files: function () { return ["_data/navigation.yml", i18nPath("en")]; }, page: function () { return "/"; }, history: function () { return "_data/navigation.yml"; },
    load: async function (force) {
      var d = (await effYaml("_data/navigation.yml", force)) || {};
      nv.orig = { header: Array.isArray(d.header) ? d.header : [], footer: Array.isArray(d.footer) ? d.footer : [] }; nv.cur = clone(nv.orig);
      nv.en = (((await effYaml(i18nPath("en"), force)) || {}).nav) || {};
      renderNav(); navPreview();
    },
    validate: function () {
      var areas = [["header", "Top bar"], ["footer", "Footer"]];
      for (var a = 0; a < 2; a++) {
        var list = nv.cur[areas[a][0]];
        for (var i = 0; i < list.length; i++) {
          var it = list[i], n = areas[a][1] + " link " + (i + 1);
          if (!it.key && !String(it.label || "").trim()) return n + " needs a label.";
          if (!String(it.link || "").trim()) return n + " needs an address.";
          if (["home", "pricing", "email", "help"].indexOf(it.link) < 0) { var e = badLink(it.link, "mail"); if (e) return n + ": " + e; }
          if (a === 0 && (/\/refund(\.html)?$/i.test(it.link) || it.key === "refund_policy")) return "The Refund Policy stays out of the top bar (it’s in the footer).";
        }
      }
      if (!nv.cur.header.length) return "Keep at least one link in the top bar.";
      return "";
    },
    changes: function () {
      var keys = {};
      ["header", "footer"].forEach(function (a) {
        var cl = nv.cur[a].map(function (it) { var o = {}; if (it.key) o.key = it.key; else o.label = String(it.label || "").trim(); o.link = String(it.link).trim(); if (!it.key && it.labels && Object.keys(it.labels).length && it.label === (nv.orig[a].filter(function (x) { return x.label === it.label; })[0] || {}).label) o.labels = it.labels; return o; });
        if (!deepEq(cl, nv.orig[a])) keys[a] = cl;
      });
      return Object.keys(keys).length ? [{ path: "_data/navigation.yml", ops: [{ t: "yset", keys: keys }] }] : [];
    }
  });
  function navChanged() { secNav.check(); navPreviewSoon(); }
  function navListEditor(area, title) {
    var arr = nv.cur[area], box = el("div", { class: "cp-rows", "data-area": area });
    var draw = function () {
      box.textContent = "";
      arr.forEach(function (it, i) {
        var custom = !it.key, isPreset = NAV_LINKS.some(function (l) { return l[0] === it.link && l[0] !== "custom"; });
        var labelSel = selectInput(custom ? "__custom" : it.key, NAV_KEYS.map(function (k) { return [k[0], (nv.en[k[0]] || k[1]) + " (translated)"]; }).concat([["__custom", "My own text…"]]), function (v) { if (v === "__custom") { delete it.key; it.label = it.label || ""; } else { it.key = v; delete it.label; delete it.labels; } draw(); navChanged(); }, { "aria-label": title + " link " + (i + 1) + " label" });
        var linkSel = selectInput(isPreset ? it.link : "custom", NAV_LINKS, function (v) { it.link = v === "custom" ? "https://" : v; draw(); navChanged(); }, { "aria-label": title + " link " + (i + 1) + " address" });
        var fields = [labelSel];
        if (custom) fields.push(textInput(it.label, function (v) { it.label = v; navChanged(); }, { placeholder: "Label", "aria-label": title + " link " + (i + 1) + " text" }));
        fields.push(linkSel);
        if (!isPreset) fields.push(textInput(it.link, function (v) { it.link = v.trim(); navChanged(); }, { placeholder: "https://… or /page.html", spellcheck: "false", "aria-label": title + " link " + (i + 1) + " custom address" }));
        box.appendChild(el("div", { class: "cp-row-item" }, [el("span", { class: "cp-list-n", text: String(i + 1) }), el("div", { class: "cp-row-fields cp-row-2" }, fields)].concat(moveBtns(arr, i, draw, navChanged))));
      });
      box.appendChild(el("button", { type: "button", class: "cp-btn ghost small", "data-add": area, onclick: function () { arr.push({ label: "", link: "https://" }); draw(); navChanged(); } }, ["+ Add link"]));
    };
    draw(); return fieldRow(title, box, area === "header" ? "The language menu and the light/dark button always follow these links." : "", true);
  }
  function renderNav() { var b = $("navForm"); b.textContent = ""; b.appendChild(navListEditor("header", "Top bar")); b.appendChild(navListEditor("footer", "Footer")); }
  var navPreviewSoon = debounce(function () { navPreview(); }, 120);
  function navLabel(it) { return it.key ? (nv.en[it.key] || it.key) : (it.label || "…"); }
  function navPreview() {
    var p = $("navPrev"); p.textContent = "";
    p.appendChild(el("div", { class: "cp-prev-root" }, [
      el("header", { class: "site-head cp-static" }, [el("div", { class: "wrap head-row" }, [el("span", { class: "brand" }, [el("img", { src: "/assets/images/logo.svg", width: "32", height: "32", alt: "" }), el("span", { text: (site.cur && site.cur.product_name) || "AI Chat Saver" })]), el("nav", { class: "nav" }, nv.cur.header.map(function (it) { return el("a", { href: "#", text: navLabel(it), onclick: function (e) { e.preventDefault(); } }); }))])]),
      el("footer", { class: "site-foot" }, [el("div", { class: "wrap foot-row" }, [el("nav", { class: "foot-nav" }, nv.cur.footer.map(function (it) { return el("a", { href: "#", text: navLabel(it), onclick: function (e) { e.preventDefault(); } }); }))])])
    ]));
  }

  /* ---------- Announcement bar ---------- */
  var ANN_COLORS = [["#6d28d9", "Purple"], ["#c2410c", "Orange"], ["#0f766e", "Teal"], ["#1d4ed8", "Blue"], ["#b91c1c", "Red"], ["#17142b", "Dark"]];
  function contrastText(hex) {
    var m = /^#([0-9a-f]{6})$/i.exec(hex || ""); if (!m) return "#ffffff";
    var n = parseInt(m[1], 16), c = [n >> 16 & 255, n >> 8 & 255, n & 255].map(function (v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
    var L = 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    return (1.05) / (L + 0.05) >= (L + 0.05) / 0.05 ? "#ffffff" : "#17142b";
  }
  var an = { orig: null, cur: null };
  var ANN_DEFAULT = { enabled: false, text: "", texts: {}, link_texts: {}, link: "", link_text: "", color: "#6d28d9", text_color: "#ffffff", dismissible: true };
  var secAnn = defineSection("announce", {
    label: "Announcement bar", files: function () { return ["_data/announcement.yml"]; }, page: function () { return "/"; }, history: function () { return "_data/announcement.yml"; },
    load: async function (force) { await loadLangs(force); an.orig = Object.assign({}, ANN_DEFAULT, (await effYaml("_data/announcement.yml", force)) || {}); an.cur = clone(an.orig); renderAnn(); annPreview(); },
    validate: function () {
      var c = an.cur;
      if (c.enabled && !String(c.text || "").trim()) return "Write the announcement text, or switch the bar off.";
      if (String(c.text || "").length > 220) return "Keep the announcement under 220 characters.";
      if (c.link && badLink(c.link, true)) return "Announcement link: " + badLink(c.link, true);
      if (!/^#[0-9a-f]{6}$/i.test(c.color)) return "Pick a colour.";
      return "";
    },
    changes: function () {
      var c = clone(an.cur), keys = {};
      c.text = String(c.text || "").trim(); c.link = String(c.link || "").trim(); c.link_text = String(c.link_text || "").trim(); c.text_color = contrastText(c.color);
      ["texts", "link_texts"].forEach(function (k) { var o = {}; Object.keys(c[k] || {}).forEach(function (l) { var v = String(c[k][l] || "").trim(); if (v) o[l] = v; }); c[k] = o; });
      Object.keys(ANN_DEFAULT).forEach(function (k) { if (!deepEq(c[k], an.orig[k])) keys[k] = c[k]; });
      return Object.keys(keys).length ? [{ path: "_data/announcement.yml", ops: [{ t: "yset", keys: keys }] }] : [];
    }
  });
  function annChanged() { secAnn.check(); annPreviewSoon(); }
  function renderAnn() {
    var b = $("annForm"), c = an.cur; b.textContent = "";
    var g = el("div", { class: "cp-form" });
    var on = checkInput(c.enabled, function (v) { c.enabled = v; annChanged(); }, "Show the announcement bar on every page"); on.querySelector("input").id = "annOn";
    g.appendChild(el("div", { class: "cp-field wide" }, [on]));
    g.appendChild(fieldRow("Text", textInput(c.text, function (v) { c.text = v; annChanged(); }, { id: "annText", maxlength: "220" }), "Plain text. With auto-translate on, it’s translated into the other languages when you save.", true));
    g.appendChild(fieldRow("Link (optional)", textInput(c.link, function (v) { c.link = v; annChanged(); }, { id: "annLink", spellcheck: "false", placeholder: "/pricing.html or https://…" })));
    g.appendChild(fieldRow("Link text (optional)", textInput(c.link_text, function (v) { c.link_text = v; annChanged(); }, { id: "annLinkText", placeholder: "Empty = the whole text is the link" })));
    var sw = el("div", { class: "cp-swatches" });
    ANN_COLORS.forEach(function (k) { var bt = el("button", { type: "button", class: "cp-swatch", title: k[1], "aria-label": k[1], "aria-pressed": c.color.toLowerCase() === k[0] ? "true" : "false", onclick: function () { c.color = k[0]; col.value = k[0]; [].forEach.call(sw.querySelectorAll(".cp-swatch"), function (x) { x.setAttribute("aria-pressed", "false"); }); bt.setAttribute("aria-pressed", "true"); annChanged(); } }); bt.style.setProperty("--sw", k[0]); sw.appendChild(bt); });
    var col = el("input", { type: "color", id: "annColor", "aria-label": "Custom colour" }); col.value = c.color; col.addEventListener("input", function () { c.color = col.value; [].forEach.call(sw.querySelectorAll(".cp-swatch"), function (x) { x.setAttribute("aria-pressed", "false"); }); annChanged(); });
    sw.appendChild(col);
    g.appendChild(fieldRow("Colour", sw, "The text colour is picked automatically for contrast."));
    var dm = checkInput(c.dismissible, function (v) { c.dismissible = v; annChanged(); }, "Visitors can close it (it stays closed until the text changes)"); dm.querySelector("input").id = "annDismiss";
    g.appendChild(el("div", { class: "cp-field" }, [el("span", { class: "cp-label", text: "Close button" }), dm]));
    var det = el("details", { class: "cp-more wide" }, [el("summary", { text: "Text in other languages (optional)" })]);
    LANGS.filter(function (l) { return l.code !== "en"; }).forEach(function (l) {
      det.appendChild(fieldRow(l.name + " (" + l.code + ")", textInput((c.texts || {})[l.code], function (v) { c.texts = c.texts || {}; c.texts[l.code] = v; annChanged(); }, { dir: l.dir || null, lang: l.hreflang, placeholder: "Empty = the English text" })));
    });
    g.appendChild(det);
    b.appendChild(g);
  }
  var annPreviewSoon = debounce(function () { annPreview(); }, 80);
  function annPreview() {
    var c = an.cur, p = $("annPrev"); p.textContent = "";
    if (!c.enabled) p.appendChild(el("p", { class: "muted small", text: "The bar is off, so visitors don’t see it. This is how it would look:" }));
    var t = c.text || "Your announcement", bar = el("div", { class: "announce" }, [el("div", { class: "wrap announce-row" }, [
      el("p", {}, c.link ? (c.link_text ? [t + " ", el("a", { href: "#", text: c.link_text, onclick: function (e) { e.preventDefault(); } })] : [el("a", { href: "#", text: t, onclick: function (e) { e.preventDefault(); } })]) : [t]),
      c.dismissible ? el("button", { type: "button", class: "announce-x", "aria-label": "Dismiss" }, ["✕"]) : null
    ])]);
    bar.style.setProperty("--ann-bg", c.color); bar.style.setProperty("--ann-fg", contrastText(c.color));
    p.appendChild(el("div", { class: "cp-prev-root" }, [bar]));
  }

  /* ---------- Store links & launch ---------- */
  var st = { orig: null, cur: null };
  var STORE_KEYS = ["chrome_store_url", "extension_version"];
  var secStores = defineSection("stores", {
    label: "Store links", files: function () { return [SITE_PATH]; }, page: function () { return "/"; }, history: function () { return SITE_PATH; },
    load: async function (force) {
      var s = (await effYaml(SITE_PATH, force)) || {}; st.orig = {}; STORE_KEYS.forEach(function (k) { st.orig[k] = s[k] == null ? "" : String(s[k]); }); st.cur = clone(st.orig);
      try { st.chrome = (await doc("_includes/chrome.svg")).text; } catch (e) {}
      renderStores(); storesPreview();
    },
    validate: function () {
      var c = st.cur;
      if (c.chrome_store_url && !/^https:\/\/(chromewebstore\.google\.com|chrome\.google\.com\/webstore)\//.test(c.chrome_store_url.trim())) return "The Chrome link must start with https://chromewebstore.google.com/ (copy it from your item’s store page).";
      if (c.extension_version && !/^\d+(\.\d+){0,3}$/.test(c.extension_version.trim())) return "The version should look like 2.13.10.";
      return "";
    },
    changes: function () { var c = {}; STORE_KEYS.forEach(function (k) { c[k] = String(st.cur[k] || "").trim(); }); return yamlKeyChanges(SITE_PATH, c, st.orig); }
  });
  function storesChanged() { secStores.check(); storesPreviewSoon(); renderStoreStatus(); }
  function renderStoreStatus() {
    var b = $("storeStatus"); if (!b) return; b.textContent = "";
    [["chrome_store_url", "Chrome Web Store"]].forEach(function (k) {
      var live = !!String(st.cur[k[0]] || "").trim();
      b.appendChild(el("div", {}, [el("div", { class: "cp-label", text: k[1] }), el("span", { class: "cp-pill " + (live ? "built" : "queued"), text: live ? "Live link" : "Coming soon" })]));
    });
  }
  function renderStores() {
    var b = $("storesForm"); b.textContent = "";
    b.appendChild(el("div", { class: "cp-status", id: "storeStatus" }));
    var g = el("div", { class: "cp-form" });
    g.appendChild(fieldRow("Chrome Web Store link", textInput(st.cur.chrome_store_url, function (v) { st.cur.chrome_store_url = v; storesChanged(); }, { id: "stChrome", spellcheck: "false", placeholder: "Empty = Coming soon" }), "", true));
    g.appendChild(fieldRow("Extension version shown on the homepage", textInput(st.cur.extension_version, function (v) { st.cur.extension_version = v; storesChanged(); }, { id: "stVersion", spellcheck: "false", placeholder: "Empty = hidden" }), "For example 2.13.10."));
    b.appendChild(g); renderStoreStatus();
  }
  function svgImg(txt) { return txt ? el("img", { class: "store-ic", src: "data:image/svg+xml;base64," + utf8ToB64(txt), alt: "", width: "28", height: "28" }) : null; }
  var storesPreviewSoon = debounce(function () { storesPreview(); }, 100);
  function storesPreview() {
    var c = st.cur, p = $("storesPrev"); p.textContent = "";
    function badge(url, ic, live1, live2, soon1) { return url ? el("span", { class: "store" }, [svgImg(ic), el("span", {}, [el("small", { text: live1 }), live2])]) : el("span", { class: "store soon" }, [svgImg(ic), el("span", {}, [el("small", { text: soon1 }), "Coming soon"])]); }
    p.appendChild(el("div", { class: "cp-prev-root" }, [el("section", { class: "hero cp-hero-mini" }, [el("div", { class: "wrap" }, [
      el("div", { class: "stores" }, [badge(c.chrome_store_url, st.chrome, "Available in the", "Chrome Web Store", "Chrome Web Store")]),
      c.extension_version ? el("p", { class: "store-version", text: "Version " + c.extension_version }) : null
    ])])]));
  }

  /* ---------- SEO & sharing ---------- */
  var SEO_PAGES = [["home", "Home", "/"], ["pricing", "Pricing", "/pricing.html"], ["privacy", "Privacy Policy", "/privacy.html"], ["terms", "Terms", "/terms.html"], ["refund", "Refund Policy", "/refund.html"]];
  var so = { orig: null, cur: null, page: "home", code: "en", site: {}, i18n: {}, fm: {} };
  var secSeo = defineSection("seo", {
    label: "SEO", files: function () { return ["_data/seo.yml"]; }, page: function () { var pg = SEO_PAGES.filter(function (x) { return x[0] === so.page; })[0]; return (so.code !== "en" && (so.page === "home" || so.page === "pricing") ? "/" + so.code : "") + pg[2]; }, history: function () { return "_data/seo.yml"; },
    load: async function (force) {
      await loadLangs(force);
      var d = (await effYaml("_data/seo.yml", force)) || {};
      so.orig = { default_og_image: d.default_og_image || "", pages: d.pages && typeof d.pages === "object" ? d.pages : {} }; so.cur = clone(so.orig);
      so.site = (await effYaml(SITE_PATH, force)) || {};
      for (var i = 0; i < LANGS.length; i++) { try { so.i18n[LANGS[i].code] = (await effYaml(i18nPath(LANGS[i].code), force)) || {}; } catch (e) {} }
      for (var j = 2; j < SEO_PAGES.length; j++) { try { var sp = splitFm(effText((await doc("pages/" + SEO_PAGES[j][0] + ".md", force)) && "pages/" + SEO_PAGES[j][0] + ".md")); so.fm[SEO_PAGES[j][0]] = Y.load(sp.fmText, YOPT) || {}; } catch (e) { so.fm[SEO_PAGES[j][0]] = {}; } }
      renderSeo();
    },
    validate: function () {
      var c = so.cur, imgs = [c.default_og_image];
      Object.keys(c.pages).forEach(function (p) { imgs.push(c.pages[p].og_image); });
      var bad = imgs.filter(function (u) { return u && badLink(u, true); })[0]; if (bad) return "Images must be a path on this site (/assets/…) or an https:// address.";
      var txt = []; Object.keys(c.pages).forEach(function (p) { Object.keys(c.pages[p]).forEach(function (l) { var v = c.pages[p][l]; if (v && typeof v === "object") txt.push(v.title, v.description); }); });
      if (txt.some(function (s) { return s && /[<>]/.test(s); })) return "Titles and descriptions can’t contain < or >.";
      return "";
    },
    changes: function () {
      var c = cleanSeo(so.cur), keys = {};
      if (c.default_og_image !== (so.orig.default_og_image || "")) keys.default_og_image = c.default_og_image;
      if (!deepEq(c.pages, cleanSeo(so.orig).pages)) keys.pages = c.pages;
      var out = Object.keys(keys).length ? [{ path: "_data/seo.yml", ops: [{ t: "yset", keys: keys }] }] : [];
      var imgs = [c.default_og_image]; Object.keys(c.pages).forEach(function (p) { imgs.push(c.pages[p].og_image); });
      return out.concat(pendingOps(imgs.filter(Boolean).map(function (u) { return u.replace(/^\//, ""); })));
    }
  });
  function cleanSeo(c) {
    var o = { default_og_image: String(c.default_og_image || "").trim(), pages: {} };
    Object.keys(c.pages || {}).forEach(function (p) {
      var pg = {}, src = c.pages[p] || {};
      if (String(src.og_image || "").trim()) pg.og_image = String(src.og_image).trim();
      Object.keys(src).forEach(function (l) { if (l === "og_image" || !src[l] || typeof src[l] !== "object") return; var t = String(src[l].title || "").trim(), d = String(src[l].description || "").trim(); if (t || d) { pg[l] = {}; if (t) pg[l].title = t; if (d) pg[l].description = d; } });
      if (Object.keys(pg).length) o.pages[p] = pg;
    });
    return o;
  }
  function seoAuto(page, code) {
    var s = so.site, t = so.i18n[code] || {}, en = so.i18n.en || {}, m = t.meta || {}, em = en.meta || {};
    var tagline = code === "en" || s.tagline !== em.tagline ? s.tagline : m.tagline, desc = code === "en" || s.description !== em.description ? s.description : m.description;
    if (page === "home") return { title: (s.product_name || "") + " — " + (tagline || ""), description: desc || "" };
    if (page === "pricing") return { title: ((t.pricing || {}).title || "Pricing") + " · " + (s.product_name || ""), description: (t.pricing || {}).description || "" };
    var fm = so.fm[page] || {}; return { title: (fm.title || page) + " · " + (s.product_name || ""), description: fm.description || desc || "" };
  }
  function seoChanged() { secSeo.check(); seoSnippet(); }
  function renderSeo() {
    var b = $("seoForm"); b.textContent = "";
    b.appendChild(fieldRow("Default sharing image (all pages)", imageField(so.cur.default_og_image, function (v) { so.cur.default_og_image = v; seoChanged(); }, { id: "seoDefImg", placeholder: "Empty = the logo" }), "Shown when a page is shared on social media or in chats. Best size 1200 × 630.", true));
    var seg = el("div", { class: "cp-seg", id: "seoPick" });
    SEO_PAGES.forEach(function (pg) { seg.appendChild(el("button", { type: "button", "data-seo": pg[0], "aria-pressed": so.page === pg[0] ? "true" : "false", onclick: function () { so.page = pg[0]; if (pg[0] !== "home" && pg[0] !== "pricing") so.code = "en"; renderSeo(); } }, [pg[1]])); });
    b.appendChild(seg);
    var multi = so.page === "home" || so.page === "pricing";
    if (multi) { var ls = el("select", { id: "seoLang", "aria-label": "Language" }); fillLangSelect(ls, so.code); ls.addEventListener("change", function () { so.code = ls.value; renderSeo(); }); b.appendChild(el("label", { class: "cp-field cp-inline" }, [el("span", { text: "Language" }), ls])); }
    else b.appendChild(el("p", { class: "muted small", text: "Policies are in English only." }));
    var pg = so.cur.pages[so.page] || (so.cur.pages[so.page] = {}), lv = pg[so.code] || (pg[so.code] = {}), auto = seoAuto(so.page, so.code), dir = langDir(so.code);
    var g = el("div", { class: "cp-form" });
    var tIn = textInput(lv.title, function (v) { lv.title = v; cnt(tIn, tC, 60); seoChanged(); }, { id: "seoTitle", placeholder: auto.title, dir: dir }), tC = el("span", { class: "cp-count-chars" });
    var dIn = textInput(lv.description, function (v) { lv.description = v; cnt(dIn, dC, 160); seoChanged(); }, { id: "seoDesc", multiline: true, placeholder: auto.description, dir: dir }), dC = el("span", { class: "cp-count-chars" });
    function cnt(i, c, max) { var n = (i.value || i.placeholder).length; c.textContent = n + " / " + max; c.classList.toggle("over", n > max); }
    var tr1 = fieldRow("Title", tIn, "", true); tr1.appendChild(tC); g.appendChild(tr1);
    var dr1 = fieldRow("Description", dIn, "", true); dr1.appendChild(dC); g.appendChild(dr1);
    g.appendChild(fieldRow("Sharing image for this page", imageField(pg.og_image, function (v) { pg.og_image = v; seoChanged(); }, { id: "seoImg", placeholder: "Empty = the default image" }), "", true));
    b.appendChild(g); cnt(tIn, tC, 60); cnt(dIn, dC, 160);
    b.appendChild(el("h3", { text: "Google preview" })); b.appendChild(el("div", { class: "cp-snippet", id: "seoSnip" }));
    seoSnippet();
  }
  function seoSnippet() {
    var box = $("seoSnip"); if (!box) return;
    var pg = so.cur.pages[so.page] || {}, lv = pg[so.code] || {}, auto = seoAuto(so.page, so.code);
    var title = String(lv.title || "").trim() || auto.title, desc = String(lv.description || "").trim() || auto.description;
    var path = SEO_PAGES.filter(function (x) { return x[0] === so.page; })[0][2], url = "aichatsaver.github.io" + ((so.code !== "en" && (so.page === "home" || so.page === "pricing")) ? "/" + so.code : "") + (path === "/" ? "" : path);
    var img = imgSrc(pg.og_image || so.cur.default_og_image || "/assets/images/logo.png");
    box.textContent = ""; box.setAttribute("dir", langDir(so.code) || "ltr");
    box.appendChild(el("div", { class: "cp-snip-url" }, [el("img", { src: "/assets/images/logo.svg", alt: "", width: "18", height: "18" }), el("span", { text: url.replace(/\//g, " › ").replace(" › ", " › ") })]));
    box.appendChild(el("div", { class: "cp-snip-title", text: title.length > 62 ? title.slice(0, 60) + "…" : title }));
    box.appendChild(el("div", { class: "cp-snip-desc", text: desc.length > 162 ? desc.slice(0, 158) + " …" : desc }));
    box.appendChild(el("div", { class: "cp-snip-og" }, [el("img", { src: img, alt: "" }), el("div", {}, [el("b", { text: title }), el("span", { text: desc })])]));
  }

  /* ---------- Languages ---------- */
  var lg = { orig: null, cur: null, data: {} };
  var secLangs = defineSection("langs", {
    label: "Languages", files: function () { return ["_data/languages.yml"]; }, page: function () { return "/"; }, history: function () { return "_data/languages.yml"; },
    load: async function (force) {
      await loadLangs(force);
      lg.orig = {}; LANGS.forEach(function (l) { lg.orig[l.code] = l.enabled !== false; }); lg.cur = clone(lg.orig);
      for (var i = 0; i < LANGS.length; i++) { try { lg.data[LANGS[i].code] = (await effYaml(i18nPath(LANGS[i].code), force)) || {}; } catch (e) { lg.data[LANGS[i].code] = null; } }
      lg.auto = await readAuto();
      renderLangs();
    },
    validate: function () { return lg.cur.en === false ? "English can’t be switched off." : ""; },
    changes: function () {
      var out = [], ops = [];
      Object.keys(lg.cur).forEach(function (c) {
        if (c === "en" || lg.cur[c] === lg.orig[c]) return;
        ops.push({ t: "lang", code: c, on: lg.cur[c] });
        ["index.html", "pricing.html"].forEach(function (f) { out.push({ path: c + "/" + f, ops: [{ t: "fm", key: "published", value: lg.cur[c] ? null : "false" }] }); });
      });
      return ops.length ? [{ path: "_data/languages.yml", ops: ops }].concat(out) : [];
    }
  });
  function langReport(code) {
    var en = lg.data.en || {}, t = lg.data[code] || {}, missing = [], same = [];
    flatten(en, []).forEach(function (f) {
      var v = getAt(t, f.path), key = f.path.join(".");
      if (v === undefined || v === null || v === "") { if (f.value !== "" && f.value != null) missing.push(key); }
      else if (code !== "en" && typeof v === "string" && v === f.value && /[A-Za-z]{3,}/.test(v.replace(/%[a-z_]+%|<[^>]+>|AI Chat Saver|Pro|Free|https?:\S+/g, "")) && v.split(/\s+/).length > 1) same.push(key);
    });
    return { missing: missing, same: same, auto: (lg.auto[code] || []).length };
  }
  function renderLangs() {
    var b = $("langsForm"); b.textContent = "";
    var tbl = el("div", { class: "cp-langs" });
    LANGS.forEach(function (l) {
      var rep = l.code === "en" ? { missing: [], same: [], auto: 0 } : langReport(l.code);
      var sw = checkInput(lg.cur[l.code], function (v) { lg.cur[l.code] = v; row.classList.toggle("off", !v); secLangs.check(); }, l.code === "en" ? "Always on" : "On");
      var inp = sw.querySelector("input"); inp.id = "lang_" + l.code; if (l.code === "en") inp.disabled = true;
      var row = el("div", { class: "cp-lang-row" + (lg.cur[l.code] ? "" : " off"), "data-lang": l.code }, [
        el("div", { class: "cp-lang-name" }, [el("b", { text: l.name, lang: l.hreflang, dir: l.dir || null }), el("span", { class: "muted small", text: " " + l.code + (l.dir === "rtl" ? " · right-to-left" : "") + " · " + (l.code === "en" ? "/" : "/" + l.code + "/") })]),
        sw,
        el("div", { class: "cp-lang-stats" }, l.code === "en" ? [el("span", { class: "muted small", text: "Main language" })] : [
          el("span", { class: "cp-pill " + (rep.missing.length ? "errored" : "built"), text: rep.missing.length + " missing" }),
          el("span", { class: "cp-pill " + (rep.same.length ? "queued" : "built"), text: rep.same.length + " same as English" }),
          rep.auto ? el("span", { class: "cp-pill", text: rep.auto + " auto-translated" }) : null
        ])
      ]);
      tbl.appendChild(row);
      if (rep.missing.length || rep.same.length) {
        var det = el("details", { class: "cp-lang-rep" }, [el("summary", { text: "Show keys to translate (" + (rep.missing.length + rep.same.length) + ")" })]);
        var ul = el("ul", {});
        rep.missing.map(function (k) { return [k, "missing"]; }).concat(rep.same.map(function (k) { return [k, "same as English"]; })).forEach(function (x) {
          ul.appendChild(el("li", {}, [el("code", { text: x[0] }), el("span", { class: "muted small", text: " " + x[1] + " " }), el("button", { type: "button", class: "cp-link", onclick: function () { gotoTranslation(l.code, x[0]); } }, ["Edit"])]));
        });
        det.appendChild(ul); tbl.appendChild(det);
      }
    });
    b.appendChild(tbl);
  }

  /* ---------- Maintenance mode ---------- */
  var mt = { orig: null, cur: null, en: {} };
  var secMaint = defineSection("maint", {
    label: "Maintenance mode", files: function () { return ["_data/maintenance.yml"]; }, page: function () { return "/"; }, history: function () { return "_data/maintenance.yml"; },
    load: async function (force) {
      mt.orig = Object.assign({ enabled: false, title: "", message: "" }, (await effYaml("_data/maintenance.yml", force)) || {}); mt.cur = clone(mt.orig);
      mt.en = (((await effYaml(i18nPath("en"), force)) || {}).maint) || {}; mt.site = (await effYaml(SITE_PATH)) || {};
      renderMaint(); maintPreview();
    },
    validate: function () {
      if ([mt.cur.title, mt.cur.message].some(function (s) { return /[<>]/.test(s || ""); })) return "Plain text only (no < or >).";
      if (mt.cur.enabled && !mt.orig.enabled && !confirm("Turn maintenance mode on? Every public page will show the “back soon” page until you turn it off.")) return "Not saved — maintenance mode stays off.";
      return "";
    },
    changes: function () { var c = { enabled: !!mt.cur.enabled, title: String(mt.cur.title || "").trim(), message: String(mt.cur.message || "").trim() }; return yamlKeyChanges("_data/maintenance.yml", c, { enabled: !!mt.orig.enabled, title: mt.orig.title || "", message: mt.orig.message || "" }); }
  });
  function maintChanged() { secMaint.check(); maintPreview(); }
  function renderMaint() {
    var b = $("maintForm"); b.textContent = "";
    var on = checkInput(mt.cur.enabled, function (v) { mt.cur.enabled = v; maintChanged(); }, "Maintenance mode is on (the public site shows “back soon”)"); on.querySelector("input").id = "maintOn";
    b.appendChild(el("div", { class: "cp-field" }, [on]));
    var g = el("div", { class: "cp-form" });
    g.appendChild(fieldRow("Title", textInput(mt.cur.title, function (v) { mt.cur.title = v; maintChanged(); }, { id: "maintTitle", placeholder: mt.en.title || "" }), "Empty = the translated default shown in grey (each language gets its own)."));
    g.appendChild(fieldRow("Message", textInput(mt.cur.message, function (v) { mt.cur.message = v; maintChanged(); }, { id: "maintMsg", multiline: true, placeholder: mt.en.message || "" }), "Your own title or message is shown as typed in every language.", true));
    b.appendChild(g);
  }
  function maintPreview() {
    var p = $("maintPrev"); p.textContent = "";
    if (!mt.cur.enabled) p.appendChild(el("p", { class: "muted small", text: "Maintenance mode is off. This is the page visitors would see:" }));
    p.appendChild(el("div", { class: "cp-prev-root" }, [el("div", { class: "wrap narrow maint-box" }, [
      el("img", { class: "hero-logo", src: "/assets/images/logo.svg", width: "96", height: "96", alt: "" }),
      el("h1", { text: mt.cur.title || mt.en.title || "" }), el("p", { class: "lede", text: mt.cur.message || mt.en.message || "" }),
      el("p", { class: "muted", text: (mt.site && mt.site.support_email) || "" })
    ])]));
  }

  /* ---------- Coupon / Deal (_data/coupon.yml) ----------
     The site pre-applies a Freemius coupon code (?coupon=) on the checkout links of the chosen plans, only between
     the start and end (checked in the visitor's browser). Discount and redemption limit live in Freemius. */
  var COUPON_PATH = "_data/coupon.yml";
  var CP_CYCLES = [["yearly", "Pro Yearly"], ["monthly", "Pro Monthly"], ["lifetime", "Lifetime"]];
  var CP_BILLING = { yearly: "annual", monthly: "monthly", lifetime: "lifetime" };
  var CP_TEXT_MAPS = [["deal_text", "deal_texts"], ["button_text", "button_texts"], ["note_text", "note_texts"]];
  var CP_DEFAULT = { enabled: false, code: "", cycles: ["yearly", "monthly", "lifetime"], deal_text: "", deal_texts: {}, starts: "", ends: "", limit: "", lifetime_card: false, banner: true, banner_cycle: "yearly", color: "#c2410c", text_color: "#ffffff", button_text: "Get the deal", button_texts: {}, note_text: "Coupon %code% applied at checkout", note_texts: {} };
  var cp = { orig: null, cur: null, pz: null };
  function cpCodeOk(c) { return /^[A-Za-z0-9_-]{1,40}$/.test(String(c || "")); }
  function cpTime(v) { if (!v) return null; var n = Date.parse(v); return isNaN(n) ? NaN : n; }
  // Same rule the public page uses: on, valid code, now >= starts (if set) and now < ends (if set).
  function cpStatus(c, now) {
    now = now == null ? Date.now() : now;
    if (!c || !c.enabled) return { k: "off", t: "Off — the site doesn’t apply a coupon" };
    if (!cpCodeOk(c.code)) return { k: "bad", t: "Not applied — the code is missing or not valid" };
    var s = cpTime(c.starts), e = cpTime(c.ends);
    if (s !== null && isNaN(s) || e !== null && isNaN(e)) return { k: "bad", t: "Not applied — a date isn’t valid" };
    if (s !== null && now < s) return { k: "soon", t: "Scheduled — starts " + new Date(s).toLocaleString() };
    if (e !== null && now >= e) return { k: "ended", t: "Ended " + new Date(e).toLocaleString() + " — the site no longer applies it" };
    return { k: "live", t: "Live — buy buttons open the checkout with " + c.code + (e !== null ? " until " + new Date(e).toLocaleString() : "") };
  }
  function tzLabel(d) { var o = -(d || new Date()).getTimezoneOffset(), a = Math.abs(o); return "UTC" + (o < 0 ? "−" : "+") + String(Math.floor(a / 60)).padStart(2, "0") + ":" + String(a % 60).padStart(2, "0"); }
  function isoToLocalInput(v) {
    var n = cpTime(v); if (n === null || isNaN(n)) return "";
    var d = new Date(n), p = function (x) { return String(x).padStart(2, "0"); };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  function localInputToIso(v) {
    if (!v) return "";
    var d = new Date(v); if (isNaN(d.getTime())) return "";
    var o = -d.getTimezoneOffset(), a = Math.abs(o), p = function (x) { return String(x).padStart(2, "0"); };
    return v.slice(0, 16) + (o < 0 ? "-" : "+") + p(Math.floor(a / 60)) + ":" + p(a % 60);
  }
  function cpCheckoutUrl(base, code, cycle) {
    try { var u = new URL(base); u.searchParams.set("coupon", code); u.searchParams.set("billing_cycle", CP_BILLING[cycle]); return u.toString(); } catch (e) { return ""; }
  }
  var secCoupon = defineSection("coupon", {
    label: "Coupon / Deal", files: function () { return [COUPON_PATH, "_data/pricing.yml"]; }, page: function () { return "/pricing.html"; }, history: function () { return COUPON_PATH; },
    load: async function (force) {
      await loadLangs(force);
      var raw = (await effYaml(COUPON_PATH, force)) || {};
      cp.orig = Object.assign({}, clone(CP_DEFAULT), raw);
      if (!Array.isArray(cp.orig.cycles)) cp.orig.cycles = [];
      CP_TEXT_MAPS.forEach(function (m) { if (!cp.orig[m[1]] || typeof cp.orig[m[1]] !== "object") cp.orig[m[1]] = {}; });
      ["code", "deal_text", "starts", "ends", "button_text", "note_text"].forEach(function (k) { cp.orig[k] = cp.orig[k] == null ? "" : String(cp.orig[k]); });
      cp.orig.limit = cp.orig.limit == null ? "" : String(cp.orig.limit);
      cp.cur = clone(cp.orig);
      cp.pz = Object.assign({}, PZ_DEFAULT, (await effYaml("_data/pricing.yml", force)) || {});
      renderCoupon(); couponPreview();
    },
    validate: function () {
      var c = cp.cur, code = String(c.code || "").trim();
      if (c.enabled && !code) return "Type the coupon code you created in Freemius, or switch the coupon off.";
      if (code && !cpCodeOk(code)) return "The coupon code can only have letters, numbers, - and _ (up to 40).";
      if (c.enabled && !c.cycles.length) return "Pick at least one plan the coupon applies to.";
      var s = cpTime(c.starts), e = cpTime(c.ends);
      if (s !== null && isNaN(s)) return "The start date isn’t valid.";
      if (e !== null && isNaN(e)) return "The end date isn’t valid.";
      if (s !== null && e !== null && e <= s) return "The end must be after the start.";
      if (c.enabled && e !== null && e <= Date.now()) return "The end date is already past. Pick a later end, clear it, or switch the coupon off.";
      if (String(c.limit || "").trim() && !/^[1-9][0-9]{0,6}$/.test(String(c.limit).trim())) return "The limit must be a whole number, such as 100 (or leave it empty).";
      if (String(c.deal_text || "").length > 220) return "Keep the deal text under 220 characters.";
      if (c.enabled && c.banner && !String(c.deal_text || "").trim()) return "Write the deal text for the top banner, or switch the banner off.";
      if (c.enabled && c.banner && c.cycles.indexOf(c.banner_cycle) < 0) return "The banner button must open one of the plans the coupon applies to.";
      if (c.enabled && c.lifetime_card && c.cycles.indexOf("lifetime") < 0) return "The deal-only Lifetime card needs “Lifetime” ticked under “Applies to”.";
      var bad = CP_TEXT_MAPS.map(function (m) { return [c[m[0]]].concat(Object.keys(c[m[1]] || {}).map(function (l) { return c[m[1]][l]; })); }).reduce(function (a, b) { return a.concat(b); }, []).filter(function (v) { return unsafeHtml(v); })[0];
      if (bad != null) return "The texts can’t contain scripts or HTML tags.";
      if (!/^#[0-9a-f]{6}$/i.test(c.color)) return "Pick a banner colour.";
      return "";
    },
    changes: function () {
      var c = clone(cp.cur), o = cp.orig, keys = {};
      ["code", "deal_text", "button_text", "note_text", "limit", "starts", "ends"].forEach(function (k) { c[k] = String(c[k] == null ? "" : c[k]).trim(); });
      c.cycles = CP_CYCLES.map(function (x) { return x[0]; }).filter(function (k) { return c.cycles.indexOf(k) > -1; });
      c.text_color = contrastText(c.color);
      CP_TEXT_MAPS.forEach(function (m) {
        var map = {}, oldMap = o[m[1]] || {}, enChanged = c[m[0]] !== o[m[0]];
        Object.keys(c[m[1]] || {}).forEach(function (l) {
          var v = String(c[m[1]][l] || "").trim(); if (!v) return;
          // English changed: drop old translations (they'd describe the old deal) unless typed by hand in this edit.
          if (enChanged && v === oldMap[l]) return;
          map[l] = v;
        });
        c[m[1]] = map;
      });
      Object.keys(CP_DEFAULT).forEach(function (k) { if (!deepEq(c[k], o[k])) keys[k] = c[k]; });
      return Object.keys(keys).length ? [{ path: COUPON_PATH, ops: [{ t: "yset", keys: keys }] }] : [];
    }
  });
  function cpChanged() { secCoupon.check(); couponPreviewSoon(); }
  function renderCoupon() {
    var b = $("couponForm"), c = cp.cur, z = cp.pz; b.textContent = "";
    var g = el("div", { class: "cp-form" });
    var on = checkInput(c.enabled, function (v) { c.enabled = v; cpChanged(); }, "Apply a coupon on the website"); on.querySelector("input").id = "cpOn";
    g.appendChild(el("div", { class: "cp-field wide" }, [on, el("span", { class: "cp-help-text", id: "cpStatus" })]));
    g.appendChild(el("div", { class: "cp-banner warn wide", id: "cpFreemiusNote" }, [el("span", {}, [
      el("strong", { text: "Set the discount and the real limit in Freemius. " }),
      "Create the coupon in Freemius → Marketing → Coupons: the discount amount, the redemption limit (for example 100 uses), its plans and its own expiry are set there. The website can’t count how many people used a coupon — counting needs the Freemius secret key, which must never be on a public website. When Freemius’s limit is reached, the checkout simply refuses the code."
    ])]));
    if (!z.launched) g.appendChild(el("div", { class: "cp-banner wide", id: "cpNotLaunched" }, [el("span", { text: "Pro isn’t on sale yet (Pricing → “Pro is on sale” is off), so the buy buttons are inactive. The coupon starts working on them as soon as you launch." })]));
    g.appendChild(fieldRow("Coupon code", textInput(c.code, function (v) { c.code = v; cpChanged(); }, { id: "cpCode", maxlength: "40", spellcheck: "false", autocomplete: "off", placeholder: "e.g. LAUNCH20" }), "Exactly as you created it in Freemius. Letters, numbers, - and _ only."));
    var cyc = el("div", { class: "cp-checks", id: "cpCycles" });
    CP_CYCLES.forEach(function (x) {
      var lab = checkInput(c.cycles.indexOf(x[0]) > -1, function (v) { var i = c.cycles.indexOf(x[0]); if (v && i < 0) c.cycles.push(x[0]); if (!v && i > -1) c.cycles.splice(i, 1); renderBannerCycle(); cpChanged(); }, x[1]);
      lab.querySelector("input").id = "cpCyc_" + x[0]; cyc.appendChild(lab);
    });
    g.appendChild(el("div", { class: "cp-field" }, [el("span", { class: "cp-label", text: "Applies to" }), cyc, el("span", { class: "cp-help-text", text: "Buy buttons of these plans open the checkout with the code. Lifetime is used by the deal-only Lifetime card or a permanent Lifetime card." })]));
    g.appendChild(fieldRow("Deal text (optional)", textInput(c.deal_text, function (v) { c.deal_text = v; cpChanged(); }, { id: "cpText", maxlength: "220", placeholder: "Launch deal: Lifetime Pro $20, first %limit% people" }), "Shown in the top banner. %limit% = the limit below, %code% = the code. With auto-translate on, it’s translated into the other languages when you save.", true));
    g.appendChild(fieldRow("Limit shown in the text (optional)", textInput(c.limit, function (v) { c.limit = v; cpChanged(); }, { id: "cpLimit", inputmode: "numeric", maxlength: "7", placeholder: "e.g. 100" }), "Display only (fills %limit%). The real limit is the one you set in Freemius."));
    var tz = tzLabel();
    var st = el("input", { type: "datetime-local", id: "cpStart" }); st.value = isoToLocalInput(c.starts);
    st.addEventListener("input", function () { c.starts = localInputToIso(st.value); cpChanged(); });
    var en = el("input", { type: "datetime-local", id: "cpEnd" }); en.value = isoToLocalInput(c.ends);
    en.addEventListener("input", function () { c.ends = localInputToIso(en.value); cpChanged(); });
    g.appendChild(fieldRow("Starts (optional)", st, "Your time zone (" + tz + "). Empty = from now."));
    g.appendChild(fieldRow("Ends (optional)", en, "Your time zone (" + tz + "). After this, visitors’ browsers stop applying and showing the coupon by themselves. Set the same expiry in Freemius too."));
    var lt = checkInput(c.lifetime_card, function (v) { c.lifetime_card = v; cpChanged(); }, "Show a Lifetime card on the pricing page only while the deal runs"); lt.querySelector("input").id = "cpLifetime";
    var ltHelp = z.lifetime_enabled ? "A permanent Lifetime card is already on (Pricing), so this has no effect." : "Uses the Lifetime price and checkout link from Pricing" + ((/^\s*(tbd)?\s*$/i.test(String(z.price_lifetime || "")) || !String(z.checkout_lifetime || "").trim()) ? " — set them there first (price is " + (z.price_lifetime || "empty") + ", link " + (String(z.checkout_lifetime || "").trim() ? "set" : "empty") + ")." : ".");
    g.appendChild(el("div", { class: "cp-field wide" }, [el("span", { class: "cp-label", text: "Lifetime" }), lt, el("span", { class: "cp-help-text", id: "cpLifetimeHelp", text: ltHelp })]));
    var bn = checkInput(c.banner, function (v) { c.banner = v; cpChanged(); }, "Show the deal text in a banner at the top of every page, with a button to the checkout"); bn.querySelector("input").id = "cpBanner";
    g.appendChild(el("div", { class: "cp-field wide" }, [el("span", { class: "cp-label", text: "Top banner" }), bn, el("span", { class: "cp-help-text", text: "Hidden when the coupon is off, not started or ended. While it shows, it replaces the normal announcement bar. The button appears once Pro is on sale." })]));
    var bcWrap = el("span", { id: "cpBannerCycleWrap" });
    g.appendChild(fieldRow("Banner button opens", bcWrap));
    g.appendChild(fieldRow("Banner button text", textInput(c.button_text, function (v) { c.button_text = v; cpChanged(); }, { id: "cpBtnText", maxlength: "40" })));
    var sw = el("div", { class: "cp-swatches" });
    ANN_COLORS.forEach(function (k) { var bt = el("button", { type: "button", class: "cp-swatch", title: k[1], "aria-label": k[1], "aria-pressed": c.color.toLowerCase() === k[0] ? "true" : "false", onclick: function () { c.color = k[0]; col.value = k[0]; [].forEach.call(sw.querySelectorAll(".cp-swatch"), function (x) { x.setAttribute("aria-pressed", "false"); }); bt.setAttribute("aria-pressed", "true"); cpChanged(); } }); bt.style.setProperty("--sw", k[0]); sw.appendChild(bt); });
    var col = el("input", { type: "color", id: "cpColor", "aria-label": "Custom colour" }); col.value = c.color; col.addEventListener("input", function () { c.color = col.value; [].forEach.call(sw.querySelectorAll(".cp-swatch"), function (x) { x.setAttribute("aria-pressed", "false"); }); cpChanged(); });
    sw.appendChild(col);
    g.appendChild(fieldRow("Banner colour", sw, "The text colour is picked automatically for contrast."));
    g.appendChild(fieldRow("Note under the price", textInput(c.note_text, function (v) { c.note_text = v; cpChanged(); }, { id: "cpNote", maxlength: "80" }), "Shown under the price of each plan the coupon applies to. %code% = the code.", true));
    var det = el("details", { class: "cp-more wide" }, [el("summary", { text: "Texts in other languages (optional)" })]);
    det.appendChild(el("p", { class: "muted small", text: "Empty = translated automatically when you save the English (or the English is shown)." }));
    LANGS.filter(function (l) { return l.code !== "en"; }).forEach(function (l) {
      CP_TEXT_MAPS.forEach(function (m) {
        var lab = { deal_text: "Deal text", button_text: "Button", note_text: "Note" }[m[0]];
        det.appendChild(fieldRow(l.name + " (" + l.code + ") — " + lab, textInput((c[m[1]] || {})[l.code], function (v) { c[m[1]] = c[m[1]] || {}; c[m[1]][l.code] = v; cpChanged(); }, { id: "cp_" + m[1] + "_" + l.code, dir: l.dir || null, lang: l.hreflang, placeholder: "Empty = automatic" })));
      });
    });
    g.appendChild(det);
    b.appendChild(g);
    renderBannerCycle();
  }
  function renderBannerCycle() {
    var w = $("cpBannerCycleWrap"), c = cp.cur; if (!w) return; w.textContent = "";
    var opts = CP_CYCLES.filter(function (x) { return c.cycles.indexOf(x[0]) > -1; });
    if (!opts.length) { w.appendChild(el("span", { class: "muted small", text: "Tick a plan under “Applies to” first." })); return; }
    if (c.cycles.indexOf(c.banner_cycle) < 0) c.banner_cycle = opts[0][0];
    w.appendChild(selectInput(c.banner_cycle, opts.map(function (x) { return [x[0], x[1] + " checkout"]; }), function (v) { c.banner_cycle = v; cpChanged(); }, { id: "cpBannerCycle" }));
  }
  var couponPreviewSoon = debounce(function () { couponPreview(); }, 80);
  function couponPreview() {
    var c = cp.cur, z = cp.pz, p = $("couponPrev"); if (!p || !c) return; p.textContent = "";
    var stt = cpStatus(c), sEl = $("cpStatus");
    if (sEl) { sEl.textContent = stt.t; sEl.setAttribute("data-k", stt.k); }
    var code = String(c.code || "").trim();
    if (stt.k !== "live") p.appendChild(el("p", { class: "muted small", text: "Visitors don’t see this right now (" + stt.t.split(" — ")[0].toLowerCase() + "). This is how it looks while the deal runs:" }));
    var deal = String(c.deal_text || "").replace(/%code%/g, code || "CODE").replace(/%limit%/g, String(c.limit || "").trim());
    var root = el("div", { class: "cp-prev-root" });
    if (c.banner && deal) {
      var bar = el("div", { class: "announce deal" }, [el("div", { class: "wrap announce-row" }, [
        el("p", {}, [deal, z.launched ? el("a", { href: "#", class: "deal-btn", text: c.button_text || "Get the deal", onclick: function (e) { e.preventDefault(); } }) : null]),
        el("button", { type: "button", class: "announce-x", "aria-label": "Dismiss" }, ["✕"])
      ])]);
      bar.style.setProperty("--ann-bg", c.color); bar.style.setProperty("--ann-fg", contrastText(c.color));
      root.appendChild(bar);
    }
    var note = String(c.note_text || "").replace(/%code%/g, code || "CODE");
    var list = el("ul", { class: "cp-cplist", id: "cpUrls" });
    CP_CYCLES.forEach(function (x) {
      if (c.cycles.indexOf(x[0]) < 0) return;
      var base = String(z["checkout_" + x[0]] || "").trim();
      list.appendChild(el("li", {}, [el("strong", { text: x[1] + ": " }), base ? el("code", { text: cpCheckoutUrl(base, code || "CODE", x[0]) }) : el("span", { class: "muted", text: "no checkout link in Pricing yet" })]));
    });
    root.appendChild(el("p", { class: "coupon-note", text: note }));
    p.appendChild(root);
    p.appendChild(el("p", { class: "muted small", text: "Checkout links while the deal runs:" }));
    p.appendChild(list);
  }

  /* =====================================================================
     Tools: Dashboard, Drafts, Media library, History & undo, Backup, Search
     ===================================================================== */

  /* ---------- reading many files (blob cache) ---------- */
  var BLOBS = {}; // sha -> base64
  async function blobB64(sha) {
    if (BLOBS[sha]) return BLOBS[sha];
    var r = await gh(RP + "/git/blobs/" + sha); if (!r.ok) throw new Error(apiErr(r));
    return (BLOBS[sha] = String(r.data.content || "").replace(/\s+/g, ""));
  }
  async function pool(items, n, fn) { var i = 0, out = new Array(items.length); async function w() { while (i < items.length) { var k = i++; out[k] = await fn(items[k], k); } } var ws = []; for (var j = 0; j < Math.min(n, items.length); j++) ws.push(w()); await Promise.all(ws); return out; }
  // All text files of the site (not control/), with this browser's drafts applied.
  async function allTexts(force) {
    await getTree(force);
    var paths = treePaths(function (p) { return TEXT_EXT.test(p) && !/^control\//.test(p); }), map = {};
    await pool(paths, 6, async function (p) {
      var t = (TREE || []).filter(function (x) { return x.path === p; })[0], text = "";
      if (DOCS[p] && (!t || DOCS[p].sha === t.sha)) text = DOCS[p].text || "";
      else if (t) text = b64ToUtf8(await blobB64(t.sha));
      if (DRAFTS[p]) { var dr = DRAFTS[p]; text = dr.ops.some(function (o) { return o.t === "del"; }) ? null : applyOps(text, dr.ops.filter(function (o) { return o.t !== "b64"; })); }
      if (text != null) map[p] = text;
    });
    return map;
  }

  /* ---------- line diff ---------- */
  function lineDiff(a, b) {
    var A = String(a || "").replace(/\r\n/g, "\n").split("\n"), B = String(b || "").replace(/\r\n/g, "\n").split("\n");
    var pre = 0; while (pre < A.length && pre < B.length && A[pre] === B[pre]) pre++;
    var suf = 0; while (suf < A.length - pre && suf < B.length - pre && A[A.length - 1 - suf] === B[B.length - 1 - suf]) suf++;
    var a1 = A.slice(pre, A.length - suf), b1 = B.slice(pre, B.length - suf), n = a1.length, m = b1.length, ops = [];
    if (n * m > 4000000) { a1.forEach(function (l) { ops.push(["-", l]); }); b1.forEach(function (l) { ops.push(["+", l]); }); }
    else {
      var W = m + 1, L = new Uint32Array((n + 1) * W);
      for (var i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) L[i * W + j] = a1[i] === b1[j] ? L[(i + 1) * W + j + 1] + 1 : Math.max(L[(i + 1) * W + j], L[i * W + j + 1]);
      var x = 0, y = 0;
      while (x < n && y < m) { if (a1[x] === b1[y]) { ops.push([" ", a1[x]]); x++; y++; } else if (L[(x + 1) * W + y] >= L[x * W + y + 1]) ops.push(["-", a1[x++]]); else ops.push(["+", b1[y++]]); }
      while (x < n) ops.push(["-", a1[x++]]); while (y < m) ops.push(["+", b1[y++]]);
    }
    return A.slice(0, pre).map(function (l) { return [" ", l]; }).concat(ops, A.slice(A.length - suf).map(function (l) { return [" ", l]; }));
  }
  function renderDiff(box, a, b) {
    box.textContent = "";
    var d = lineDiff(a, b), changed = d.some(function (x) { return x[0] !== " "; });
    if (!changed) { box.appendChild(el("p", { class: "muted", text: "No differences." })); return; }
    var keep = d.map(function () { return false; });
    d.forEach(function (x, i) { if (x[0] !== " ") for (var k = Math.max(0, i - 3); k <= Math.min(d.length - 1, i + 3); k++) keep[k] = true; });
    var pre = el("pre", { class: "cp-diffpre" }), skipping = false, adds = 0, dels = 0;
    d.forEach(function (x, i) {
      if (x[0] === "+") adds++; if (x[0] === "-") dels++;
      if (!keep[i]) { if (!skipping) { pre.appendChild(el("span", { class: "cp-d-skip", text: "⋯\n" })); skipping = true; } return; }
      skipping = false; pre.appendChild(el("span", { class: x[0] === "+" ? "cp-d-add" : x[0] === "-" ? "cp-d-del" : "cp-d-ctx", text: x[0] + " " + x[1] + "\n" }));
    });
    box.appendChild(el("p", { class: "muted small" }, [el("span", { class: "cp-d-addtxt", text: "+" + adds }), " / ", el("span", { class: "cp-d-deltxt", text: "−" + dels }), " lines"]));
    box.appendChild(pre);
  }

  /* ---------- Dashboard ---------- */
  var SECTION_LINKS = [["home", "Homepage"], ["pricing", "Pricing"], ["coupon", "Coupon"], ["faq", "FAQ"], ["ais", "Supported AIs"], ["nav", "Navigation"], ["announce", "Announcement"], ["stores", "Store links"], ["seo", "SEO"], ["langs", "Languages"], ["i18n", "Translations"], ["media", "Media"], ["history", "History"], ["backup", "Backup"]];
  async function loadDash() {
    var top = $("dashTop"), list = $("dashChecklist"), q = $("dashQuick");
    q.textContent = "";
    SECTION_LINKS.forEach(function (s) { q.appendChild(el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { selectTab(s[0]); } }, [s[1]])); });
    q.appendChild(el("a", { class: "cp-btn small", href: bustUrl("/"), target: "_blank", rel: "noopener" }, ["View site"]));
    try {
      var s = (await effYaml(SITE_PATH)) || {}, z = Object.assign({}, PZ_DEFAULT, (await effYaml("_data/pricing.yml")) || {});
      var a = (await effYaml("_data/announcement.yml")) || {}, m = (await effYaml("_data/maintenance.yml")) || {};
      function unset(v) { var x = v == null ? "" : String(v).trim(); return !x || /^tbd$/i.test(x); }
      var items = [
        [!unset(s.price_monthly), "Pro Monthly price", "pricing"], [!unset(s.price_yearly), "Pro Yearly price", "pricing"],
        [!unset(s.chrome_store_url), "Chrome Web Store link", "stores"],
        [!unset(z.checkout_yearly), "Freemius checkout link — Pro Yearly", "pricing"], [!unset(z.checkout_monthly), "Freemius checkout link — Pro Monthly", "pricing"],
        [!unset(s.extension_version), "Extension version shown on the homepage", "stores"], [!!z.launched, "Pro is on sale (launch switch)", "pricing"]
      ];
      if (z.lifetime_enabled) items.push([!unset(z.price_lifetime), "Pro Lifetime price", "pricing"], [!unset(z.checkout_lifetime), "Freemius checkout link — Pro Lifetime", "pricing"]);
      list.textContent = "";
      items.forEach(function (it) { list.appendChild(el("li", { class: it[0] ? "done" : "todo" }, [el("span", { class: "cp-tick", "aria-hidden": "true", text: it[0] ? "✓" : "○" }), el("span", { text: it[1] + (it[0] ? "" : " — not set yet") }), it[0] ? null : el("button", { type: "button", class: "cp-link", onclick: function () { selectTab(it[2]); } }, ["Set it"])])); });
      top.textContent = "";
      var cells = [];
      cells.push(el("div", { class: "cp-dcell" }, [el("div", { class: "cp-label", text: "Site" }), el("span", { class: "cp-pill " + (m.enabled ? "errored" : "built"), text: m.enabled ? "Maintenance mode ON" : "Online" })]));
      cells.push(el("div", { class: "cp-dcell" }, [el("div", { class: "cp-label", text: "Announcement bar" }), el("span", { class: "cp-pill " + (a.enabled ? "queued" : ""), text: a.enabled ? "Showing" : "Off" })]));
      var cpd = (await effYaml(COUPON_PATH)) || {}, cps = cpStatus(cpd);
      cells.push(el("div", { class: "cp-dcell", id: "dashCoupon" }, [el("div", { class: "cp-label", text: "Coupon" }), el("button", { type: "button", class: "cp-link cp-pill " + ({ live: "built", soon: "queued", ended: "", bad: "errored", off: "" }[cps.k]), onclick: function () { selectTab("coupon"); } }, [{ live: "Live: " + cpd.code, soon: "Scheduled: " + cpd.code, ended: "Ended", bad: "Not valid", off: "Off" }[cps.k]])]));
      cells.push(el("div", { class: "cp-dcell" }, [el("div", { class: "cp-label", text: "Drafts waiting" }), el("button", { type: "button", class: "cp-link", onclick: function () { selectTab("drafts"); } }, [String(draftCount())])]));
      cells.push(el("div", { class: "cp-dcell" }, [el("div", { class: "cp-label", text: "Auto-translate" }), el("span", { class: "muted", text: !autoOn() ? "Off" : trSupported() ? "On" : "On, but this browser can’t translate (needs Chrome 138+)" })]));
      var bc = el("div", { class: "cp-dcell", id: "dashBuild" }, [el("div", { class: "cp-label", text: "Last site build" }), el("span", { class: "muted", text: "…" })]);
      var lc2 = el("div", { class: "cp-dcell wide", id: "dashLast" }, [el("div", { class: "cp-label", text: "Last change" }), el("span", { class: "muted", text: "…" })]);
      [bc].concat(cells, [lc2]).forEach(function (c) { top.appendChild(c); });
      var b = await gh(RP + "/pages/builds/latest"); if (!b.ok) b = await gh(RP + "/pages/builds/latest", { auth: false });
      bc.lastChild.replaceWith(b.ok && b.data ? el("span", { class: "cp-pill " + b.data.status, text: ({ built: "Live", building: "Building…", queued: "Queued", errored: "Build failed" }[b.data.status] || b.data.status) + (b.data.status === "errored" && b.data.error && b.data.error.message ? ": " + b.data.error.message : "") }) : el("span", { class: "muted", text: "unknown" }));
      var c = await gh(RP + "/commits?sha=" + BRANCH + "&per_page=1");
      if (c.ok && c.data[0]) lc2.lastChild.replaceWith(el("span", {}, [el("span", { text: (c.data[0].commit.message || "").split("\n")[0] + " — " }), el("time", { class: "muted", text: fmtDate(c.data[0].commit.committer.date) })]));
    } catch (e) { top.textContent = e.message; }
  }

  /* ---------- Drafts ---------- */
  function loadDrafts() {
    var box = $("draftList"); box.textContent = "";
    var paths = Object.keys(DRAFTS).sort();
    $("draftsPublish").disabled = !paths.length; $("draftsDiscard").disabled = !paths.length;
    if (!paths.length) { box.appendChild(el("p", { class: "muted", text: "No drafts. Use “Add to drafts” in any section to collect changes, then publish them here as one change (one site rebuild)." })); setState("draftsState", ""); return; }
    setState("draftsState", paths.length + " file" + (paths.length === 1 ? "" : "s") + " waiting to be published", "dirty");
    paths.forEach(function (p) {
      var d = DRAFTS[p], kind = d.ops.some(function (o) { return o.t === "del"; }) ? "delete" : d.ops.some(function (o) { return o.t === "b64"; }) ? "upload" : "edit";
      box.appendChild(el("div", { class: "cp-draft", "data-path": p }, [
        el("div", { class: "cp-draft-main" }, [el("code", { text: p }), el("span", { class: "muted small", text: " " + (kind === "delete" ? "delete" : kind === "upload" ? "new image" : "edit") + " · " + (d.labels || []).join(", ") + (d.at ? " · " + fmtDate(d.at) : "") })]),
        kind === "edit" ? el("button", { type: "button", class: "cp-btn ghost small", onclick: async function () { await doc(p); $("diffTitle").textContent = p; renderDiff($("diffBody"), DOCS[p].text || "", effText(p)); $("diffDlg").showModal(); } }, ["View changes"]) : null,
        el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { if (confirm("Discard the draft for " + p + "?")) { dropDraft(p); loadDrafts(); } } }, ["Discard"])
      ]));
    });
  }
  $("draftsPublish").addEventListener("click", async function () {
    var paths = Object.keys(DRAFTS); if (!paths.length) { setState("draftsState", "Nothing to publish"); return; }
    var btn = $("draftsPublish"); btn.disabled = true; setState("draftsState", "Publishing " + paths.length + " file" + (paths.length === 1 ? "" : "s") + " as one change…");
    try {
      await Promise.all(paths.map(function (p) { return doc(p).catch(function () {}); }));
      var msg = $("draftMsg").value.trim() || "Admin: publish " + paths.length + " change" + (paths.length === 1 ? "" : "s");
      var res = await commitChanges(paths.map(function (p) { return { path: p, ops: [] }; }), paths.length === 1 && !$("draftMsg").value.trim() ? "Admin: update " + paths[0] : msg, "/");
      $("draftMsg").value = ""; loadDrafts();
      setState("draftsState", res.commit ? "Published as one change. " + LIVE_NOTE : "Nothing changed — the site already had these.", "ok");
    } catch (e) { setState("draftsState", e.message, "err"); toast(e.message, "err"); loadDrafts(); setState("draftsState", e.message, "err"); }
    finally { btn.disabled = !draftCount(); }
  });
  $("draftsDiscard").addEventListener("click", function () {
    if (!draftCount() || !confirm("Discard all " + draftCount() + " drafts? This can’t be undone.")) return;
    Object.keys(DRAFTS).forEach(function (p) { delete DRAFTS[p]; bump(p); }); saveDrafts(); loadDrafts(); toast("Drafts discarded.");
  });

  /* ---------- Media library ---------- */
  var UPLOAD_DIR = "assets/images/uploads/", mediaQueue = [];
  async function loadMedia(force) {
    var g = $("mediaGrid"); setState("mediaState", "Loading…");
    try {
      var texts = await allTexts(force);
      var files = treePaths(function (p) { return p.indexOf(UPLOAD_DIR) === 0 && isImagePath(p); });
      g.textContent = "";
      if (!files.length) g.appendChild(el("p", { class: "muted", text: "No uploaded images yet." }));
      files.forEach(function (p) {
        var name = p.slice(UPLOAD_DIR.length), used = Object.keys(texts).filter(function (f) { return texts[f].indexOf("uploads/" + name) > -1; });
        var t = (TREE || []).filter(function (x) { return x.path === p; })[0], pending = DRAFTS[p] ? " (draft — not published yet)" : "";
        g.appendChild(el("div", { class: "cp-media-item", "data-path": p }, [
          el("img", { src: imgSrc("/" + p), alt: "", loading: "lazy" }),
          el("span", { class: "cp-media-name", text: name + pending }),
          el("span", { class: "muted small", text: (t && t.size ? fmtBytes(t.size) + " · " : "") + (used.length ? "Used in " + used.join(", ") : "Not used") }),
          el("div", { class: "cp-media-actions" }, [
            el("button", { type: "button", class: "cp-btn ghost small", onclick: function () { var v = "/" + p; (navigator.clipboard ? navigator.clipboard.writeText(v) : Promise.reject()).then(function () { toast("Copied " + v, "ok"); }, function () { prompt("Copy this path:", v); }); } }, ["Copy path"]),
            el("button", { type: "button", class: "cp-btn ghost small", disabled: used.length > 0, title: used.length ? "Used in " + used.join(", ") + " — remove it there first" : "Delete this image", onclick: function () { deleteMedia(p); } }, ["Delete"])
          ])
        ]));
      });
      setState("mediaState", files.length + " image" + (files.length === 1 ? "" : "s"));
    } catch (e) { setState("mediaState", e.message, "err"); loaded.media = false; }
  }
  async function deleteMedia(p) {
    if (!confirm("Delete " + p + "? You can restore it later from History.")) return;
    try { await commitChanges([{ path: p, ops: [{ t: "del" }] }], "Admin: delete " + p, "/"); TREE = null; await loadMedia(true); }
    catch (e) { toast(e.message, "err"); }
  }
  async function readQueue() {
    var fs = [].slice.call($("mediaFile").files || []), msg = $("mediaMsg"), ok = [], errs = [];
    for (var i = 0; i < fs.length; i++) { try { ok.push(await readImage(fs[i])); } catch (e) { errs.push(String(e.message || e)); } }
    msg.className = "cp-msg"; msg.textContent = errs.join(" ");
    return ok;
  }
  async function mediaGo(draft) {
    var ims = await readQueue(); if (!ims.length) { if (!$("mediaMsg").textContent) $("mediaMsg").textContent = "Choose one or more images first."; return; }
    try { await getTree(true); } catch (e) {}
    var taken = {}, ch = ims.map(function (im) { var p = uniqueUploadPath(im.name, im.ext), base = p, n = 2; while (taken[p]) p = base.replace(/\.(\w+)$/, "-" + (n++) + ".$1"); taken[p] = 1; return { path: p, ops: [{ t: "b64", b64: im.b64, isNew: true }] }; });
    if (draft) { ch.forEach(function (c) { stageOps(c.path, c.ops, "Media library"); }); toast(ch.length + " image" + (ch.length === 1 ? "" : "s") + " added to drafts.", "ok"); }
    else {
      var b = $("mediaUpload"); b.disabled = true; setState("mediaState", "Uploading…");
      try { await commitChanges(ch, ch.length === 1 ? "Admin: upload " + ch[0].path : "Admin: upload " + ch.length + " images", "/"); TREE = null; }
      catch (e) { setState("mediaState", e.message, "err"); toast(e.message, "err"); b.disabled = false; return; }
      b.disabled = false;
    }
    $("mediaFile").value = ""; var m = $("mediaMsg"); m.className = "cp-msg ok"; m.textContent = ch.map(function (c) { return "/" + c.path; }).join("  ");
    await loadMedia(!draft);
  }
  $("mediaUpload").addEventListener("click", function () { mediaGo(false); });
  $("mediaDraft").addEventListener("click", function () { mediaGo(true); });
  $("mediaReload").addEventListener("click", function () { TREE = null; loadMedia(true); });

  /* ---------- History & undo ---------- */
  var hs = { path: "", commits: [], sel: null, mode: "change", thisText: null, thisB64: null, parentText: null, missing: false };
  async function loadHistoryTab() {
    var sel = $("histFile");
    try { await getTree(); } catch (e) { setState("histState", e.message, "err"); loaded.history = false; return; }
    var cur = hs.path || sel.value; sel.textContent = ""; sel.appendChild(el("option", { value: "", text: "Choose a file…" }));
    treePaths(function (p) { return !/^control\//.test(p); }).forEach(function (p) { sel.appendChild(el("option", { value: p, text: p })); });
    if (cur && !sel.querySelector('option[value="' + cur.replace(/"/g, "") + '"]')) sel.appendChild(el("option", { value: cur, text: cur + " (deleted)" }));
    sel.value = cur || "";
    if (cur) await loadHist(cur);
  }
  function openHistory(path) { hs.path = path || ""; selectTab("history"); if (loaded.history) loadHistoryTab(); }
  $("histFile").addEventListener("change", function () { hs.path = $("histFile").value; if (hs.path) loadHist(hs.path); });
  async function loadHist(path) {
    var list = $("histList"); list.textContent = ""; hs.sel = null; $("histRestore").disabled = $("histDraft").disabled = true;
    $("histDiff").textContent = ""; $("histDiff").appendChild(el("p", { class: "muted", text: "Choose a change on the left." }));
    setState("histState", "Loading…");
    var r = await gh(RP + "/commits?sha=" + BRANCH + "&path=" + encodeURIComponent(path) + "&per_page=30");
    if (!r.ok) { setState("histState", apiErr(r), "err"); return; }
    hs.commits = r.data; setState("histState", r.data.length ? r.data.length + " recent change" + (r.data.length === 1 ? "" : "s") : "No history for this file.");
    r.data.forEach(function (c, i) {
      list.appendChild(el("li", {}, [el("button", { type: "button", class: "cp-hist-item", "data-sha": c.sha, onclick: function () { pickVersion(i); } }, [
        el("code", { text: c.sha.slice(0, 7) }), el("span", { class: "msg", text: (c.commit.message || "").split("\n")[0] + (i === 0 ? " (current)" : "") }), el("time", { text: fmtDate(c.commit.committer.date) })
      ])]));
    });
  }
  async function textAt(path, ref) { var d = await fetchDoc(path, ref); return d; }
  async function pickVersion(i) {
    var c = hs.commits[i]; hs.sel = c;
    [].forEach.call(document.querySelectorAll(".cp-hist-item"), function (b) { b.classList.toggle("on", b.getAttribute("data-sha") === c.sha); });
    setState("histState", "Loading version " + c.sha.slice(0, 7) + "…");
    try {
      var v = await textAt(hs.path, c.sha); hs.thisText = v.text; hs.thisB64 = v.b64; hs.missing = v.missing;
      var parent = c.parents && c.parents[0] ? await textAt(hs.path, c.parents[0].sha) : { text: "", missing: true };
      hs.parentText = parent.missing ? "" : parent.text;
      await doc(hs.path, true);
      showHistDiff();
      var isCurrent = !hs.missing && DOCS[hs.path] && DOCS[hs.path].sha === v.sha;
      $("histRestore").disabled = $("histDraft").disabled = hs.missing || isCurrent;
      setState("histState", hs.missing ? "This change deleted the file; pick an earlier change to restore it." : isCurrent ? "This is the current version." : "Version " + c.sha.slice(0, 7) + " from " + fmtDate(c.commit.committer.date) + ".");
    } catch (e) { setState("histState", e.message, "err"); }
  }
  function showHistDiff() {
    var box = $("histDiff");
    [].forEach.call(document.querySelectorAll("#histMode button"), function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-mode") === hs.mode ? "true" : "false"); });
    if (!hs.sel) return;
    if (!isTextPath(hs.path)) { box.textContent = ""; box.appendChild(el("p", { class: "muted", text: "This is an image, so there is no text to compare." })); if (!hs.missing && isImagePath(hs.path)) box.appendChild(el("img", { class: "cp-hist-img", src: "data:" + mimeOf(hs.path) + ";base64," + hs.thisB64, alt: "" })); return; }
    if (hs.mode === "change") renderDiff(box, hs.parentText, hs.missing ? "" : hs.thisText);
    else renderDiff(box, hs.missing ? "" : hs.thisText, DOCS[hs.path] ? DOCS[hs.path].text : "");
  }
  [].forEach.call(document.querySelectorAll("#histMode button"), function (b) { b.addEventListener("click", function () { hs.mode = b.getAttribute("data-mode"); showHistDiff(); }); });
  function restoreOps() { return isTextPath(hs.path) ? [{ t: "text", text: hs.thisText, base: DOCS[hs.path] ? DOCS[hs.path].sha : null }] : [{ t: "b64", b64: hs.thisB64 }]; }
  $("histRestore").addEventListener("click", async function () {
    if (!hs.sel || hs.missing) return;
    if (!confirm("Restore " + hs.path + " to the version from " + fmtDate(hs.sel.commit.committer.date) + "? This saves it as a new change.")) return;
    var b = $("histRestore"); b.disabled = true; setState("histState", "Restoring…");
    try { await doc(hs.path, true); var res = await commitChanges([{ path: hs.path, ops: restoreOps() }], "Admin: restore " + hs.path + " to " + hs.sel.sha.slice(0, 7), "/"); await loadHist(hs.path); setState("histState", res.commit ? "Restored as a new change. " + LIVE_NOTE : "Already the same as that version.", "ok"); }
    catch (e) { setState("histState", e.message, "err"); b.disabled = false; }
  });
  $("histDraft").addEventListener("click", async function () {
    if (!hs.sel || hs.missing) return;
    await doc(hs.path, true); stageOps(hs.path, restoreOps(), "Restore " + hs.sel.sha.slice(0, 7));
    setState("histState", "Added to drafts. Publish it from Drafts.", "ok"); toast("Restore added to drafts.", "ok");
  });

  /* ---------- Backup (ZIP made in the browser) ---------- */
  var CRC_T = (function () { var t = new Uint32Array(256); for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(u8) { var c = 0xffffffff; for (var i = 0; i < u8.length; i++) c = CRC_T[(c ^ u8[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
  function makeZip(files) { // [{name, data:Uint8Array}] -> Uint8Array (stored, no compression)
    var parts = [], central = [], off = 0, d = new Date();
    var dt = ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xffff, dd = (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xffff;
    files.forEach(function (f) {
      var name = new TextEncoder().encode(f.name), crc = crc32(f.data), h = new DataView(new ArrayBuffer(30));
      h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, 0, true); h.setUint16(10, dt, true); h.setUint16(12, dd, true);
      h.setUint32(14, crc, true); h.setUint32(18, f.data.length, true); h.setUint32(22, f.data.length, true); h.setUint16(26, name.length, true); h.setUint16(28, 0, true);
      parts.push(new Uint8Array(h.buffer), name, f.data);
      var c = new DataView(new ArrayBuffer(46));
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true); c.setUint16(12, dt, true); c.setUint16(14, dd, true);
      c.setUint32(16, crc, true); c.setUint32(20, f.data.length, true); c.setUint32(24, f.data.length, true); c.setUint16(28, name.length, true); c.setUint32(42, off, true);
      central.push(new Uint8Array(c.buffer), name);
      off += 30 + name.length + f.data.length;
    });
    var csize = central.reduce(function (a, b) { return a + b.length; }, 0), e = new DataView(new ArrayBuffer(22));
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true); e.setUint32(12, csize, true); e.setUint32(16, off, true);
    var all = parts.concat(central, [new Uint8Array(e.buffer)]), len = all.reduce(function (a, b) { return a + b.length; }, 0), out = new Uint8Array(len), p = 0;
    all.forEach(function (b) { out.set(b, p); p += b.length; });
    return out;
  }
  $("backupBtn").addEventListener("click", async function () {
    var btn = $("backupBtn"), msg = $("backupMsg"), everything = $("backupAll").checked; btn.disabled = true; msg.className = "cp-msg ok"; msg.textContent = "Reading the file list…";
    try {
      TREE = null; await getTree(true);
      var items = TREE.filter(function (t) { return t.path !== VAULT_PATH && (everything ? true : /^(_data\/|pages\/|assets\/images\/uploads\/)/.test(t.path)); });
      var n = 0, files = await pool(items, 6, async function (t) { var b = await blobB64(t.sha); msg.textContent = "Downloading " + (++n) + " of " + items.length + "…"; return { name: t.path, data: b64ToBytes(b) }; });
      var zip = makeZip(files), day = new Date().toISOString().slice(0, 10);
      var a = el("a", { href: URL.createObjectURL(new Blob([zip], { type: "application/zip" })), download: "aichatsaver-site-backup-" + day + (everything ? "-full" : "") + ".zip" });
      document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
      msg.textContent = "Backup ready: " + files.length + " files, " + fmtBytes(zip.length) + ".";
    } catch (e) { msg.className = "cp-msg"; msg.textContent = e.message; }
    finally { btn.disabled = false; }
  });

  /* ---------- Global search ---------- */
  var SEARCH_ROUTE = { "_data/site.yml": "site", "_data/home.yml": "home", "_data/ais.yml": "ais", "_data/navigation.yml": "nav", "_data/pricing.yml": "pricing", "_data/coupon.yml": "coupon", "_data/announcement.yml": "announce", "_data/seo.yml": "seo", "_data/maintenance.yml": "maint", "_data/languages.yml": "langs" };
  var searchSeq = 0;
  async function runSearch(q) {
    var seq = ++searchSeq, box = $("searchResults"), info = $("searchInfo");
    selectTab("search"); box.textContent = ""; info.textContent = "Searching…";
    var texts; try { texts = await allTexts(false); } catch (e) { info.textContent = e.message; return; }
    if (seq !== searchSeq) return;
    var ql = q.toLowerCase(), res = [];
    Object.keys(texts).sort(function (a, b) { return (/^_data|^pages/.test(a) ? 0 : 1) - (/^_data|^pages/.test(b) ? 0 : 1) || a.localeCompare(b); }).forEach(function (p) {
      var t = texts[p];
      if (/\.ya?ml$/.test(p) && /^_data\//.test(p)) {
        var o = null; try { o = Y.load(t, YOPT); } catch (e) {}
        if (o && typeof o === "object") { flatten(o, []).forEach(function (f) { var k = f.path.join("."), v = f.value == null ? "" : String(f.value); if (v.toLowerCase().indexOf(ql) > -1 || k.toLowerCase() === ql) res.push({ path: p, key: k, text: v }); }); return; }
      }
      t.split("\n").forEach(function (ln, i) { if (ln.toLowerCase().indexOf(ql) > -1) res.push({ path: p, line: i + 1, text: ln.trim() }); });
    });
    info.textContent = res.length ? res.length + " result" + (res.length === 1 ? "" : "s") + " for “" + q + "”" + (res.length > 200 ? " (showing 200)" : "") : "Nothing found for “" + q + "”.";
    res.slice(0, 200).forEach(function (r) {
      var i = r.text.toLowerCase().indexOf(ql), s = Math.max(0, i - 60), snip = (s ? "…" : "") + r.text.slice(s, i + ql.length + 90) + (i + ql.length + 90 < r.text.length ? "…" : "");
      var li = el("li", {}, [el("button", { type: "button", class: "cp-result", onclick: function () { openResult(r); } }, [
        el("span", { class: "cp-result-where" }, [el("code", { text: r.path }), r.key ? el("span", { class: "muted small", text: " " + r.key }) : el("span", { class: "muted small", text: " line " + r.line })]),
        hlText(snip, q)
      ])]);
      box.appendChild(li);
    });
  }
  function hlText(s, q) { var span = el("span", { class: "cp-result-text" }), low = s.toLowerCase(), ql = q.toLowerCase(), i = 0, j; while ((j = low.indexOf(ql, i)) > -1) { span.appendChild(document.createTextNode(s.slice(i, j))); span.appendChild(el("mark", { text: s.slice(j, j + q.length) })); i = j + q.length; } span.appendChild(document.createTextNode(s.slice(i))); return span; }
  function openResult(r) {
    var m = /^_data\/i18n\/([\w-]+)\.yml$/.exec(r.path);
    if (m && r.key) return gotoTranslation(m[1], r.key);
    var pm = /^pages\/(privacy|terms|refund)\.md$/.exec(r.path);
    if (pm) { if (pol.name !== pm[1] && SECS.policies.dirty && !confirm("Discard your unsaved changes to this policy?")) return; pol.name = pm[1]; if (loaded.policies) { selectTab("policies"); SECS.policies.reload(false); } else selectTab("policies"); return; }
    var sec = SEARCH_ROUTE[r.path];
    if (sec) {
      selectTab(sec);
      if (sec === "site" && r.key) setTimeout(function () { var f = $("f_" + r.key.split(".")[0].replace(/[^\w]/g, "_")); if (f) { f.focus(); f.scrollIntoView({ block: "center" }); } }, 400);
      return;
    }
    gotoFile(r.path);
  }
  $("gSearch").addEventListener("input", debounce(function () { var q = $("gSearch").value.trim(); if (q.length >= 2) runSearch(q); }, 300));
  $("gSearch").addEventListener("keydown", function (e) { if (e.key === "Enter") { var q = $("gSearch").value.trim(); if (q.length >= 1) runSearch(q); } });
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


  var LOADERS = {
    dash: loadDash, drafts: loadDrafts,
    home: function () { return secHome.reload(false); }, pricing: function () { return secPricing.reload(false); }, coupon: function () { return secCoupon.reload(false); }, faq: function () { return secFaq.reload(false); }, ais: function () { return secAis.reload(false); },
    policies: function () { return secPol.reload(false); }, nav: function () { return secNav.reload(false); }, announce: function () { return secAnn.reload(false); },
    stores: function () { return secStores.reload(false); }, seo: function () { return secSeo.reload(false); }, langs: function () { return secLangs.reload(false); },
    i18n: function () { return secI18n.reload(false); }, maint: function () { return secMaint.reload(false); }, site: function () { return secSite.reload(false); },
    media: function () { return loadMedia(false); }, history: loadHistoryTab, backup: function () {}, search: function () {},
    files: async function () { await loadFilesTab(); if (file.path) await secFiles.reload(false); },
    status: loadStatus, security: function () {}
  };

  boot();
})();
