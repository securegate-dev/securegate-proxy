"use strict";
const $ = (id) => document.getElementById(id);

// ── SCRAMJET SETUP ──
const { ScramjetController } = $scramjetLoadController();
const scramjet = new ScramjetController({
  files: {
    wasm: "/scram/scramjet.wasm.wasm",
    all: "/scram/scramjet.all.js",
    sync: "/scram/scramjet.sync.js",
  },
});
const scramjetInit = Promise.resolve(scramjet.init());

const connection = new BareMux.BareMuxConnection("/baremux/worker.js");
// Leer = Proxy läuft auf derselben Domain. Für Netlify steht in config.js die Render-URL.
const SERVER = (window.SG_SERVER || location.origin).replace(/\/+$/, "");
const wsBase = SERVER.replace(/^http/, "ws");
const getToken = () => { try { return localStorage.getItem("sg_token") || ""; } catch { return ""; } };
const setToken = (t) => { try { t ? localStorage.setItem("sg_token", t) : localStorage.removeItem("sg_token"); } catch {} };
let frame = null;
let ready = null;

function setStatus(t, c) {
  $("stat-text").textContent = t;
  $("dot").className = "dot " + (c || "green");
}

function showError(title, sub) {
  $("err-title").textContent = "✕ " + title;
  $("err-sub").innerHTML = sub;
  $("fblock-err").classList.add("show");
  if (frame) frame.frame.style.display = "none";
  $("placeholder").style.display = "none";
  setStatus("✕ " + title, "red");
}
function hideError() { $("fblock-err").classList.remove("show"); }

async function setup() {
  if (!navigator.serviceWorker) {
    throw new Error("Service Worker nicht verfügbar – Seite muss über HTTPS laufen und darf nicht im privaten Modus von Firefox geöffnet sein.");
  }
  await scramjetInit;
  await navigator.serviceWorker.register("/sw.js");
  await navigator.serviceWorker.ready;
  await connection.setTransport("/libcurl/index.mjs", [
    { websocket: wsBase + "/t/" + encodeURIComponent(getToken()) + "/wisp/" },
  ]);
  $("wisp-state").textContent = "VERBUNDEN";

  frame = scramjet.createFrame();
  frame.frame.id = "sj-frame";
  $("barea").appendChild(frame.frame);

  frame.addEventListener("urlchange", (e) => {
    const u = String(e.url);
    if (document.activeElement !== $("urlinput")) $("urlinput").value = u;
    $("scheme-label").textContent = u.startsWith("https") ? "🔒 HTTPS" : "⚠ HTTP";
    try { setStatus("✓ " + new URL(u).hostname, "green"); } catch {}
  });
  frame.frame.addEventListener("load", () => {
    if ($("stat-text").textContent.startsWith("LADE")) setStatus("✓ GELADEN", "green");
  });
}

function ensureReady() {
  if (!ready) ready = setup().catch((err) => { ready = null; throw err; });
  return ready;
}

// ── URL / SUCHE ──
function toUrl(input) {
  input = input.trim();
  try { return new URL(input).toString(); } catch {}
  try {
    const u = new URL("https://" + input);
    if (u.hostname.includes(".") && !input.includes(" ")) return u.toString();
  } catch {}
  return $("engine").value.replace("%s", encodeURIComponent(input));
}

async function navigate() {
  const raw = $("urlinput").value;
  if (!raw.trim()) return;
  const url = toUrl(raw);
  hideError();
  setStatus("LADE " + url, "yellow");
  try {
    await ensureReady();
  } catch (err) {
    showError("PROXY NICHT BEREIT", String(err.message || err));
    return;
  }
  $("placeholder").style.display = "none";
  frame.frame.style.display = "block";
  document.body.classList.add("browsing");
  $("urlinput").value = url;
  frame.go(url);
}

// ── LOGIN ──
async function auth() {
  const btn = $("auth-btn");
  btn.disabled = true;
  try {
    const r = await fetch(SERVER + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("pw").value }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.ok) { setToken(d.token); return openApp(); }
    $("gerr").textContent = "✕ " + (d.error || "FEHLER").toUpperCase();
  } catch {
    $("gerr").textContent = "✕ SERVER NICHT ERREICHBAR (RENDER WACHT GERADE AUF? 30 SEK WARTEN)";
  } finally {
    btn.disabled = false;
  }
  $("pw").value = "";
  setTimeout(() => ($("gerr").textContent = ""), 3000);
}

function openApp() {
  $("gate").classList.add("gone");
  $("app").classList.add("on");
  $("urlinput").focus();
  ensureReady().catch((err) => showError("PROXY NICHT BEREIT", String(err.message || err)));
}

function logout() {
  setToken("");
  location.reload();
}

// ── EVENTS ──
$("auth-btn").onclick = auth;
$("pw").onkeydown = (e) => { if (e.key === "Enter") auth(); };
$("btn-go").onclick = navigate;
$("urlinput").onkeydown = (e) => { if (e.key === "Enter") navigate(); };
$("urlinput").onfocus = () => $("urlinput").select();
$("btn-back").onclick = () => frame && frame.back();
$("btn-fwd").onclick = () => frame && frame.forward();
$("btn-reload").onclick = () => frame && frame.reload();
$("btn-sett").onclick = () => $("spanel").classList.toggle("open");
$("btn-logout").onclick = logout;
$("btn-err-back").onclick = () => {
  hideError();
  if (frame && frame.frame.src) frame.frame.style.display = "block";
  else $("placeholder").style.display = "";
};
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "l") { e.preventDefault(); $("urlinput").focus(); }
});

try { const s = localStorage.getItem("sg_engine"); if (s) $("engine").value = s; } catch {}
$("engine").onchange = () => { try { localStorage.setItem("sg_engine", $("engine").value); } catch {} };

// Schon eingeloggt? Dann Gate überspringen
if (getToken()) {
  fetch(SERVER + "/api/check", { headers: { Authorization: "Bearer " + getToken() } })
    .then((r) => r.json())
    .then((d) => { if (d.ok) openApp(); else setToken(""); })
    .catch(() => {});
}
