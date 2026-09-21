// SecureGate v3 – Scramjet + Wisp Proxy mit serverseitigem Passwortschutz
import { createServer } from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import { epoxyPath } from "@mercuryworkshop/epoxy-transport";

const publicPath = fileURLToPath(new URL("./public/", import.meta.url));

// ── PASSWORT ── in Render unter "Environment" als SG_PASSWORD setzen
const PASSWORD = process.env.SG_PASSWORD || "";
if (!PASSWORD) {
  console.warn("⚠  SG_PASSWORD ist nicht gesetzt – Login ist deaktiviert, bis du es in Render einträgst.");
}
const TOKEN = PASSWORD
  ? createHmac("sha256", PASSWORD).update("securegate-v3").digest("hex")
  : null;

// Token kommt im WebSocket-Pfad (/t/<token>/wisp/) oder als "Authorization: Bearer …" (API)
function tokenOk(t) {
  if (!TOKEN || !t || t.length !== TOKEN.length) return false;
  return timingSafeEqual(Buffer.from(t), Buffer.from(TOKEN));
}
function tokenFromReq(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : null;
}

function safeEqual(a, b) {
  const ha = createHmac("sha256", "cmp").update(String(a)).digest();
  const hb = createHmac("sha256", "cmp").update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

// Einfacher Brute-Force-Schutz: max. 10 Fehlversuche pro IP in 15 Minuten
const attempts = new Map();
function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;
}
function tooMany(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (Date.now() - a.first > 15 * 60 * 1000) { attempts.delete(ip); return false; }
  return a.count >= 10;
}
function recordFail(ip) {
  const a = attempts.get(ip);
  if (!a || Date.now() - a.first > 15 * 60 * 1000) attempts.set(ip, { first: Date.now(), count: 1 });
  else a.count++;
}

// ── WISP (der eigentliche Tunnel) ──
logging.set_level(logging.NONE);
Object.assign(wisp.options, {
  allow_udp_streams: false,
  allow_private_ips: false,      // kein Zugriff auf interne Render-Netze
  allow_loopback_ips: process.env.SG_TEST === "1", // nur für lokale Tests
  dns_method: "resolve",
  dns_servers: ["1.1.1.1", "1.0.0.1"],
  dns_result_order: "ipv4first", // Render hat kein IPv6 nach außen
});

const fastify = Fastify({
  trustProxy: true,
  serverFactory: (handler) =>
    createServer()
      .on("request", (req, res) => {
        // nötig für SharedArrayBuffer (Scramjet sync)
        res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        res.setHeader("Referrer-Policy", "no-referrer");
        // CORS, damit die Oberfläche auch von Netlify aus die API nutzen kann
        if (req.url.startsWith("/api/")) {
          res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
          res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
          res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
          res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
          res.setHeader("Vary", "Origin");
          if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
        }
        handler(req, res);
      })
      .on("upgrade", (req, socket, head) => {
        // Proxy-Tunnel NUR mit gültigem Login-Token
        // Format: /t/<token>/wisp/  (libcurl verlangt einen / am Ende)
        const m = req.url.split("?")[0].match(/^\/t\/([a-f0-9]+)\/wisp\/$/);
        if (m && tokenOk(m[1])) {
          wisp.routeRequest(req, socket, head);
        } else {
          socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
          socket.destroy();
        }
      }),
});

// ── LOGIN API ──
fastify.post("/api/login", async (req, reply) => {
  const ip = clientIp(req.raw);
  if (!TOKEN) return reply.code(503).send({ ok: false, error: "SG_PASSWORD fehlt auf dem Server" });
  if (tooMany(ip)) return reply.code(429).send({ ok: false, error: "Zu viele Versuche – warte 15 Minuten" });
  const pw = req.body && typeof req.body.password === "string" ? req.body.password : "";
  if (!safeEqual(pw, PASSWORD)) {
    recordFail(ip);
    return reply.code(401).send({ ok: false, error: "Falsches Passwort" });
  }
  attempts.delete(ip);
  return { ok: true, token: TOKEN };
});

fastify.get("/api/check", async (req) => ({ ok: tokenOk(tokenFromReq(req.raw)) }));

// ── STATISCHE DATEIEN ──
fastify.register(fastifyStatic, { root: publicPath, decorateReply: true });
fastify.register(fastifyStatic, { root: scramjetPath, prefix: "/scram/", decorateReply: false });
fastify.register(fastifyStatic, { root: libcurlPath, prefix: "/libcurl/", decorateReply: false });
fastify.register(fastifyStatic, { root: baremuxPath, prefix: "/baremux/", decorateReply: false });
fastify.register(fastifyStatic, { root: epoxyPath, prefix: "/epoxy/", decorateReply: false });

fastify.setNotFoundHandler((req, reply) => reply.code(404).type("text/plain").send("404"));

const port = parseInt(process.env.PORT || "8080", 10);
fastify.listen({ port, host: "0.0.0.0" }).then(() => {
  console.log(`SecureGate läuft auf Port ${port}`);
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => { fastify.close(); process.exit(0); });
}
