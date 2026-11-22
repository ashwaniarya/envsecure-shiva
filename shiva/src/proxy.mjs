// Governance proxy in front of the (unchanged) Keysrs relay/gateway.
// Order for every request: pinned client cert (handshake) -> governance check -> single-use nonce + TTL -> audit write -> forward.
// Any failure before the forward returns a generic refusal and forwards nothing. There is no fallback path.
import https from "node:https";
import http from "node:http";
import { append } from "./audit.mjs";
import { fingerprint, sameFp } from "./tls.mjs";

const DENY = (res, status, body) => { if (!res.headersSent) { res.writeHead(status, { "content-type": "text/plain" }); } res.end(body); };
const HOP = new Set(["x-shiva-nonce", "x-shiva-agent", "x-shiva-command-hash", "connection", "host", "content-length"]);

export function createShivaProxy({ serverCert, serverKey, pinnedClientCert, upstream, grants, auditPath, check = async () => true, checkTimeoutMs = 2000, now = Date.now }) {
  const clientFp = fingerprint(pinnedClientCert);
  const up = new URL(upstream);

  const audit = (fields) => append(auditPath, fields, now); // throws on failure -> caller denies

  const server = https.createServer({
    cert: serverCert, key: serverKey,
    requestCert: true, rejectUnauthorized: false, // chain trust is replaced by the fingerprint pin below
    minVersion: "TLSv1.3",
  }, async (req, res) => {
    const peer = req.socket.getPeerCertificate();
    // Defence in depth: the pin is also enforced at connection time (below); a request never gets past here without it.
    if (!peer || !peer.raw || !sameFp(peer.fingerprint256, clientFp)) return DENY(res, 403, "refused");

    const keyName = (req.url || "/").split("/")[1] || "";
    const agent = String(req.headers["x-shiva-agent"] || "");
    const cmdHash = req.headers["x-shiva-command-hash"] ? String(req.headers["x-shiva-command-hash"]) : null; // recorded only; scope binding is phase two
    const nonce = req.headers["x-shiva-nonce"];
    let refusal;
    try {
      let allowed = false;
      try {
        allowed = await Promise.race([
          Promise.resolve(check({ key: keyName, agent, cmdHash })),
          new Promise((_, rej) => setTimeout(() => rej(new Error("governance timeout")), checkTimeoutMs).unref()),
        ]) === true;
      } catch { refusal = "governance check unavailable"; }
      if (!refusal && !allowed) refusal = "governance denied";
      if (!refusal) {
        const g = grants.consume(typeof nonce === "string" ? nonce : "", { key: keyName, agent });
        if (!g.ok) refusal = g.reason;
      }
      audit({ event: "request", decision: refusal ? "deny" : "allow", key: keyName, agent, cmdHash, reason: refusal ?? null });
    } catch {
      return DENY(res, 503, "refused"); // grants or audit store unreadable/unwritable: fail closed
    }
    if (refusal) return DENY(res, 403, "refused");

    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k)) headers[k] = v;
    const mod = up.protocol === "https:" ? https : http;
    const out = mod.request({ hostname: up.hostname, port: up.port, method: req.method, path: req.url, headers, timeout: 15000 }, (r) => {
      res.writeHead(r.statusCode || 502, r.headers);
      r.pipe(res);
    });
    out.on("error", () => DENY(res, 502, "upstream unavailable")); // nothing is served from any local fallback
    out.on("timeout", () => out.destroy());
    req.pipe(out);
  });

  // Pin the client before any HTTP bytes are read: an unpinned client is dropped right after the handshake.
  server.on("secureConnection", (sock) => {
    const peer = sock.getPeerCertificate();
    if (!peer || !peer.raw || !sameFp(peer.fingerprint256, clientFp)) sock.destroy();
  });
  server.on("tlsClientError", () => {});
  return server;
}
