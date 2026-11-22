// Single-use, TTL-bound grants. Only a SHA-256 of each nonce is stored; the nonce itself is shown once at issue time.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

const h = (s) => createHash("sha256").update(s).digest("hex");
export const MAX_TTL_SECONDS = 3600;

export class Grants {
  constructor(path, now = Date.now) { this.path = path; this.now = now; }
  #load() { return existsSync(this.path) ? JSON.parse(readFileSync(this.path, "utf8")) : {}; }
  #save(db) { const tmp = this.path + ".tmp"; writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 }); renameSync(tmp, this.path); }

  issue({ key, agent, ttlSeconds }) {
    if (!key || !agent) throw new Error("key and agent are required");
    const ttl = Math.floor(Number(ttlSeconds));
    if (!(ttl > 0) || ttl > MAX_TTL_SECONDS) throw new Error(`ttl must be 1..${MAX_TTL_SECONDS} seconds`);
    const buf = randomBytes(32);
    const nonce = buf.toString("base64url");
    buf.fill(0);
    const db = this.#load();
    db[h(nonce)] = { key, agent, expiresAt: this.now() + ttl * 1000, used: false };
    this.#save(db);
    return { nonce, expiresAt: new Date(this.now() + ttl * 1000).toISOString() };
  }

  // Marks the nonce used before anything else happens, so a replay or concurrent second use always loses.
  consume(nonce, { key, agent }) {
    if (typeof nonce !== "string" || nonce.length < 20) return { ok: false, reason: "no nonce" };
    const db = this.#load();
    const rec = db[h(nonce)];
    if (!rec) return { ok: false, reason: "unknown nonce" };
    if (rec.used) return { ok: false, reason: "nonce already used" };
    if (this.now() > rec.expiresAt) { rec.used = true; this.#save(db); return { ok: false, reason: "expired" }; }
    if (rec.key !== key) return { ok: false, reason: "wrong key" };
    if (rec.agent !== agent) return { ok: false, reason: "wrong agent" };
    rec.used = true;
    this.#save(db);
    return { ok: true };
  }
}
