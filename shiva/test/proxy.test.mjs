import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createShivaProxy } from "../src/proxy.mjs";
import { shivaRequest } from "../src/client.mjs";
import { Grants } from "../src/grants.mjs";
import { fingerprint } from "../src/tls.mjs";
import { verify } from "../src/audit.mjs";
import { CANARY, allFilesText, fakeUpstream, listen, makeCert, tmp } from "./helpers.mjs";

async function rig({ check, upstreamUrl, clock = { t: Date.now() } } = {}) {
  const dir = tmp();
  const srv = makeCert(dir, "relay"), cli = makeCert(dir, "sandbox"), rogue = makeCert(dir, "rogue");
  const up = await fakeUpstream();
  const grants = new Grants(join(dir, "g.json"), () => clock.t);
  const auditPath = join(dir, "audit.log");
  const proxy = createShivaProxy({ serverCert: srv.cert, serverKey: srv.key, pinnedClientCert: cli.cert, upstream: upstreamUrl ?? up.url, grants, auditPath, check, now: () => clock.t });
  const port = await listen(proxy);
  const call = (opts = {}) => shivaRequest(`https://127.0.0.1:${port}/openai/v1/x`, {
    cert: cli.cert, key: cli.key, pinnedServerCert: srv.cert, pinnedServerFp: fingerprint(srv.cert), ...opts,
    headers: { authorization: `Bearer ${CANARY}`, "x-shiva-agent": "a1", "x-shiva-command-hash": "abc123", ...(opts.headers || {}) },
  });
  const nonce = () => grants.issue({ key: "openai", agent: "a1", ttlSeconds: 60 }).nonce;
  return { dir, srv, cli, rogue, up, grants, auditPath, proxy, port, call, nonce, clock, close: () => { proxy.close(); up.server.close(); } };
}

test("happy path: allowed request is forwarded with the client token and a metadata-only audit entry", async () => {
  const r = await rig({ check: async () => true });
  const res = await r.call({ headers: { "x-shiva-nonce": r.nonce() } });
  assert.equal(res.status, 200); assert.equal(res.body, "upstream-ok");
  assert.equal(r.up.seen[0].auth, `Bearer ${CANARY}`); assert.equal(r.up.seen[0].nonce, undefined); // shiva headers are stripped
  const e = JSON.parse(readFileSync(r.auditPath, "utf8").trim()); assert.equal(e.decision, "allow"); assert.equal(e.cmdHash, "abc123"); assert.equal(e.key, "openai");
  r.close();
});
test("replay of the same request (same nonce) is rejected and not forwarded", async () => {
  const r = await rig({ check: async () => true }); const n = r.nonce();
  assert.equal((await r.call({ headers: { "x-shiva-nonce": n } })).status, 200);
  assert.equal((await r.call({ headers: { "x-shiva-nonce": n } })).status, 403);
  assert.equal(r.up.seen.length, 1); r.close();
});
test("expired grant is rejected end to end", async () => {
  const r = await rig({ check: async () => true }); const n = r.nonce(); r.clock.t += 61_000;
  assert.equal((await r.call({ headers: { "x-shiva-nonce": n } })).status, 403); assert.equal(r.up.seen.length, 0); r.close();
});
test("missing nonce is rejected", async () => {
  const r = await rig({ check: async () => true }); assert.equal((await r.call()).status, 403); assert.equal(r.up.seen.length, 0); r.close();
});
test("FAIL CLOSED: governance check throws -> nothing forwarded, no env fallback", async () => {
  const r = await rig({ check: async () => { throw new Error("governance down"); } });
  assert.equal((await r.call({ headers: { "x-shiva-nonce": r.nonce() } })).status, 403); assert.equal(r.up.seen.length, 0); r.close();
});
test("FAIL CLOSED: governance check hangs -> timeout denies", async () => {
  const r = await rig({ check: () => new Promise(() => {}) }); r.proxy.close();
  const dir = r.dir; // rebuild with a short timeout
  const srv = makeCert(dir, "relay2"), cli = r.cli;
  const proxy = createShivaProxy({ serverCert: srv.cert, serverKey: srv.key, pinnedClientCert: cli.cert, upstream: r.up.url, grants: r.grants, auditPath: r.auditPath, check: () => new Promise(() => {}), checkTimeoutMs: 100 });
  const port = await listen(proxy);
  const res = await shivaRequest(`https://127.0.0.1:${port}/openai/x`, { cert: cli.cert, key: cli.key, pinnedServerCert: srv.cert, pinnedServerFp: fingerprint(srv.cert), headers: { "x-shiva-agent": "a1", "x-shiva-nonce": r.nonce() } });
  assert.equal(res.status, 403); assert.equal(r.up.seen.length, 0); proxy.close(); r.up.server.close();
});
test("FAIL CLOSED: upstream relay unreachable -> generic 502, nothing local served", async () => {
  const r = await rig({ check: async () => true, upstreamUrl: "http://127.0.0.1:1" });
  const res = await r.call({ headers: { "x-shiva-nonce": r.nonce() } });
  assert.equal(res.status, 502); assert.equal(res.body, "upstream unavailable"); r.close();
});
test("FAIL CLOSED: audit log unwritable -> request refused, not forwarded", async () => {
  const r = await rig({ check: async () => true });
  r.proxy.close(); const srv = makeCert(r.dir, "relay3");
  const proxy = createShivaProxy({ serverCert: srv.cert, serverKey: srv.key, pinnedClientCert: r.cli.cert, upstream: r.up.url, grants: r.grants, auditPath: join(r.dir, "no-such-dir", "audit.log") });
  const port = await listen(proxy);
  const res = await shivaRequest(`https://127.0.0.1:${port}/openai/x`, { cert: r.cli.cert, key: r.cli.key, pinnedServerCert: srv.cert, pinnedServerFp: fingerprint(srv.cert), headers: { "x-shiva-agent": "a1", "x-shiva-nonce": r.nonce() } });
  assert.equal(res.status, 503); assert.equal(r.up.seen.length, 0); proxy.close(); r.up.server.close();
});
test("mTLS: client with no certificate is refused before any request reaches upstream", async () => {
  const r = await rig({ check: async () => true });
  await assert.rejects(r.call({ cert: undefined, key: undefined, headers: { "x-shiva-nonce": r.nonce() } })); assert.equal(r.up.seen.length, 0); r.close();
});
test("mTLS: client with an unpinned (wrong) certificate is refused", async () => {
  const r = await rig({ check: async () => true });
  await assert.rejects(r.call({ cert: r.rogue.cert, key: r.rogue.key, headers: { "x-shiva-nonce": r.nonce() } })); assert.equal(r.up.seen.length, 0); r.close();
});
test("mTLS: client refuses a relay whose certificate is not the pinned one, before sending anything", async () => {
  const r = await rig({ check: async () => true });
  await assert.rejects(r.call({ pinnedServerCert: r.srv.cert, pinnedServerFp: fingerprint(r.rogue.cert), headers: { authorization: `Bearer ${CANARY}`, "x-shiva-nonce": r.nonce() } }), /pinned fingerprint/);
  assert.equal(r.up.seen.length, 0); r.close();
});
test("CANARY: the secret never appears in the audit log, grants file or CLI/process output", async () => {
  const r = await rig({ check: async () => true });
  await r.call({ headers: { "x-shiva-nonce": r.nonce() } }); await r.call({ headers: { "x-shiva-nonce": "bad".repeat(10) } });
  const onDisk = allFilesText(r.dir); assert.equal(onDisk.includes(CANARY), false); assert.equal(onDisk.includes(CANARY.slice(5)), false);
  const bin = new URL("../bin/shiva.mjs", import.meta.url).pathname;
  const out = spawnSync("node", [bin, "verify", r.auditPath], { env: { ...process.env, SHIVA_CANARY: CANARY } });
  assert.equal((out.stdout + out.stderr).toString().includes(CANARY), false);
  assert.equal(verify(r.auditPath).ok, true); r.close();
});
test("CANARY: crash output carries no error details and no diagnostic report", () => {
  const code = `import { harden } from ${JSON.stringify(new URL("../src/hardening.mjs", import.meta.url).href)}; harden(); throw new Error(${JSON.stringify(CANARY)});`;
  const out = spawnSync("node", ["--input-type=module", "-e", code], { cwd: tmp() });
  const text = (out.stdout + out.stderr).toString();
  assert.equal(text.includes(CANARY), false); assert.match(text, /details withheld/); assert.equal(out.status, 70);
});
