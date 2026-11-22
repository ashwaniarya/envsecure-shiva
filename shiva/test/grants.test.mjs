import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { Grants } from "../src/grants.mjs";
import { tmp } from "./helpers.mjs";

const mk = (clock) => new Grants(join(tmp(), "g.json"), () => clock.t);
const ctx = { key: "openai", agent: "a1" };
test("a fresh nonce is accepted once, a replay is rejected", () => {
  const c = { t: 1000 }, g = mk(c); const { nonce } = g.issue({ ...ctx, ttlSeconds: 60 });
  assert.equal(g.consume(nonce, ctx).ok, true);
  const again = g.consume(nonce, ctx); assert.equal(again.ok, false); assert.match(again.reason, /already used/);
});
test("an expired TTL is rejected", () => {
  const c = { t: 1000 }, g = mk(c); const { nonce } = g.issue({ ...ctx, ttlSeconds: 30 });
  c.t += 31_000; const r = g.consume(nonce, ctx); assert.equal(r.ok, false); assert.equal(r.reason, "expired");
});
test("the last second inside the TTL still works", () => {
  const c = { t: 1000 }, g = mk(c); const { nonce } = g.issue({ ...ctx, ttlSeconds: 30 });
  c.t += 30_000; assert.equal(g.consume(nonce, ctx).ok, true);
});
test("a TTL above the hard cap or non-positive is refused at issue", () => {
  const g = mk({ t: 0 });
  assert.throws(() => g.issue({ ...ctx, ttlSeconds: 99999 })); assert.throws(() => g.issue({ ...ctx, ttlSeconds: 0 }));
});
test("wrong key, wrong agent, unknown nonce are rejected", () => {
  const g = mk({ t: 0 }); const { nonce } = g.issue({ ...ctx, ttlSeconds: 60 });
  assert.equal(g.consume(nonce, { key: "other", agent: "a1" }).ok, false);
  assert.equal(g.consume(nonce, { key: "openai", agent: "a2" }).ok, false);
  assert.equal(g.consume("x".repeat(43), ctx).ok, false);
});
test("the grants file stores only a hash of the nonce", async () => {
  const { readFileSync } = await import("node:fs");
  const p = join(tmp(), "g.json"); const g = new Grants(p, () => 0); const { nonce } = g.issue({ ...ctx, ttlSeconds: 60 });
  assert.equal(readFileSync(p, "utf8").includes(nonce), false);
});
