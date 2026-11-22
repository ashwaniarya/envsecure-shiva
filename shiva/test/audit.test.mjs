import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { append, verify, head } from "../src/audit.mjs";
import { tmp } from "./helpers.mjs";

function seed(n = 4) {
  const p = join(tmp(), "audit.log");
  for (let i = 0; i < n; i++) append(p, { event: "request", decision: "allow", key: "openai", agent: `a${i}`, cmdHash: `h${i}` });
  return p;
}
test("a clean chain verifies", () => { const p = seed(); const r = verify(p); assert.equal(r.ok, true); assert.equal(r.entries, 4); });
test("entries carry the previous hash", () => {
  const p = seed(2); const [a, b] = readFileSync(p, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(b.prev, a.hash);
});
test("editing a field is detected", () => {
  const p = seed(); const l = readFileSync(p, "utf8").split("\n"); l[1] = l[1].replace('"a1"', '"evil"'); writeFileSync(p, l.join("\n"));
  const r = verify(p); assert.equal(r.ok, false); assert.equal(r.at, 1);
});
test("deleting a middle entry is detected", () => {
  const p = seed(); const l = readFileSync(p, "utf8").split("\n"); l.splice(1, 1); writeFileSync(p, l.join("\n"));
  assert.equal(verify(p).ok, false);
});
test("deleting the first entry is detected", () => {
  const p = seed(); const l = readFileSync(p, "utf8").split("\n"); l.splice(0, 1); writeFileSync(p, l.join("\n"));
  assert.equal(verify(p).ok, false);
});
test("reordering two entries is detected", () => {
  const p = seed(); const l = readFileSync(p, "utf8").split("\n"); [l[1], l[2]] = [l[2], l[1]]; writeFileSync(p, l.join("\n"));
  assert.equal(verify(p).ok, false);
});
test("tail truncation is detected only against an anchored head", () => {
  const p = seed(); const anchored = head(p).hash;
  const l = readFileSync(p, "utf8").split("\n"); l.splice(3, 1); writeFileSync(p, l.join("\n"));
  assert.equal(verify(p).ok, true); // known limit, documented
  assert.equal(verify(p, anchored).ok, false);
});
test("the CLI verify command exits 0 clean and 1 tampered", async () => {
  const { spawnSync } = await import("node:child_process");
  const p = seed(); const bin = new URL("../bin/shiva.mjs", import.meta.url).pathname;
  assert.equal(spawnSync("node", [bin, "verify", p]).status, 0);
  const l = readFileSync(p, "utf8").split("\n"); l[2] = l[2].replace("allow", "deny"); writeFileSync(p, l.join("\n"));
  assert.equal(spawnSync("node", [bin, "verify", p]).status, 1);
});
