// Append-only, hash-chained audit log (JSON lines). Metadata only: never a secret value.
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";

export const GENESIS = "0".repeat(64);
const FIELDS = ["seq", "ts", "event", "decision", "key", "agent", "cmdHash", "reason", "prev"];

export function entryHash(e) {
  // fixed field order, so reordering or editing any field changes the hash
  const body = JSON.stringify(FIELDS.map((f) => (e[f] === undefined ? null : e[f])));
  return createHash("sha256").update(body).digest("hex");
}

function readLines(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0);
}

export function head(path) {
  const lines = readLines(path);
  if (lines.length === 0) return { seq: -1, hash: GENESIS };
  const last = JSON.parse(lines[lines.length - 1]);
  return { seq: last.seq, hash: last.hash };
}

// Throws if the write fails: callers must treat that as a denial (fail closed).
export function append(path, fields, now = Date.now) {
  const h = head(path);
  const e = {
    seq: h.seq + 1,
    ts: new Date(now()).toISOString(),
    event: fields.event,
    decision: fields.decision,
    key: fields.key ?? null,
    agent: fields.agent ?? null,
    cmdHash: fields.cmdHash ?? null,
    reason: fields.reason ?? null,
    prev: h.hash,
  };
  e.hash = entryHash(e);
  appendFileSync(path, JSON.stringify(e) + "\n", { flag: "a", mode: 0o600 });
  return e;
}

// Returns { ok, entries, error?, at? }. Detects edits, deletions in the middle or at the start, and reordering.
// Truncating the tail is only detectable against an anchored head hash (`expectHead`).
export function verify(path, expectHead) {
  const lines = readLines(path);
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let e;
    try { e = JSON.parse(lines[i]); } catch { return { ok: false, entries: i, at: i, error: "unparseable entry" }; }
    if (e.seq !== i) return { ok: false, entries: i, at: i, error: "sequence gap or reorder" };
    if (e.prev !== prev) return { ok: false, entries: i, at: i, error: "broken chain (prev hash mismatch)" };
    if (entryHash(e) !== e.hash) return { ok: false, entries: i, at: i, error: "entry hash mismatch (edited)" };
    prev = e.hash;
  }
  if (expectHead && expectHead !== prev) return { ok: false, entries: lines.length, at: lines.length, error: "head hash differs from anchored head (truncated or extended)" };
  return { ok: true, entries: lines.length, head: prev };
}
