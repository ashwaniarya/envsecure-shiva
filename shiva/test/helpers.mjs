import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

// Throwaway self-signed certs generated at test time in a temp dir. Never committed.
export function makeCert(dir, name) {
  const key = join(dir, `${name}.key`), crt = join(dir, `${name}.crt`);
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", `/CN=${name}`, "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], { stdio: "ignore" });
  return { key: readFileSync(key), cert: readFileSync(crt) };
}
export const tmp = () => mkdtempSync(join(tmpdir(), "shiva-"));
export const CANARY = "ksfc_CANARY_SECRET_9f8e7d6c5b4a39281706";

// Fake upstream relay: records what it received (never persisted anywhere).
export function fakeUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => { seen.push({ url: req.url, auth: req.headers.authorization, nonce: req.headers["x-shiva-nonce"] }); res.end("upstream-ok"); });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ server, seen, url: `http://127.0.0.1:${server.address().port}` })));
}
export const listen = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
export function allFilesText(dir) { return readdirSync(dir).map((f) => readFileSync(join(dir, f), "utf8")).join("\n"); }
export { writeFileSync };
