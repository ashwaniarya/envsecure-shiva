#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { harden } from "../src/hardening.mjs";
import { append, head, verify } from "../src/audit.mjs";
import { Grants } from "../src/grants.mjs";
import { createShivaProxy } from "../src/proxy.mjs";

harden();
const [cmd, ...rest] = process.argv.slice(2);
const opt = (name, d) => { const i = rest.indexOf(`--${name}`); return i >= 0 ? rest[i + 1] : (process.env[`SHIVA_${name.toUpperCase().replace(/-/g, "_")}`] ?? d); };
const usage = () => { console.error("usage: shiva verify <log> [--expect-head <hash>] | head <log> | issue --key K --agent A --ttl S [--grants F --log F] | serve --listen PORT --upstream URL --cert F --key F --client-cert F [--grants F --log F]"); process.exit(2); };

if (cmd === "verify") {
  const r = verify(rest[0], opt("expect-head"));
  if (r.ok) { console.log(`OK: ${r.entries} entries, head ${r.head}`); process.exit(0); }
  console.error(`TAMPERED: ${r.error} at entry ${r.at}`); process.exit(1);
} else if (cmd === "head") {
  console.log(head(rest[0]).hash);
} else if (cmd === "issue") {
  const grants = new Grants(opt("grants", "shiva-grants.json"));
  const g = grants.issue({ key: opt("key"), agent: opt("agent"), ttlSeconds: opt("ttl", "60") });
  append(opt("log", "shiva-audit.log"), { event: "issue", decision: "allow", key: opt("key"), agent: opt("agent") });
  console.log(`nonce ${g.nonce}\nexpires ${g.expiresAt}\n(single use; shown once)`);
} else if (cmd === "serve") {
  const server = createShivaProxy({
    serverCert: readFileSync(opt("cert")), serverKey: readFileSync(opt("key")), pinnedClientCert: readFileSync(opt("client-cert")),
    upstream: opt("upstream"), grants: new Grants(opt("grants", "shiva-grants.json")), auditPath: opt("log", "shiva-audit.log"),
  });
  server.listen(Number(opt("listen", "8443")), "127.0.0.1", () => console.log("shiva listening (mTLS, pinned)"));
} else usage();
