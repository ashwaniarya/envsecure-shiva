// Sandbox-side client: presents its cert and trusts only the pinned relay fingerprint.
import https from "node:https";
import { pinnedServerCheck } from "./tls.mjs";

export function shivaRequest(url, { cert, key, pinnedServerCert, pinnedServerFp, method = "GET", headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers,
      cert, key, ca: pinnedServerCert, minVersion: "TLSv1.3",
      checkServerIdentity: pinnedServerCheck(pinnedServerFp),
    }, (res) => { const parts = []; res.on("data", (c) => parts.push(c)); res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(parts).toString("utf8") })); });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
