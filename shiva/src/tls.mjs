// Fingerprint pinning for both directions of the mTLS link.
import { X509Certificate } from "node:crypto";

export function fingerprint(pem) { return new X509Certificate(pem).fingerprint256; }

const norm = (s) => String(s).replace(/:/g, "").toLowerCase();
export const sameFp = (a, b) => norm(a) === norm(b);

// Client side: trust only the relay cert whose fingerprint is pinned. Runs during the handshake, before any request.
export function pinnedServerCheck(pinnedFp) {
  return (_host, cert) => (sameFp(cert.fingerprint256, pinnedFp) ? undefined : new Error("relay certificate does not match the pinned fingerprint"));
}
