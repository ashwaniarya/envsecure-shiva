# EnvSecure-Shiva v1

Governance layer in front of the unchanged Keysrs relay/gateway. Zero dependencies, Node 22+. Upstream code (Sources/, Relay/, etc.) is untouched.

```
sandbox client --mTLS (both pinned)--> shiva proxy --> [governance check -> nonce+TTL -> audit] --> Keysrs relay (unchanged)
```

| Req | Built |
|---|---|
| 1 No plaintext secrets | Audit holds metadata only (key name, agent, ts, command hash). Grants file holds a SHA-256 of each nonce. Diagnostic reports off, fatal errors print no details. Test greps disk, CLI output and crash output for a canary. |
| 2 Nonce + TTL | `shiva issue` gives a 256-bit single-use nonce, TTL capped at 3600 s. Consumed before forwarding. Replay, expiry, second use all refused. |
| 3 Hash-chained log | Each entry has `prev` and `hash`. `shiva verify <log> [--expect-head H]` detects edit, deletion, reorder. |
| 4 Fail closed | Governance error or timeout, grants/audit store failure, or upstream down: generic refusal, nothing forwarded, no .env fallback. |
| 6 Pinned mTLS | TLS 1.3, relay pins the client cert fingerprint, client pins the relay fingerprint. Unpinned peers are dropped after the handshake, before any request is read. |

Run: `cd shiva && npm test`. Test certs are generated in a temp dir by openssl during tests.

## Known weaknesses
- Tail truncation of the audit log is only detectable against an anchored head hash (`shiva head`, store it elsewhere). Whoever owns the file can also rebuild the whole chain; v1 proves integrity, not authorship.
- JS strings are immutable, so the client token in request headers cannot be zeroed. Shiva only zeroes buffers it owns. The token passes through to upstream by design.
- The default governance check allows everything that has a valid grant. Real policy is phase two.
- Grants and audit use plain files with no locking: one proxy process per files.
- Upstream Swift tests need macOS and were not run here.

## Phase two (not built)
Scope binding of a grant to the exact command hash (hash is only recorded today), team policy.
