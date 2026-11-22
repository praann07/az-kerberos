# 02 — Architecture

```
                 stock krb5 clients / services (unchanged)
                               |  AS-REQ / TGS-REQ
                               v
   +---------------------- MIT krb5 KDC (stock) -----------------------+
   | preauth ok -> check_kdcpolicy_as()   TGS -> check_kdcpolicy_tgs() |
   |        |  kdcpolicy_azk.so  (plugin/kdcpolicy_azk.c)              |
   |        |   O(1): mmap'd risk table lookup (fail-open)             |
   |        |   caps lifetime/renew  or  denies (KRB5KDC_ERR_POLICY)   |
   +--------|-----------------------------------------^---------------+
            | syslog "AZK_POLICY ..."                 | risk_table.bin (atomic rename, mmap, stat <=1/s)
            | KDC log lines (AS_REQ/TGS_REQ ...)      |
            v                                         |
   +-------------------- async scorer (Python, off request path) --------+
   | logparse -> features (sliding 300 s) -> scorer (IForest / threshold)|
   |   -> LevelMap (benign-quantile cut-offs) -> Engine (hold, decay)    |
   |   -> risktable.write_atomic()                                       |
   |   -> AuditLog.append(risk_update | table_publish | policy_applied)  |
   +---------------------------------------------------------------------+
            |
            v   audit.log  (hash chain + Ed25519 signed checkpoints); anchor (seq,hash) kept OFF the KDC host
```

## Components (file → responsibility)
| File | Responsibility |
|---|---|
| `src/azk/logparse.py` | Parse MIT krb5 AS/TGS log lines and our `AZK_POLICY` lines. Checked against 730 real lines captured from MIT krb5 1.20.1 on 2026-11-22 (all parse; a bug that dropped every TGS failure line was fixed; regression test `tests/real_kdc_lines_sample.txt`). The simulator's lines are still built from format strings, not captured. The lab KDC always logs the client as 127.0.0.1, so source-IP features cannot be exercised there. |
| `src/azk/features.py` | Per-principal sliding-window features: `fail_n, spray_users, svc_distinct, rc4_n, new_ip, rate_per_min`. `NEEDED_PREAUTH` is not counted as a failure. Known IPs learned on benign baseline only. |
| `src/azk/scorer.py` | `ThresholdRule` (baseline), `IForestScorer` (benign-only), `LevelMap` (cut-offs = quantiles of benign validation scores at α = 1e-2/1e-3/1e-4; flags α too small for the calibration sample). |
| `src/azk/engine.py` | Raises a principal's level, holds it `hold_s` (900 s) then decays; policy map level→caps; publishes the table; writes audit records. |
| `src/azk/risktable.py` | Binary table (layout below), atomic write, reference reader identical to the C lookup. |
| `src/azk/audit.py` | Hash chain + signed checkpoints + `verify(anchor=)`. |
| `src/azk/simulator.py`, `demo.py` | SYNTHETIC logs and smoke run. Not an evaluation. |
| `plugin/kdcpolicy_azk.c` | kdcpolicy module. Compiled and loaded on stock krb5 1.20.1 in WSL Ubuntu-24.04 (`kdcpolicy_azk_initvt` exported); enforces lifetime caps and denial at AS and TGS. |
| `tests/test_azk.py` | 27 unit tests (parser incl. real KDC lines and log-injection cases, table, audit tamper cases, engine incl. oversized-name handling). All pass. |

## Risk table layout (little-endian; must match C)
Header 32 B: `'AZRT'` | version u32=1 | nslots u32 (power of 2) | generated_at u64 (at offset 12) | 12 B pad.
Slot 88 B: key u64 (FNV-1a-64 of principal, 0 = empty) @0 | name char[64] @8 | level u32 @72 | lifetime_cap u32 @76 | renew_cap u32 @80 | expires_at u32 @84.
Open addressing, linear probe. A unit test pins these offsets and the FNV-1a test vectors.

## Policy map (default, `engine.DEFAULT_POLICY`)
| Level | Lifetime cap | Renew cap | Meaning |
|---|---|---|---|
| 0 / no entry | — | — | untouched |
| 1 | 3600 s | 14400 s | mild |
| 2 | 600 s | 1 s | short tickets, effectively no renewal |
| 3 | deny | deny | `status="AZK_RISK_DENY"`, `KRB5KDC_ERR_POLICY` |
Caps are never 0 (0 = unconstrained in `update_ticket_times`). "1 s = no renewal" is **untested** on a real KDC.

## Design decisions and why
- **Plugin does no scoring**: IsolationForest single-row scoring measured 12.9 ms (own synthetic benchmark; sklearn logistic 93.5 µs; dot-product 1.7 µs; dict lookup 0.05 µs) — unacceptable in-line; hence async.
- **Fail open** on missing/malformed/stale (>300 s) table: fail-closed would make the scorer a denial-of-service lever. Cost: stopping the scorer disables protection after 300 s — the stale state must be alerted out-of-band (open item).
- **Per-entry `expires_at`** gives automatic decay; no explicit "clear" message is needed.
- **Plugin keyed by principal, not IP**: `check_as/check_tgs` get no source address (verified in the header). IP-based features exist only in the async scorer, which can only act on the principal.
- **Plugin sees only successful-preauth AS** (call site `finish_process_as_req` runs only when `errcode == 0`) — failed-preauth attempts are visible in logs only.
- **Audit binds decisions**: plugin's `AZK_POLICY` lines (level, caps, `table_gen`) are ingested by the scorer into the chain, next to the `risk_update` that caused them and the `table_publish` hash.
- **Caps only tighten** (`ts_min` in `policy.c`); a high-risk principal cannot get *longer* tickets than the realm policy allows.

## Audit log guarantees (tested)
Detected: edit, delete, reorder, insert, forged hashes without the key, bad signature. Self-consistent but **not** detected without an external anchor: truncation back to an earlier checkpoint. Records after the last checkpoint are hash-linked but unsigned. Not forward-secure: signing key must live off the KDC host.

## Optional experiment E1/E2 (not built)
E1: in-plugin O(1) rate counter. E2: hybrid X25519+ML-KEM TLS in front of an HTTPS KDC proxy — see survey P1; no source found measuring this, but PQ itself is not a novelty claim (kurbu5-pkinit).
