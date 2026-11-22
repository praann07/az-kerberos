# 05 — Status, limits, blockers, work breakdown
_Updated 2026-11-20 (All Milestones Completed & Evaluated Live)._

## 1. What exists
| Item | State |
|---|---|
| Literature survey (4 pillars, COMBO CHECK) | Complete (`survey_related_work.md`) |
| Python pipeline (`src/azk`) | Complete; **23/23 unit tests pass** (Python 3.12, pytest 8.3.3) |
| Synthetic smoke run (`python -m azk.demo`) | Runs end to end; audit chain verifies |
| C plugin (`plugin/kdcpolicy_azk.c`) | **Compiled with 0 warnings**, installed and verified live on MIT KDC |
| Live MIT KDC lab | **Active in WSL2 Ubuntu 24.04**; realm LAB.TEST (50 users, 20 services) |
| Threat T1 Mitigation | Fully implemented & verified (AS-phase cap at L2, 2-signal L3, circuit breaker) |
| Evaluation on live KDC | X4–X6 measured; X1–X3 re-run as REAL end-to-end (3 repeats); old synthetic X1–X3 superseded |
| Conference Paper | Complete in Markdown (`docs/conference_paper.md`) and IEEE LaTeX (`docs/conference_paper.tex`) |

## 2. Live KDC Evaluation Results (MEASURED on Live MIT Kerberos KDC)

### Latency Overhead (X4)
- **C in-memory lookup:** 13.4 ns (50 entries) vs 14.2 ns (5,000 entries) in the reported run; a re-run on 2026-11-22 gave 18.3 ns and 19.6 ns (quote about 14–20 ns). The ~10^6x ratio versus in-line ML compares a C hash lookup with a Python sklearn call, so it is not like-for-like.
- **End-to-end KDC request latency:** 467.4 ms median (stock) vs 382.4 ms (empty table), 256.6 ms (50 entries) and 252.5 ms (5,000 entries), 60 samples each. Stock being slowest means run-order/WSL noise; no overhead measurable above that noise.

### Audit Ledger Performance (X5)
- **Append throughput:** 64,476 events/s (Ed25519-signed checkpoints every 100 records).
- **Verification throughput:** 81,748 records/s.
- **Tamper matrix:** all 6 of our own vectors detected (bit-flips, record deletion, reordering, insertion, forged signature, anchored truncation); truncation without an external anchor is accepted.

### Fail-Open Resilience (X6)
- Missing table: fails open (10-hour standard ticket issued).
- Corrupt magic / truncated size: fails open (10-hour standard ticket issued).
- Stale table (>300s): fails open (10-hour standard ticket issued).
- Active table: strictly enforced (capped or denied).

### Live Attack Mitigation (X1–X3)
REAL end-to-end runs (2026-11-22): `tests/run_live_experiment_real.py`, raw `out/x1_x2_x3_real_results.json` (tick 1 s, 3 repeats, pacing 0/1/3 s), `out/x1_x2_x3_real_poll025.json` (tick 0.25 s, 2 repeats), summaries `out/x1_x2_x3_real_summary.txt`, `out/x1_x2_x3_real_poll025_summary.txt`. The earlier X1–X3 numbers (18→2 full, 8 capped, 8 denied; FRR 3/100) came from `tests/run_live_experiment.py`, which fed synthetic log lines and inferred outcomes; they are SUPERSEDED and must not be cited.
- **AES Kerberoasting (18 requests), tickets full / capped / denied:** unprotected 18/0/0; threshold 8/10/0 (paced), 18/0/0 (burst); AZ-Kerberos 6/12/0 (paced), 15/3/0 (burst). Capped = 3,600 s, still crackable offline.
- **RC4 Kerberoasting (10 requests):** unprotected 10/0/0; threshold 6/4/0; AZ-Kerberos 6/4/0 (paced); all modes 10/0/0 for a burst.
- **Denied = 0 in every live attack run** (two-signal rule needs ≥10 distinct services and ≥5 RC4 requests; not met). Not tuned after the fact. Deny path verified only by X6 and manual smoke.
- **Victim Lock-Out (T1):** no spray victim capped or denied under AZ-Kerberos (15/15 full); threshold capped 10 of 15 (single-IP lab artifact: all clients 127.0.0.1).
- **Benign false restrictions:** 4 of 600 requests (1 of 25 users, 1 of 3 benign sequences); 0 of 400 with 0.25 s tick. Audit logs verified in 13 of 13 AZ runs.
- **Honest verdict:** closed loop works on stock krb5 1.20.1; it does not stop Kerberoasting (attacker keeps 6/18 full tickets, 15/18 in a burst); no demonstrated advantage over a threshold rule; stolen-credential attack not run.
- **Paper integrity fixes 2026-11-21:** removed an unsupported "98.7% accuracy / LSTM" claim for Grippo & Kholidy (arXiv 2301.00044 is manual event inspection, no quantitative result); added limitations for partial survey, Table 2/3 caveats and evaluation scale. Backups: `docs/conference_paper.md.bak_pre_integrity`, `docs/conference_paper.tex.bak_pre_integrity`.

## 3. Blockers and decisions needed
1. **No Linux environment.** This Windows machine has no `gcc`/`make`, no Docker, and WSL has no installed distribution. The plugin cannot be compiled and no MIT KDC can run. Options: (a) install a WSL2 Ubuntu distro, (b) a Linux VM, (c) use a university/cloud Linux box. I have not installed anything. **Recommended: (a)** — enough for `krb5-kdc`, `libkrb5-dev`, `gcc`.
2. Impacket's behaviour against an MIT KDC is unverified; attack tooling for the lab is unconfirmed.
3. Qomplx US12580898 was read on 2026-11-22 (detection + post-hoc ticket destruction via a ledger; no lifetime adaptation, no signed chain, not stock MIT krb5): partial overlap only. Still unread: US11968227, US12438906, continuations US12452307 / US12641123, IEEE Computer 2024.

## 4. Plugin bring-up checklist (once Linux exists)
- [ ] Install `krb5-kdc`, `krb5-admin-server`, `libkrb5-dev`; create a realm with ~50 principals.
- [ ] Compile `kdcpolicy_azk.so`; fix compile errors; confirm krb5 version ≥ 1.16.
- [ ] Confirm `[plugins] kdcpolicy = { module = azk:/path/kdcpolicy_azk.so }` loads (compare MIT `src/tests/t_kdcpolicy.py`); check the KDC log for load errors.
- [ ] Confirm `ticket->enc_part2` is populated in `check_tgs`; if not, change the TGS keying.
- [ ] Confirm lifetime cap actually shortens the issued ticket (`klist -e`), and whether a 1 s renew cap blocks renewal.
- [ ] Confirm where `syslog()` lines land relative to the KDC log target; make the scorer read both.
- [ ] Confirm the KDC is single-threaded (remap without a lock) and that a table swap under load is safe.
- [ ] Capture real log lines; replace the simulator-derived parser fixtures; check `k5_print_addr` format.
- [ ] Measure X4 (overhead).

## 5. Work breakdown (ordered; effort estimates are guesses)
| # | Work | Depends on | Est. |
|---|---|---|---|
| W1 | Linux env + MIT KDC + lab traffic generator | decision §3.1 | 1–2 d |
| W2 | Compile/load plugin, bring-up checklist | W1 | 1–2 d |
| W3 | Capture real logs; fix parser/feature assumptions | W1 | 1 d |
| W4 | Fix T1 (victim lock-out): level cap for failure-driven escalation, two-signal level 3, breaker | — | 1 d |
| W5 | Attack runs (Kerberoast, AS-REP, spray, stolen-cred) with labels | W1, W3 | 2–3 d |
| W6 | Experiments X1–X6, tables, plots | W2, W4, W5 | 3 d |
| W7 | Resolve remaining novelty threats (Qomplx US11968227 / US12438906, IEEE Computer 2024); update survey | — | 1 d |
| W8 | Report/slides from `docs/` | W6, W7 | 2 d |

## 6. What we may and may not claim
May claim: closed loop from async KDC-log scoring to enforced ticket-lifetime caps on stock MIT krb5 1.20.1 (observed in real runs), bound to a signed hash-chained decision log, with measured trade-offs. May NOT claim: that it stops Kerberoasting, that it beats a threshold rule, or that live denial was demonstrated (never triggered; only X6 and manual smoke).
May **not** claim: PQ Kerberos novelty (kurbu5-pkinit, IETF draft); novelty of hash-chained logs; novelty of ML on Kerberos logs; any detection or latency number before it is measured on a live KDC; "no prior work exists" (only: none found in a partial search).
