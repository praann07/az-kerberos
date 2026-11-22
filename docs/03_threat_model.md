# 03 — Threat model

## Assets
Ticket-issuance decisions; risk table; scorer host; audit log + signing key; benign users' availability.

## Attackers
| ID | Attacker | In scope? |
|---|---|---|
| A1 | External: password spray / AS-REP roasting against the KDC | yes |
| A2 | Holder of one stolen credential (Kerberoasting, lateral movement) | yes |
| A3 | Compromised service host forging requests | partly |
| A4 | Root on the KDC host (edits log/table, stops scorer) | tamper-**evidence** only |
| A5 | Attacker who injects strings into principal names / logs | yes (parser hardening) |

## Threats, mitigations, and honest status
| # | Threat | Mitigation in design | Status |
|---|---|---|---|
| T1 | **Victim lock-out amplification**: attacker sprays failures at victim principals → scorer restricts/denies the *victims*. | Cap failure-driven escalation at level 2 (never deny on failure counts alone); require two independent signals for level 3; global "max restricted share" circuit breaker; report victim impact as a metric. | Observed in the first synthetic run (all 10 restricted benign principals were attack targets). **Mitigation now implemented** in `src/azk/engine.py` (failure-only cap at level 2, two-signal rule for level 3, circuit breaker) and unit-tested (`test_engine_t1_victim_lockout_and_circuit_breaker`). Live runs: spray victims 15 full / 0 capped / 0 denied (see T14, T15 for how the mitigation itself can be abused). |
| T2 | Stopping/blinding the scorer (fail-open window 300 s). | Out-of-band staleness alert; audit `table_stale` record. | Not implemented. |
| T3 | Low-and-slow stolen credential evades features. | None claimed. | Synthetic `slow_*` attacks undetected by both scorer and baseline. State as a limitation. |
| T4 | Golden ticket: forged TGT of arbitrary lifetime. | `check_tgs` sees TGS requests using it; caps apply to **new** service tickets only, not the forged TGT. | Partial; depends on unverified `ticket->enc_part2` population. |
| T5 | Silver ticket: never contacts the KDC. | Out of scope — invisible to a KDC-side design. | Stated. |
| T6 | Detection→enforcement lag: first N issuances after attack start are unprotected. | Measured as "issuances after detection + lag" (lag modelled 5 s in demo). | Measured synthetically only. |
| T7 | Already-issued tickets stay valid; Kerberos has no revocation. | Renewals go through `check_tgs` and can be capped/denied. | Design only. |
| T8 | Log/audit tampering by A4. | Hash chain + signed checkpoints + off-host anchor. | Implemented, unit-tested; truncation needs anchor; not forward-secure. |
| T9 | Log injection via crafted principal names. | Strict regex parser; ignore unparseable lines; fuzz it. | Hardened 2026-11-22 after a security review: all patterns are anchored with `.match()` at the start of the syslog message (`_MSG_START` in `src/azk/logparse.py`), so a principal name containing `AZK_POLICY phase=AS client=...` is parsed as a failed AS_REQ, not a policy event; principal names with spaces are parsed instead of dropped. Regression tests: `test_parse_forged_policy_text_in_principal_name_is_not_a_policy_event`, `test_parse_principal_names_with_spaces_are_not_dropped`. Still **not fuzzed**; a name that itself contains ` for ` can still split the client/service fields wrongly. |
| T10 | Principal aliases / enterprise names: `request->client` ≠ name in log. | `check_as` now keys on the KDB entry's canonical principal (`client->princ`), falling back to `request->client`. | Fixed in `plugin/kdcpolicy_azk.c`; struct layout checked against installed krb5 1.20.1 (`offsetof(princ)=64`, `sizeof=88`, identical). **Bypass could not be reproduced in the lab** (DB2 backend: `kinit -C -E` → "not found"; aliases need LDAP), so the fix is defence in depth and was only regression-tested on plain principals (level-2 cap of 300 s enforced after rebuild). |
| T11 | RC4-downgrade signal is weak: `allow_rc4` default false since krb5 1.21. | AES-Kerberoasting features (distinct services, rate). | Doc fact verified; live behaviour untested. |
| T12 | Plugin crash/bug takes down the KDC (C code in the issuance path). | Minimal code, fail-open, review, run under test KDC first. | Compiled with `gcc -Wall` and running in a live MIT krb5 1.20.1 KDC (WSL Ubuntu 24.04); fail-open verified (`out/x6_failopen_results.json`). Not fuzzed, not reviewed by a second person. |
| T13 | Model poisoning if "benign" training data contains attacks. | Train on vetted days; calibrate on separate day. | Process control only. |
| T14 | **Circuit-breaker abuse**: the breaker caps everyone at level 1 once `restricted >= total_principals × 0.25` (13 of 50). An attacker who gets ~13 names restricted (names come from failed AS_REQs and may not exist) switches denial off for all principals. | None; deliberate trade-off ("never lock out the realm"). Possible hardening, **not implemented**: count only principals that exist in the KDB, exempt TGS-anomaly signals from the downgrade, use the real realm size. | **Accepted limitation**, found by an automated security review and confirmed by reading `engine.py`; not exploited live. Changing it would invalidate the real X1–X3 results, so it was left unchanged. In those runs denial never fired anyway. |
| T15 | **Failure-only test is window-wide**: `engine.py` treats a client as failure-only when its window features `svc_distinct` and `rc4_n` are both 0, not by looking at the triggering event. A victim with normal service-ticket activity that is also being sprayed is not capped at level 2, so level 3 is reachable if two signals are elevated. | None implemented. Hardening: decide from the event type, never allow level 3 on `fail_n`/`spray_users` alone. | **Accepted limitation**, found by an automated security review; plausible from the code but **not demonstrated** — the unit test covers only a pure-failure victim. |

## Explicitly out of scope
PKINIT/PQ changes, client changes, silver tickets, attacks on the realm's keys/KDB, physical attacks, DoS on the KDC network port.
