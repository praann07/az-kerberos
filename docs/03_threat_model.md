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
| T1 | **Victim lock-out amplification**: attacker sprays failures at victim principals → scorer restricts/denies the *victims*. | Cap failure-driven escalation at level 2 (never deny on failure counts alone); require two independent signals for level 3; global "max restricted share" circuit breaker; report victim impact as a metric. | **Observed in first synthetic run: all 10 restricted benign principals were attack targets.** Mitigation not yet implemented. Highest-priority fix. |
| T2 | Stopping/blinding the scorer (fail-open window 300 s). | Out-of-band staleness alert; audit `table_stale` record. | Not implemented. |
| T3 | Low-and-slow stolen credential evades features. | None claimed. | Synthetic `slow_*` attacks undetected by both scorer and baseline. State as a limitation. |
| T4 | Golden ticket: forged TGT of arbitrary lifetime. | `check_tgs` sees TGS requests using it; caps apply to **new** service tickets only, not the forged TGT. | Partial; depends on unverified `ticket->enc_part2` population. |
| T5 | Silver ticket: never contacts the KDC. | Out of scope — invisible to a KDC-side design. | Stated. |
| T6 | Detection→enforcement lag: first N issuances after attack start are unprotected. | Measured as "issuances after detection + lag" (lag modelled 5 s in demo). | Measured synthetically only. |
| T7 | Already-issued tickets stay valid; Kerberos has no revocation. | Renewals go through `check_tgs` and can be capped/denied. | Design only. |
| T8 | Log/audit tampering by A4. | Hash chain + signed checkpoints + off-host anchor. | Implemented, unit-tested; truncation needs anchor; not forward-secure. |
| T9 | Log injection via crafted principal names. | Strict regex parser; ignore unparseable lines; fuzz it. | Parser strict, **not fuzzed**. |
| T10 | Principal aliases / enterprise names: `request->client` ≠ name in log. | Documented limitation; compare in live lab. | Unverified. |
| T11 | RC4-downgrade signal is weak: `allow_rc4` default false since krb5 1.21. | AES-Kerberoasting features (distinct services, rate). | Doc fact verified; live behaviour untested. |
| T12 | Plugin crash/bug takes down the KDC (C code in the issuance path). | Minimal code, fail-open, review, run under test KDC first. | **Never compiled.** |
| T13 | Model poisoning if "benign" training data contains attacks. | Train on vetted days; calibrate on separate day. | Process control only. |

## Explicitly out of scope
PKINIT/PQ changes, client changes, silver tickets, attacks on the realm's keys/KDB, physical attacks, DoS on the KDC network port.
