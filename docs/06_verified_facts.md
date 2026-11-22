# 06 — Verified facts and open verification items

## Verified against primary sources (2026-11-20)
| Fact | Source |
|---|---|
| kdcpolicy interface: major 1, minor 1; `kdcpolicy_<name>_initvt`; vtable `{name, init, fini, check_as, check_tgs}` | https://raw.githubusercontent.com/krb5/krb5/master/src/include/krb5/kdcpolicy_plugin.h |
| Interface introduced in krb5 1.16; modules can veto AS/TGS or restrict lifetime/renew; module data lives for the KDC process lifetime; `<kdb.h>` entry access is not stable across releases | https://web.mit.edu/kerberos/krb5-latest/doc/plugindev/kdcpolicy.html (docs release 1.22.3) |
| Deny = set `*status` to a string literal + return error (test module: `KRB5KDC_ERR_POLICY`, status `"LOCAL_POLICY"`) | `src/plugins/kdcpolicy/test/main.c`, `src/tests/t_kdcpolicy.py` |
| No source-address argument is passed to `check_as`/`check_tgs` | header (signatures above) |
| Caps only tighten; 0 = unconstrained: `if (life) endtime = ts_min(ts_incr(now, life), endtime)` (same for renew) | `src/kdc/policy.c` |
| `check_kdcpolicy_as` runs only after preauth succeeded (`errcode == 0`) | `src/kdc/do_as_req.c:218` |
| `check_kdcpolicy_tgs(context, req, server, header_tkt, ...)` runs after `compute_ticket_times` | `src/kdc/do_tgs_req.c:919` |
| Plugin config syntax `[plugins] kdcpolicy = { module = name:/path.so }` | `src/tests/t_kdcpolicy.py` (not in the krb5.conf docs page) |
| Log formats of `AS_REQ`/`TGS_REQ` lines | `src/kdc/kdc_log.c`, `src/kdc/kdc_util.c` |
| `allow_rc4` / `allow_des3` default false since 1.21 | https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html |
| IETF draft-bokovoy-kitten-pkinit-pqc-02: pure ML-KEM, hybrid deferred, ek 1184 B / ct 1088 B / ML-DSA-65 sig 3309 B, TCP required | https://www.ietf.org/archive/id/draft-bokovoy-kitten-pkinit-pqc-02.txt |
| Crosby & Wallach numbers (800 MB vs 3 KB proof at 80M events; 1,750 events/s incl. DSA) | USENIX Security 2009 full text |
| Kotlaba ICISSP 2020 Table 2 rows D01/D02-$/D04 | https://www.scitepress.org/Papers/2020/89550/89550.pdf |

## Own measurements (synthetic, this machine)
IsolationForest single-row score 12.9 ms; sklearn LogisticRegression `predict_proba` 93.5 µs; dot-product logistic 1.7 µs; dict lookup 0.05 µs. Synthetic 10-feature data, latency only. Unit tests: 24 pass (includes a parser test on real MIT krb5 1.20.1 KDC lines).

## Verified on the live lab KDC (MIT krb5 1.20.1-6ubuntu2.10, WSL Ubuntu-24.04, 2026-11-22)
- `[plugins] kdcpolicy = { module = azk:/usr/lib/x86_64-linux-gnu/krb5/plugins/kdcpolicy/kdcpolicy_azk.so }` loads; AS and TGS hooks both enforce (level 2 cap 300 s -> 5-minute ticket; level 3 -> "KDC policy rejects request").
- `ticket->enc_part2` IS populated at `check_tgs` (the plugin logs `client=user01@LAB.TEST` for TGS requests).
- Real KDC log formats were captured (730 lines); a sanitised sample is `tests/real_kdc_lines_sample.txt`. They exposed a parser bug (TGS failure lines have no comma after the etypes block; 156 of 730 real lines were dropped), fixed in `src/azk/logparse.py:32-34`, regression test `test_parse_real_kdc_lines_from_live_mit_krb5`.
- The KDC cannot write `/var/log/krb5kdc.log` under the systemd unit (read-only filesystem), so the lab uses `kdc = SYSLOG:INFO:DAEMON` and reads journald (`journalctl -t azk-kdcpolicy`).
- RC4 service tickets need `allow_weak_crypto = true` and `allow_rc4 = true` in the client `krb5.conf` and `arcfour-hmac` in the realm `session_etypes`; otherwise the KDC answers `BAD_ENCRYPTION_TYPE`.
- Every client appears as `127.0.0.1` in the log, even when the client connects to another loopback address (the kernel chooses the source), so the lab cannot vary the source IP.
- Qomplx US12580898 (read 2026-11-22): detection plus post-hoc ticket destruction driven by a master ledger of authentication objects kept by domain-controller agents. One cryptographic hash per object, not a hash chain; no ML risk score; no ticket-lifetime adaptation; no signed log; not stock MIT krb5. Partial overlap only; not a combination threat.

## Real X1-X3 results (measured 2026-11-22, live MIT krb5 1.20.1, WSL Ubuntu-24.04)
Source: `out/x1_x2_x3_real_results.json` (tick 1 s, 3 repeats, seeds 1000-1002, pacing 0/1/3 s, 27 runs, 720 training events), `out/x1_x2_x3_real_poll025.json` (tick 0.25 s, 2 repeats, 12 runs), summaries `out/x1_x2_x3_real_summary.txt` and `out/x1_x2_x3_real_poll025_summary.txt`.
- Unprotected: AES 18 full, RC4 10 full, 15 spray victims full.
- Threshold (cap only): paced AES 8 full / 10 capped, RC4 6 / 4; burst all full; 5 victims full + 10 capped (single-IP artifact).
- AZ-Kerberos: paced AES 6 full / 12 capped, RC4 6 / 4; burst AES 15 / 3 (restricted in 1 of 3 runs), RC4 10 full; victims 15 full; benign 4 of 600 requests restricted (one seed); audit verified 9 of 9 + 4 of 4 runs.
- Tick 0.25 s: burst AES 13.5 full / 4.5 capped; paced unchanged; benign 0 of 400.
- Denied = 0 in every live attack run. Capped lifetime 3,600 s (level 1). Not tuned afterward.
- Lab limits: all clients 127.0.0.1; attack 4 (stolen credential, new host) not run; 3 repeats, no statistics.

## Assumed, not verified
- KDC is single-threaded (remap without a lock).
- 1 s renew cap effectively disables renewal.
- `k5_print_addr` output format (address kept opaque).
- Impacket attacks against an MIT KDC, and the exact log lines they produce.

## Superseded measurement (do not cite)
`out/x1_x2_x3_evaluation_results.json` (old X1-X3) came from `tests/run_live_experiment.py`, which fed the engine synthetic log lines and inferred outcomes from engine state; its RC4 requests all failed with `BAD_ENCRYPTION_TYPE`. Replaced by `tests/run_live_experiment_real.py` and `out/x1_x2_x3_real_results.json`.

## Survey items not read / not used
Qomplx US11968227, US12438906 (+continuations), IEEE Computer 2024 DOI 10.1109/MC.2024.3434535; Freeman et al. NDSS 2016 "89% recall at 10% FPR" (snippet only — do not cite); AdaBoost ACC 98.0 figures (abstract only); arXiv 2610.07459 / 2609.01931 / 2606.23003 claim about omitted-log detection (unread — do not use); MIT/Heimdal PQ roadmaps.
