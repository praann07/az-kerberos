# 04 — Evaluation plan

Rule: numbers from the survey are **author-reported on different data** and are context, not targets we can claim to beat. We run our own baseline on our own data. Nothing in this file is a result unless marked MEASURED.

## Data
| Source | Use | Status |
|---|---|---|
| Live lab: MIT KDC, ~50 users, ~20 services, benign traffic generator, public attack tools (e.g. Impacket) | Primary evaluation (train/calibrate/test days) | **Not built** — no Linux environment on the dev machine; Impacket-vs-MIT-KDC behaviour unverified |
| `src/azk/simulator.py` | Pipeline testing only | Built; results never reported as evaluation |
| LANL cyber1 (https://csr.lanl.gov/data/cyber1/; 58 days, 1,648,275,307 events; `redteam.txt.gz` = compromise events, not Kerberos-technique labels) | Optional benign-behaviour realism; cannot label Kerberoasting | Not used yet |
| Wiefling RBA dataset (https://zenodo.org/records/6782156; >33M synthesized logins) | Sanity check of risk-score calibration idea only; not Kerberos | Not used yet |
| No public Kerberos-technique-labelled KDC-log dataset found (survey P2) | — | Gap that justifies the lab |

## Experiments
| ID | Question | Method | Metrics |
|---|---|---|---|
| X1 | Does scoring → table → plugin reduce attacker issuances? | Run each attack (Kerberoast AES/RC4, spray, AS-REP, stolen-cred) ×N with plugin on/off, scorer on logs | issuances after detection, time-to-restriction |
| X2 | What does it cost benign users? | Benign days; calibration α sweep | false-restriction rate (events, principals), **victim impact**, extra `kinit` count |
| X3 | Beats a static rule? | `ThresholdRule` and Splunk-style 3σ on 4769 counts on the same logs | detection, FP at matched false-restriction rate |
| X4 | Plugin overhead | `kinit` and TGS-REQ p50/p99, 10k requests, plugin off vs on (table of 50 and 5,000 entries; table swap during load) | added µs/ms |
| X5 | Audit cost and tamper detection | records/s with/without checkpoints; edit/delete/reorder/truncate matrix | throughput, detection rate |
| X6 | Failure modes | table missing/stale/corrupt, scorer killed | KDC keeps issuing; staleness alert fires |

## Survey numbers kept for context (author-reported, with sources in `survey_related_work.md`)
- Kotlaba ICISSP 2020 Table 2: honeypot rule 7/7 TP, 0 FP; `$`-filter 5/5 TP, 0 FP; krbtgt-filter 326 events, 7 TP, 319 FP (private AD logs).
- Kotlaba ICISSP 2021: static rule TP2 FP31 FN1; OC-SVM TP3 FP34 FN0 — **only 3 positive events**.
- F-RBA (arXiv 2412.12324): avg TPR ≈ 88%, step-up only (web login, not Kerberos).
- Wiefling TOPS 2022: blocking 99.5% of naive attackers ⇒ legitimate re-auth every 2nd login.
- Crosby & Wallach 2009: 1,750 events/s incl. DSA signing single core; 10,500/s with signing offloaded; 3 KB proof vs 800 MB hash chain at 80M events.
- No Kerberos work found reports latency overhead of its detector.

## Statistics and honesty rules
Fixed seeds; train/calibration/test on separate days; report counts (TP/FP/FN) not only rates; with few attack instances give intervals or say "n too small"; synthetic numbers labelled SYNTHETIC; never tune on the test day.
