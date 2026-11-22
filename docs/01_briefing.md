# 01 — Project Briefing (22AIE314 Computer Security)

**Title:** AZ-Kerberos — risk-adaptive ticket issuance for stock MIT Kerberos, with a signed hash-chained decision log.
**Status of this document:** final 4-part briefing after the literature survey (`survey_related_work.md`, 85 KB, partial — see §3 caveats). Revised from Draft 1 after the survey and the supervisor critique (stock clients reject custom tickets; per-request ML latency; no public dataset; scope too large).

## 1. PROJECT OVERVIEW
A closed loop around an unmodified MIT krb5 KDC:

1. A **kdcpolicy plugin** (C, krb5 ≥ 1.16 interface) looks up the requesting principal in a memory-mapped **risk table** and, per request, either does nothing, **caps the ticket lifetime / renewable lifetime**, or **denies** the request. It does O(1) work and never calls the model.
2. An **asynchronous scorer** (Python) tails the KDC log, computes per-principal sliding-window features (failed pre-auth, password-spray fan-out, distinct services requested, RC4 tickets, new source address, request rate), scores them (Isolation Forest trained on benign logs only), and publishes the risk table atomically.
3. An **audit log** (hash chain + Ed25519-signed checkpoints) records every risk change, every published table (with its SHA-256 and entries) and every `AZK_POLICY` line the plugin emitted — so each issuance restriction is bound to the score that caused it.

No wire-protocol change, no client change, no custom ticket format.

Syllabus anchors: Unit 2 — Kerberos, user authentication, access-control matrix (the risk table is a dynamic overlay on the KDC's access decision); Unit 1 — intruders, malicious code (Kerberoasting / AS-REP roasting / password spray), digital signatures and hash functions (audit chain); Unit 3 — protection policies, trusted systems (tamper-evident records), disaster recovery (fail-open design).

## 2. EXISTING WORK & BASELINES (all from the survey; "abstract only" items are not relied on)
| Area | Closest work | Author-reported result | Why it is not our design |
|---|---|---|---|
| PQ Kerberos | IETF draft-bokovoy-kitten-pkinit-pqc-02 (rev 2026-09-30) | sizes only: ML-KEM-768 ek 1184 B / ct 1088 B, ML-DSA-65 sig 3309 B; TCP required; no latency | specifies **pure** ML-KEM, hybrid deferred; not our focus |
| PQ via plugin | `kurbu5-pkinit` (Rust ML-KEM PKINIT plugin, stock MIT krb5) | not stated in README read | means **"PQ on stock krb5" is NOT a novelty claim** — PQ dropped from scope |
| Kerberos IDS | Kotlaba ICISSP 2020/2021; Grippo & Kholidy arXiv 2301.00044; Splunk 3-sigma 4769 rule; Qomplx US11477245B2 | 2020: honeypot 7/7 TP 0 FP, `$`-filter 5/5 TP 0 FP; 2021: OC-SVM TP3 FP34 FN0 (only 3 positives) | every one read is **alert-only**; none changes issuance |
| Adaptive auth | F-RBA (arXiv 2412.12324), Wiefling TOPS 2022, OpenStack RBA (arXiv 2303.12361), MS Entra CAE (vendor doc) | F-RBA avg TPR ≈ 88%; Wiefling: 99.5% naive attackers blocked ⇒ legit reauth every 2nd login | web/SSO step-up or revocation, not Kerberos ticket lifetime; OpenStack gates issuance synchronously, lifetime not adapted |
| Audit logs | Crosby & Wallach USENIX Sec 2009; Schneier & Kelsey 1998/99; Ma & Tsudik 2008; Marson & Poettering 2013; journald FSS; RFC 5848 | C&W: 1,750 events/s incl. DSA signing, 1 core | hash-chained logging is old and standard — **not a novelty claim** |

## 3. THE NOVELTY GAP (stated narrowly on purpose)
Claim: **a closed loop that turns asynchronous anomaly scores on KDC logs into enforced ticket-lifetime/renewal caps or denial, on a stock MIT krb5 KDC with no wire change, with the enforcement decisions bound into a signed hash-chained log.** Contribution is the *combination and its measurement* (time-to-restriction, issuances-after-detection, false-restriction rate incl. victim impact, plugin overhead), not any single ingredient.

Evidence for the gap: COMBO CHECK in the survey — no single prior work found doing (a) async scoring that changes Kerberos issuance + (b) on stock MIT krb5 + (c) a signed hash-chained log. **This is a weak negative** (≈20 source calls per pillar; IEEE Xplore / ACM DL / NDSS / S&P / CCS not searched directly; Semantic Scholar rate-limited).

Novelty threats NOT ruled out (read these before submission):
- Qomplx US12580898 "Master ledger and local host log extension detection and mitigation of forged authentication attacks" was read on 2026-11-22: detection plus post-hoc ticket destruction driven by a master ledger of authentication objects held by domain-controller agents; one hash per object (not a hash chain), no ML risk score, no ticket-lifetime adaptation, no signed log, not stock MIT krb5. Partial overlap, not a combination threat. Qomplx US11477245B2: its "mitigation" is analyst recommendations (partial grep, not exhaustive). Still unread: US11968227, US12438906, continuations US12452307 / US12641123; IEEE Computer 2024 DOI 10.1109/MC.2024.3434535.
- Vendor/community work on MIT/Heimdal kdcpolicy plugins and Red Hat's PQ Kerberos prototyping (QARC) not fully searched.
- Per-source baselining on KDC events already exists (Splunk, Kotlaba), so "ML on Kerberos logs" alone is **not** novel.

## 4. EXPECTED RESULTS & METRICS — hypotheses, NOT results
| Metric | How measured | Baseline | Hypothesis (to be tested; may fail) |
|---|---|---|---|
| Issuances after detection (per attack, lower is better) | live-KDC attack runs | threshold rule on same logs | scorer + table cuts issuances vs. threshold rule at equal false-restriction rate |
| Time-to-restriction | log time → first capped/denied issuance | threshold rule | bounded by tail + publish lag (design: seconds) |
| False-restriction rate (events and principals) incl. attack **victims** | benign days + attack days | threshold rule | calibrated to α=1% by construction on benign data; drift must be measured |
| KDC overhead with plugin | `kinit` / TGS-REQ p50/p99, plugin on/off | no plugin | sub-millisecond (design: one `stat` per second + hash probe) — **unmeasured, plugin never compiled** |
| Audit throughput / proof cost | records/s, bytes per checkpoint | Crosby & Wallach 1,750 events/s incl. DSA | higher, because signing only at checkpoints — **unmeasured** |
| Tamper detection | edit/delete/reorder/truncate tests | — | all detected; tail truncation only with external anchor (tested in unit tests) |

First synthetic smoke run (pipeline check only; see `05_plan_and_status.md` §2): the Isolation Forest did **not** beat the threshold baseline on false-restrictions (3.3% vs 0.4% of benign events) or on issuances-after-detection for Kerberoasting. Reported as found; no tuning to flatter it.
