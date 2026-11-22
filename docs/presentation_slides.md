# AZ-Kerberos: Presentation Slides
**Risk-Adaptive Ticket Issuance for Stock MIT Kerberos with Cryptographic Decision Binding**  
*Course: 22AIE314 Computer Security*  

---

## Slide 1: Title & Overview
### AZ-Kerberos
**Risk-Adaptive Ticket Issuance for Stock MIT Kerberos**
- **Problem:** Static, unconstrained 10-hour tickets; alert-only IDSs leave an unmitigated attack window; in-line ML adds 12.9 ms latency.
- **Solution:** A decoupled closed-loop system enforcing dynamic lifetime/renewal caps or denials on stock MIT krb5 at **about 14–20 nanoseconds** per lookup.
- **Key Results (real live-KDC runs, 3 repeats):** closed loop works on stock krb5 1.20.1 (post-detection tickets capped to 1 h; audit verifies); but the attacker still got 6 of 18 AES tickets at full lifetime (15 of 18 in a burst), denial never fired, and a threshold rule did about as well; no victim capped/denied in the spray; 64,400 events/s audit throughput.

---

## Slide 2: Background & Threat Context
### Kerberos Structural Vulnerability
- **Static Trust Assumption (RFC 4120):** Authentication decisions are binary. Once verified, client receives a 10-hour TGT and 10-hour service tickets.
- **No Revocation Mechanism:** The KDC cannot revoke or modify already-issued tickets without re-keying services.
- **Exploitation by Adversaries:**
  - *Kerberoasting:* Request service tickets across many SPNs and crack offline.
  - *Password Spraying:* Low-and-slow authentication probes against multiple users.
  - *Compromised Credentials:* Broad lateral movement across the enterprise.

---

## Slide 3: The Architectural Dilemma
### Why Existing Solutions Fail
1. **Alert-Only IDSs (Splunk, Kotlaba, Defender):**
   - Detect anomalies in event logs, but *never alter ticket issuance*.
   - By the time a human SOC analyst responds, hashes are already harvested.
2. **In-Line Machine Learning:**
   - Evaluating an Isolation Forest on the synchronous request path takes **12.9 ms**.
   - KDC budget is sub-millisecond; in-line models cause thread starvation and DoS.
3. **Protocol Modification (e.g. custom tickets):**
   - Incompatible with stock client OSes (Windows, Linux, macOS).

---

## Slide 4: AZ-Kerberos System Architecture
### The Decoupled Closed Loop
```
  [ Clients / Workstations ]  -- AS-REQ / TGS-REQ -->  [ MIT krb5 KDC ]
                                                            |
                                                 kdcpolicy_azk.so (C Plugin)
                                                 * O(1) FNV-1a Hash + Linear Probe
                                                 * ~14-20 ns lookup in mmap table
                                                 * Enforces caps or denial
                                                            ^
                                                 risk_table.bin (Atomic rename)
                                                            |
  [ Audit Log (audit.log) ]  <-- append --  [ Asynchronous Scorer (Python) ]
  * SHA-256 hash chain                      * Tails KDC journal / syslog
  * Ed25519-signed checkpoints              * 300s sliding window features
  * 64,476 events/sec                       * Benign-trained Isolation Forest
                                            * T1 Victim Lock-Out Shield
```

---

## Slide 5: The C Enforcement Plugin (`kdcpolicy_azk.c`)
### Nanosecond Enforcement on Stock MIT krb5
- **Standard Pluggable Interface:** Implements `krb5_kdcpolicy_vtable` (introduced in krb5 1.16).
- **Request Hooks:**
  - `check_as()`: Enforces caps/denials on initial login.
  - `check_tgs()`: Extracts requesting client from decrypted `ticket->enc_part2->client` structure.
- **Zero-Allocation Memory-Mapped Lookup:**
  - Binary table layout: 32-byte header (`AZRT`), 88-byte packed slots.
  - FNV-1a-64 hashing with open-addressing linear probing.
  - **Measured lookup latency: about 14–20 nanoseconds** (14.2 ns reported run, 19.6 ns re-run; roughly 10^6 x faster than a Python sklearn call, not like-for-like).
- **Fail-Open by Design:**
  - If table is missing, corrupt, or older than 300 seconds, the plugin automatically fails open (10-hour standard tickets).

---

## Slide 6: Threat T1: The Victim Lock-Out Dilemma
### Preventing Attacker Weaponization of Anomaly Detection
- **The Threat:** Attacker deliberately fails pre-authentication for targeted executive accounts. A naive detector escalates risk and locks out legitimate employees!
- **AZ-Kerberos Defense Shield:**
  1. *Preauth Failure Capping:* Accounts with only pre-auth failures are capped at **Level 2** (10-minute ticket lifetime, never denial). The user can still log in and work!
  2. *Two-Signal Rule for Denial:* Level 3 denial requires at least two independent indicators (e.g. service fan-out + RC4 requests).
  3. *Global Realm Circuit Breaker:* If $>25\%$ of users are restricted, breaker trips, degrading all escalations to Level 1.
- **Empirical Validation:** 0 legitimate users denied during 15-target password spray attack.

---

## Slide 7: Cryptographically Bound Audit Ledger
### Non-Repudiation for Access Decisions
- **SHA-256 Hash Chain:** Every record links cryptographically to the previous record hash.
- **Amortized Digital Signatures:** Ed25519 signatures generated at periodic checkpoints ($\kappa = 64$ records).
- **Decision Binding:** Plugin emits `AZK_POLICY` syslog events with `table_gen` timestamp; engine records `policy_applied` in the audit log.
- **Performance:**
  - Ingestion throughput: **64,476 events/sec** (Crosby & Wallach report 1,750 events/s with per-event DSA signing on other hardware; ours signs every 100 events, so not like-for-like).
  - Verification throughput: **81,748 records/sec**.
  - All 6 of our own tamper test vectors detected (bit-flip, deletion, reordering, insertion, forged key, anchored truncation); truncation without an anchor is NOT detected.

---

## Slide 8: Empirical Evaluation: Live KDC Lab
### Real-World Testing on Stock MIT Kerberos 1.20.1
- **Environment:** Ubuntu 24.04 LTS (WSL2), Linux 6.18, MIT Kerberos 1.20.1.
- **Realm Configuration:** `LAB.TEST` with 50 user principals and 20 service principals (AES-256 and RC4-HMAC).
- **Experiments Executed:**
  - **X4:** KDC request latency and microbenchmarks.
  - **X5:** Audit ledger throughput and tamper matrix.
  - **X6:** Fail-open fault injection (missing, corrupt, stale tables).
  - **X1–X3:** End-to-end live attack mitigation vs. baselines.

---

## Slide 9: Experimental Results: Latency & Overhead
### Microbenchmarks & Live Request Overhead
| Configuration | Table Size | Median ($p_{50}$) Latency | Per-Lookup Cost |
|---|---|---|---|
| In-Line Isolation Forest | N/A | 12.9 ms | 12,900,000 ns |
| **AZ-Kerberos C Table** | **50 entries** | **256.6 ms (client round-trip)** | **13.4 ns** |
| **AZ-Kerberos C Table** | **5,000 entries** | **252.5 ms (client round-trip)** | **14.2 ns (re-run 19.6)** |
| Stock KDC (No Plugin) | N/A | 467.4 ms (client round-trip) | 0 ns |

- In-memory table lookup costs **about 14–20 nanoseconds** per request.
- End-to-end `kinit` latency shows no overhead measurable above noise (the stock KDC row is slowest, so these 60-sample runs are noisy, not a speed-up).

---

## Slide 10: Experimental Results: Live Attack Mitigation
### Comparison Across Operational Modes
| Metric | Unprotected Stock KDC | Static Threshold Baseline | AZ-Kerberos (This Work) |
|---|---|---|---|
Tickets by outcome: full / capped (1 h) / denied. Mean of 3 repeats, scorer tick 1 s, real `kinit`/`kvno` calls.

| Metric | Unprotected Stock KDC | Static Threshold Baseline | AZ-Kerberos (This Work) |
|---|---|---|---|
| **AES Kerberoast (18), paced 1 s / 3 s** | 18 / 0 / 0 | 8 / 10 / 0 | 6 / 12 / 0 |
| **AES Kerberoast (18), unpaced burst** | 18 / 0 / 0 | 18 / 0 / 0 | 15 / 3 / 0 |
| **RC4 Kerberoast (10), paced** | 10 / 0 / 0 | 6 / 4 / 0 | 6 / 4 / 0 |
| **Spray victims (15) logging in** | 15 / 0 / 0 | 5 / 10 / 0 (single-IP lab artifact) | 15 / 0 / 0 |
| **Benign requests restricted (of 200)** | 0 | 0 | 1.33 (4 in 1 of 3 runs) |
| **Time to first restriction, AES** | none | 8.6 s / 24.5 s | 6.4 s / 18.5 s |

- Denied = 0 in every live attack run; the deny path is verified only by X6 and manual smoke tests.
- Capped tickets are still crackable offline; the cap only limits later replay.
- No demonstrated advantage over the threshold rule (6 vs 8 full AES tickets, equal RC4). All clients are 127.0.0.1; 3 repeats; no statistical test.

---

## Slide 11: Summary of Contributions
1. **Closed-Loop Design:** Decoupled risk-adaptive ticket issuance on stock MIT Kerberos with zero client/wire changes (partial literature search found no prior work combining these; not a proof of first).
2. **Nanosecond Request Path:** about 14–20 ns in-memory lookup vs 12.9 ms for a Python sklearn call (not like-for-like).
3. **Threat T1 observation:** no victim capped or denied in 15-target password-spray runs (also none without protection); no formal proof.
4. **Cryptographic Binding:** 64.4k eps audit ledger linking KDC decisions to anomaly scores and table hashes.
5. **Live Evaluation:** Scripted Kerberoast and spray attacks on a live MIT KDC in a lab realm; 3 repeats; modest effect (detection after ~6 services, denial never fired, no gain over a threshold rule). Stolen-credential attack not run.

---

## Slide 12: Q & A
### Thank You!
- **Artifacts:** Full source code, C plugin, test suites, and evaluation scripts available in repository.
- **Paper:** Available in Markdown (`docs/conference_paper.md`) and IEEE LaTeX (`docs/conference_paper.tex`).
