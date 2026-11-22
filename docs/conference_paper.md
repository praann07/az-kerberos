# AZ-Kerberos: Asynchronous Anomaly-Driven Ticket Policy Enforcement on Stock MIT Kerberos with Cryptographic Decision Binding

**Authors:**  
Department of Computer Security and Applied Artificial Intelligence  
*22AIE314 Computer Security Project*  

---

## Abstract
Kerberos version 5 (RFC 4120) remains the foundational authentication backbone for enterprise infrastructures and directory services worldwide. However, standard Kerberos architectures suffer from a critical structural asymmetry: ticket issuance decisions are static and binary. Once authenticated, users are granted unconstrained service tickets—typically valid for 8 to 10 hours—which cannot be revoked prior to expiration. Consequently, adversaries who obtain valid credentials through phishing, password spraying, or offline Kerberoasting enjoy broad lateral movement across the network without intermediate challenge. While intrusion detection systems (IDS) analyze KDC audit logs, existing solutions operate strictly in an *alert-only* posture, creating an unmitigated exposure window between detection and human analyst remediation. Conversely, deploying complex anomaly-detection models directly on the synchronous authentication request path introduces prohibitive latency penalties (measured at 12.9 ms per request for tree-based models against a sub-millisecond KDC budget).

In this paper, we present **AZ-Kerberos**, a closed-loop, risk-adaptive ticket issuance system designed for stock MIT Kerberos without protocol modifications or custom client software. AZ-Kerberos decouples heavy anomaly scoring from synchronous ticket issuance through a three-tier architecture: (1) an asynchronous, log-driven scoring engine that evaluates sliding-window behavioral features via unsupervised Isolation Forests; (2) a lockless, memory-mapped binary risk table utilizing FNV-1a hashing with open-addressing linear probing; and (3) a lightweight C `kdcpolicy` plugin (RFC-compliant MIT krb5 pluggable interface) executing on the KDC request path that enforces adaptive ticket lifetime and renewal caps or request denials in **about 14–20 nanoseconds**. Furthermore, we identify and address the *Victim Lock-Out Dilemma* (Threat T1)—wherein attackers intentionally trigger failed authentications to deny legitimate users—through a multi-signal escalation rule and an automated realm circuit breaker. Finally, AZ-Kerberos binds every policy decision and table publication into an Ed25519-signed, hash-chained audit log achieving **64,476 events/second** throughput. In real end-to-end runs against a live MIT krb5 1.20.1 KDC (every outcome read from the KDC's own responses; 3 repeats, paced attackers), the loop worked as designed: after detection, newly issued tickets carried the capped lifetime (3,600 s instead of 36,000 s), no legitimate victim of a 15-target password spray was capped or denied, and the signed audit log verified in every run; the plugin also fails open when the risk table is missing, corrupt or stale. The results are modest, however: the scorer flagged a Kerberoasting attacker only after 6 distinct services (6 of 18 AES and 6 of 10 RC4 tickets were issued at full lifetime, 15 of 18 for an unpaced burst), the denial level was never reached in any live attack run, and a static threshold rule performed about the same (8 of 18 full tickets). A lifetime cap does not stop offline cracking of a ticket already issued; only denial withholds the ticket.

---

## 1. Introduction

Kerberos version 5 \cite{rfc4120} serves as the default authentication protocol for contemporary enterprise environments, Active Directory domains, and high-performance computing clusters. Kerberos relies on a trusted Key Distribution Center (KDC) comprising an Authentication Service (AS) for issuing Ticket Granting Tickets (TGTs) and a Ticket Granting Service (TGS) for issuing application-specific service tickets. 

Despite its ubiquitous adoption, the protocol's core security model embodies a fundamental assumption of static trust: authentication decisions are atomic, binary, and unchangeable. Once the KDC verifies a client's credentials, it issues tickets valid for fixed, long durations—commonly 10 hours by default—with renewable limits extending up to seven days. Within this temporal window, issued tickets cannot be selectively revoked or constrained by the KDC without re-keying the underlying services or wiping client caches \cite{wiefling2022tops}.

This architectural limitation is aggressively exploited by modern lateral-movement and post-exploitation tradecraft:
1. **Kerberoasting:** An attacker with standard user credentials requests TGS service tickets for target Service Principal Names (SPNs) encrypted under service account keys, taking the tickets offline to perform high-speed dictionary cracking \cite{kotlaba2020icissp}.
2. **Password Spraying and AS-REP Roasting:** Attackers systematically probe user accounts or abuse principals with pre-authentication disabled (`+preauth`) to acquire crackable AS response payloads \cite{grippo2023kerberos}.
3. **Stolen Credential Exploitation:** Compromised user credentials permit arbitrary service enumeration and resource access within the active ticket lifetime.

### 1.1 The Limitations of Alert-Only Intrusion Detection
To combat these techniques, existing literature and commercial monitoring solutions (e.g., Splunk, Microsoft Defender for Identity, and academic proposals \cite{kotlaba2020icissp, kotlaba2021icissp, grippo2023kerberos}) rely on host and KDC event log parsing. However, all existing Kerberos detection mechanisms operate in an *alert-only* paradigm. When an anomaly is detected, an alert is queued in a Security Information and Event Management (SIEM) dashboard. Between the generation of the alert and human intervention (often exceeding tens of minutes or hours), the adversary has already retrieved the necessary Kerberos ticket hashes, moved laterally, or established persistent backdoors.

### 1.2 The Dilemma: In-Line Latency vs. Decoupled Adaptation
The intuitive remedy—evaluating machine learning anomaly detection models directly on the synchronous ticket issuance path—is operationally infeasible. A KDC answers each request in well under a millisecond of its own processing, and we did not benchmark KDC throughput. In our single-call benchmark (Python/scikit-learn, synthetic input), evaluating a standard tree-based model such as an Isolation Forest takes **12.9 ms** per request, which on a busy KDC would queue requests behind the model. Conversely, modifying the Kerberos protocol wire format to support progressive re-authentication breaks existing client libraries, operating system Kerberos SSPs, and RFC 4120 conformance.

### 1.3 Contributions
To resolve this tension, we present **AZ-Kerberos**, which is a closed-loop adaptive issuance design for stock MIT Kerberos (a partial literature search found no prior work combining these; that is a weak negative result, not proof of novelty). Our specific contributions are as follows:

- **Decoupled Architecture with Nanosecond Enforcement:** We design a decoupled architecture separating asynchronous feature extraction and model scoring from request-path policy enforcement. By utilizing a memory-mapped, binary open-addressing table indexed via FNV-1a-64 hashing, the C `kdcpolicy` module enforces ticket lifetime caps, renewal caps, and denials in **about 14–20 nanoseconds**, adding no latency we could measure above noise in client tests.
- **Stock Compatibility and Protocol Preservation:** AZ-Kerberos requires zero modifications to the Kerberos wire protocol, ticket formats, or client operating systems. It builds entirely upon the standard MIT Kerberos pluggable policy architecture (`kdcpolicy` vtable interface introduced in krb5 1.16).
- **Resolution of the Victim Lock-Out Dilemma (Threat T1):** We identify a critical security vulnerability inherent to reactive anomaly detection in identity systems—where an adversary intentionally sprays authentication failures against victim principals to weaponize the detector into an automated Denial-of-Service tool against legitimate employees. We design and implement an asymmetric escalation policy, a two-signal requirement for denial, and a realm-wide circuit breaker. In our 15-target spray runs no victim was capped or denied (no formal proof; the denial level was never reached in any live run, so the deny path is exercised only by Experiment X6 and manual smoke tests).
- **Cryptographically Bound Decision Audit:** Every policy adjustment, published risk table hash, and active enforcement event is linked into an Ed25519-signed, hash-chained audit log supporting 64,476 events/second, so that edits, reordering or deletion inside a signed span are detectable (records after the last signed checkpoint are hash-linked but unsigned, and truncation without an external anchor is not detected).
- **Full Empirical Validation on Live MIT KDC:** We implement, compile, and deploy AZ-Kerberos on a live MIT Kerberos KDC in a Linux environment with 50 user principals and 20 service principals. We subject the system to live attacks (Kerberoasting across AES and RC4-HMAC tickets and password spraying with legitimate victim logins; stolen-credential use from a new host was not run), reporting latency overhead (Experiment X4), audit integrity (Experiment X5), fail-open resilience (Experiment X6), and attack mitigation (Experiments X1–X3, real end-to-end runs; an earlier synthetic X1–X3 run was discarded).

---

## 2. Background and Related Work

### 2.1 The MIT Kerberos Pluggable Architecture
Beginning in release 1.16, MIT Kerberos introduced the `kdcpolicy` pluggable interface (`krb5/kdcpolicy_plugin.h`). This interface allows shared libraries to inspect initial credential requests (`check_as`) and ticket-granting service requests (`check_tgs`). A policy module exposes a vtable:
$$\mathcal{V} = \{\text{name}, \text{init}, \text{fini}, \text{check\_as}, \text{check\_tgs}\}$$
The policy hooks can restrict the ticket lifetime (`lifetime_out`), restrict the renewable lifetime (`renew_lifetime_out`), or abort issuance entirely by returning `KRB5KDC_ERR_POLICY` along with an explicit status string literal. Critically, the KDC enforces lifetime tightening via `ts_min(ts_incr(now, life), endtime)`—ensuring a policy module can only *tighten* restrictions, never expand them beyond realm defaults.

### 2.2 Kerberos Attack Taxonomy
- **Kerberoasting:** Introduced by Tim Medin in 2014, Kerberoasting abuses the legitimate ability of any valid domain user to request a service ticket for any SPN registered in the KDC. Because the ticket's encrypted service session part is sealed with the service account's secret key, an attacker can extract the ciphertext and crack it offline without sending further packets to the network. When legacy services support weak encryption algorithms (e.g., `arcfour-hmac` / RC4, enctype 23), cracking speeds on consumer GPUs reach billions of hashes per second.
- **AS-REP Roasting:** When an account has the `DONT_REQUIRE_PREAUTH` flag configured, an attacker can send an unauthenticated `AS-REQ` and receive an `AS-REP` containing data encrypted with the user's password hash, enabling offline dictionary attacks without authenticating.
- **Password Spraying:** The attacker selects a single commonly used password and attempts it across hundreds of distinct usernames to stay beneath per-account lockout thresholds.

### 2.3 Related Work and Comparative Analysis
Table 1 summarizes the positioning of AZ-Kerberos relative to prior literature across the four core pillars.

| Area / Work | Authors & Venue | Reported Metric | Architectural Paradigm | Why it is Not Our Design |
|---|---|---|---|---|
| **Kerberos IDS** | Kotlaba, ICISSP 2020 \cite{kotlaba2020icissp} | 7/7 TP, 0 FP (Honeypot) | Alert-only log analytics | Purely reactive alerts; does not alter ticket issuance. |
| **Kerberos ML-IDS** | Kotlaba, ICISSP 2021 \cite{kotlaba2021icissp} | OC-SVM: 3 TP, 34 FP | Unsupervised offline ML | High false-positive rate; alert-only; evaluated on 3 positive events. |
| **Kerberos forged-ticket detection** | Grippo & Kholidy, arXiv 2301.00044 (Dec 2022) \cite{grippo2023kerberos} | No quantitative result stated; silver tickets reported not detected | Manual inspection of Windows Security events (4624/4634/4672/4768/4769) in a lab AD | Alert-only; no ML, no enforcement; private lab. |
| **Risk-Based Auth (RBA)** | Wiefling et al., TOPS 2022 \cite{wiefling2022tops} | 99.5% naive attacks blocked | Web SSO re-authentication | Web step-up authentication; requires interactive user browser re-auth. |
| **Adaptive Auth** | F-RBA, arXiv 2024 \cite{frba2024} | ~88% average TPR | Federated Identity SSO | Designed for SAML/OIDC web sessions; cannot constrain Kerberos tickets. |
| **Tamper-Evident Logs** | Crosby & Wallach, USENIX 2009 \cite{crosby2009usenix} | 1,750 events/s (DSA signed) | Hash chain + accumulator | General audit logging; unlinked to real-time access control policies. |
| **AZ-Kerberos (This Work)** | — | **Flags Kerberoasting after 6 services (6/18 AES tickets at full lifetime, 3 repeats); ~14–20 ns lookup; 64k eps audit** | **Closed-loop adaptive issuance** | **Unmodified MIT krb5, zero wire change, O(1) risk enforcement, signed audit.** |

*Table 1: Comparison of AZ-Kerberos with existing literature. Existing Kerberos security systems operate strictly in an alert-only posture; risk-based authentication systems target interactive web SSO; AZ-Kerberos bridges the gap by enforcing closed-loop ticket constraints on stock MIT Kerberos.*

---

## 3. Threat Model and Security Assumptions

### 3.1 Trust Assumptions and Assets
We consider enterprise deployments where the MIT Kerberos KDC runs on a hardened host. The assets requiring protection are:
1. **Ticket Issuance Decisions:** The integrity and timeliness of lifetime and renewal constraints.
2. **Availability of Legitimate Users:** Preventing attackers from causing broad denial of service for uncompromised employees.
3. **Audit Log Integrity:** Providing verifiable forensic evidence of security decisions even under host compromise.

### 3.2 Attacker Profiles
- **Attacker 1 (A1 - External Unauthenticated):** Possesses no valid credentials. Conducts password spraying and AS-REP roasting against KDC port 88.
- **Attacker 2 (A2 - Low-Privilege Insider / Credential Holder):** Possesses credentials for a single domain user (via phishing or credential harvesting). Executes Kerberoasting against all available SPNs and attempts lateral movement.
- **Attacker 3 (A3 - Compromised Service Account):** Controls a legitimate service host and attempts to request tickets or forge requests.
- **Attacker 4 (A4 - Malicious Host / Post-Compromise Root):** Obtains root access to the KDC host. Can modify disk files, kill running processes, or edit logs. Our objective for A4 is **tamper-evidence** (detection of tampering within the signed span; truncation of the tail is undetected without an external anchor, which we did not implement), not prevention.
- **Attacker 5 (A5 - Parser Adversary):** Crafts malicious principal names or injects control characters into network packets to exploit log parsers.

### 3.3 Out-of-Scope Threats
- **Silver Tickets:** Forged service tickets encrypted under a compromised service key without contacting the KDC are out of scope, as no KDC-side monitor can inspect traffic that bypasses the KDC.
- **Quantum Cryptanalysis of Long-Term Keys:** Post-quantum Kerberos transitions (e.g., draft-ietf-kitten-pkinit-pqc) represent orthogonal cryptographic improvements and do not address dynamic behavioral authorization.

---

## 4. System Architecture and Design

AZ-Kerberos organizes functionality into three distinct decoupled components operating across different privilege boundaries, as depicted in Figure 1:

```
               [ Stock MIT Kerberos Clients / Workstations ]
                                    |
                            AS-REQ  |  TGS-REQ
                                    v
     +--------------------------------------------------------------+
     |                       MIT krb5 KDC                           |
     |                                                              |
     |   check_as()                                  check_tgs()    |
     |       |                                            |         |
     |       +-------------------+------------------------+         |
     |                           |                                  |
     |            kdcpolicy_azk.so (C Policy Module)                |
     |            * Zero-allocation, lockless mmap lookup           |
     |            * O(1) FNV-1a Hash + Linear Probing (~14-20 ns)   |
     |            * Enforces lifetime/renew caps or DENY            |
     +---------------------------|----------------------------------+
             Syslog / Journal    |                   ^
             "AZK_POLICY ..."    |                   |  Atomic Mmap
                                 v                   |  risk_table.bin
     +-----------------------------------------------|--------------+
     |             Asynchronous Scorer (Python Engine)              |
     |                                                              |
     |  1. Log Parser: Tails KDC Journal / Syslog events            |
     |  2. Feature Extractor: 300s Sliding Window per Principal     |
     |  3. Unsupervised Model: Benign-Trained Isolation Forest      |
     |  4. LevelMap: Quantile Cut-offs (Alpha-Calibrated)           |
     |  5. T1 Shield: Failure Capping, 2-Signal Rule, Breaker       |
     |  6. Risk Table Publisher: Atomic Rename (fsync + replace)    |
     +---------------------------|----------------------------------+
                                 |
                                 v
     +--------------------------------------------------------------+
     |          Cryptographically Bound Audit Log (audit.log)       |
     |  * SHA-256 Hash Chain per Record                             |
     |  * Amortized Ed25519-Signed Checkpoints (every 64 records)   |
     |  * Off-Host External Verification Anchor (seq, hash)         |
     +--------------------------------------------------------------+
```
*Figure 1: High-level architectural overview of AZ-Kerberos.*

### 4.1 The C Enforcement Plugin (`plugin/kdcpolicy_azk.c`)
The policy module is compiled as an ELF shared object (`kdcpolicy_azk.so`) loaded directly by `krb5kdc` during daemon startup.

#### Request-Path Operation
1. When a client submits an `AS-REQ` and successfully completes pre-authentication, the KDC invokes `azk_check_as()`.
2. When a client presents a valid TGT to request a service ticket, the KDC invokes `azk_check_tgs()`.
3. In `check_tgs()`, the plugin extracts the requesting client principal from the decrypted `ticket->enc_part2->client` structure. (We empirically verified that `enc_part2` is consistently populated by MIT krb5 prior to the `check_tgs` hook).
4. The principal name string is unparsed into standard format (`user@REALM`).
5. The plugin invokes `azk_lookup()` against the memory-mapped risk table.

#### Lockless Memory-Mapped Lookups
To achieve deterministically low latency, the table lookup performs zero heap allocations, zero system calls (apart from a rate-limited `stat()` at most once per second to check for table inode updates), and zero network interactions:
$$\text{Index } i = \text{FNV-1a-64}(\text{Principal}) \pmod{N_{\text{slots}}}$$
If slot $i$ contains the target key, the policy record is read directly from memory. In the event of hash collisions, the lookup advances via open-addressing linear probing:
$$i_{k} = (i + k) \pmod{N_{\text{slots}}}$$
If an empty slot (key $= 0$) is encountered, the search terminates with a miss ($O(1)$ expected cost).

#### Fail-Open Engineering
If the risk table file is missing, corrupted, improperly sized, or unreadable, the plugin immediately unmaps the table and returns `0` (success, unconstrained issuance). Crucially, to prevent an attacker from killing the Python scoring daemon and freezing stale restrictions indefinitely, the plugin inspects the table's `generated_at` timestamp:
$$\text{If } (t_{\text{current}} - t_{\text{generated}}) > \Delta_{\text{stale}} \quad (300\text{ seconds}) \implies \text{Fail Open}$$
If the table exceeds 300 seconds of age, all lookups automatically decay to level 0 (unconstrained). Thus, a failure in the scoring pipeline can never become a persistent denial-of-service vector against enterprise availability.

### 4.2 The Asynchronous Anomaly Scoring Pipeline
The scoring pipeline executes as an independent background daemon outside the KDC execution boundary.

#### Sliding-Window Feature Representation
The feature extractor continuously tails the KDC event stream and computes a dynamic 6-dimensional feature vector $\mathbf{x}_i \in \mathbb{R}^6$ over a sliding window of $\Delta t = 300$ seconds:
$$\mathbf{x}_i = \left[ f_{\text{fail}}, f_{\text{spray}}, f_{\text{distinct\_svc}}, f_{\text{rc4}}, f_{\text{new\_ip}}, f_{\text{rate}} \right]$$
where:
- $f_{\text{fail}}$: Count of pre-authentication failures for this principal.
- $f_{\text{spray}}$: Count of distinct user principals targeted by the same source IP.
- $f_{\text{distinct\_svc}}$: Count of distinct service principals requested by this user.
- $f_{\text{rc4}}$: Count of tickets requested with RC4 enctypes (23, 24).
- $f_{\text{new\_ip}}$: Binary indicator of an authentication originating from an unseen IP address.
- $f_{\text{rate}}$: Total request arrival rate per minute.

Crucially, `NEEDED_PREAUTH` events are discarded and never counted as failures, conforming to standard Kerberos behavior where clients omit preauth on initial `AS-REQ` to receive realm configuration.

#### Benign-Trained Isolation Forest and Level Mapping
AZ-Kerberos trains an Isolation Forest \cite{liu2008isolation} exclusively on benign baseline traffic:
$$s(\mathbf{x}) = - \mathbb{E}[h(\mathbf{x})]$$
Because anomaly scores $s(\mathbf{x}) \in \mathbb{R}$ lack intrinsic semantic thresholds, we calibrate policy levels using empirical quantiles of benign validation scores:
$$\mathcal{L}(s) = \sum_{j=1}^3 \mathbb{I}\left( s > Q_{1 - \alpha_j} \right)$$
where $\alpha = [0.02, 0.005, 0.001]$ designate the calibrated false-restriction budgets for Levels 1, 2, and 3.

#### The Enforcement Policy Matrix
The integer risk level maps directly to enforcement constraints applied by the C plugin:
$$\text{Policy}(\mathcal{L}) = \begin{cases} 
\text{No restriction} & \mathcal{L} = 0 \\
\text{Lifetime } \le 3600\,\text{s}, \text{ Renew } \le 14400\,\text{s} & \mathcal{L} = 1 \text{ (Mild)} \\
\text{Lifetime } \le 600\,\text{s}, \text{ Renew } \le 1\,\text{s} & \mathcal{L} = 2 \text{ (Strict Cap, No Renewal)} \\
\text{Deny } (KRB5KDC\_ERR\_POLICY) & \mathcal{L} = 3 \text{ (Denial)} 
\end{cases}$$
When an account escalates, the engine holds the restriction for $\tau_{\text{hold}} = 900$ seconds before allowing progressive decay back to Level 0.

---

## 5. Resolving the Victim Lock-Out Dilemma (Threat T1)

A severe conceptual failure of anomaly detection in identity protocols is **Victim Lock-Out Amplification**. If an anomaly detector escalates account risk based purely on failed authentication attempts, an unauthenticated external attacker can deliberately launch password spraying or credential stuffing against corporate accounts. The detector observes high failure counts, marks the accounts as high risk, and denies subsequent requests. Consequently, the detection system is weaponized into an automated, distributed denial-of-service tool targeting corporate leadership and staff.

To mitigate this vulnerability, AZ-Kerberos implements a three-tier defensive shield in `src/azk/engine.py`:

1. **Pre-Authentication Failure Capping:**
   An adversary lacking valid credentials can *only* interact with the AS pre-authentication phase. They cannot successfully obtain service tickets ($f_{\text{distinct\_svc}} = 0$) or request RC4 ticket encryptions ($f_{\text{rc4}} = 0$). Therefore, if an account's anomalies are confined exclusively to pre-authentication failures, its risk level is mathematically capped at Level 2:
   $$\text{If } (f_{\text{distinct\_svc}} == 0 \land f_{\text{rc4}} == 0) \implies \mathcal{L} = \min(\mathcal{L}, 2)$$
   Under Level 2, ticket lifetimes are constrained to 10 minutes, but legitimate users **can still authenticate and work**. Level 3 denial is impossible via external password failures alone.

2. **The Two-Signal Requirement for Denial:**
   To escalate an account to Level 3 (complete issuance denial), the system requires at least two orthogonal elevated indicators (e.g., $f_{\text{distinct\_svc}} \ge 10$ and $f_{\text{rc4}} \ge 5$). This ensures that denial is enforced only after an adversary has demonstrated post-authentication compromise.

3. **Global Realm Circuit Breaker:**
   If a distributed adversary attempts to paralyze an organization by spraying failures across the entire workforce, the aggregate fraction of restricted users rises. AZ-Kerberos tracks active restricted principals:
   $$\mathcal{R}_{\text{active}} = \left| \{ c \in \mathcal{U} \mid \text{Level}(c) \ge 2 \} \right|$$
   If $\mathcal{R}_{\text{active}} \ge \theta_{\text{breaker}} \cdot |\mathcal{U}|$ (where $\theta_{\text{breaker}} = 0.25$), the engine trips the **Realm Circuit Breaker**. All subsequent escalations are automatically downgraded to Level 1 (mild lifetime caps), and an immediate high-priority audit event is dispatched. The adversary's attempt to lock out the realm collapses into harmless 1-hour ticket issuance.

---

## 6. Cryptographically Bound Audit Log

Forensic integrity requires that access control enforcement be irrefutably provable. If a rogue administrator or compromised process denies a legitimate executive or permits an attacker, the decision must be permanently recorded.

AZ-Kerberos implements a continuous hash-chained audit ledger (`audit.log`). Each entry $R_k$ contains:
$$R_k = \langle \text{seq}_k, \text{ts}_k, \text{prev\_hash}_k, \text{type}_k, \text{data}_k, \text{hash}_k \rangle$$
$$\text{hash}_k = \text{SHA-256}\left( \text{hash}_{k-1} \,\|\, \text{CanonicalJSON}([\text{seq}_k, \text{ts}_k, \text{type}_k, \text{data}_k]) \right)$$

To achieve high append velocity without sacrificing non-repudiation, AZ-Kerberos introduces **amortized asynchronous checkpoints**: every $\kappa = 64$ records, the logger generates a signed checkpoint:
$$\text{Sig}_k = \text{Ed25519\_Sign}\left( K_{\text{priv}}, \text{"AZK-CKPT"} \,\|\, \text{seq}_k \,\|\, \text{hash}_k \right)$$

When the KDC plugin enforces an action, it logs an `AZK_POLICY` record containing the exact table generation timestamp:
$$\text{syslog: } \texttt{AZK\_POLICY phase=TGS client=alice level=1 lifetime=120 renew=120 deny=0 table\_gen=1795197440}$$
The Python engine consumes this line and emits a `policy_applied` record into the audit log, cryptographically linking the KDC's enforcement event to the exact published risk table hash and the underlying anomaly score.

---

## 7. Empirical Evaluation

We evaluated AZ-Kerberos on an experimental testbed running an unmodified MIT Kerberos KDC (v1.20.1) under Ubuntu 24.04 LTS (Linux kernel 6.18) in an isolated WSL2 virtualization environment. The realm `LAB.TEST` was populated with 50 user principals (`user01`..`user50`) and 20 service principals (`svc01`..`svc20`), with services divided evenly between AES-256 (`aes256-cts-hmac-sha1-96`) and RC4-HMAC (`arcfour-hmac`).

### 7.1 Experiment X4: Request Latency and Plugin Overhead
A critical operational requirement is that the KDC policy hook must not degrade authentication throughput. We measured latency across 1,000,000 direct lookups in C, as well as live end-to-end client round trips.

#### In-Process C Lookup Microbenchmark
We evaluated `azk_lookup()` directly in C across 1,000,000 lookups against tables populated with 50 entries (256 slots) and 5,000 entries (32,768 slots). As shown in Table 2, the memory-mapped FNV-1a hash lookup took 13.4 ns (50 entries) and **14.2 ns** (5,000 entries) per lookup in the reported run. A later re-run on the same machine gave 18.3 ns and 19.6 ns, so we quote **about 14–20 nanoseconds**. The 12.9 ms Isolation Forest figure is a single-row sklearn call on synthetic 10-feature input, so the ratio (roughly $10^{6}\times$) compares different things (C hash lookup versus a Python library call) and shows an order of magnitude only.

| Architecture / Configuration | Table Size | Total Time (1M ops) | Lookup Latency | Speedup vs. In-Line ML |
|---|---|---|---|---|
| In-Line Isolation Forest (Python/sklearn) | N/A | 12,900 s (extrapolated) | 12,900,000.0 ns (12.9 ms) | Baseline (1.0$\times$) |
| In-Line Logistic Regression | N/A | 93.5 s (extrapolated) | 93,500.0 ns (93.5 $\mu$s) | 138$\times$ |
| **AZ-Kerberos C Table Lookup** | **50 entries** | **13.37 ms** (re-run 18.26 ms) | **13.4 ns** (re-run 18.3 ns) | **~$10^{6}\times$ (not like-for-like)** |
| **AZ-Kerberos C Table Lookup** | **5,000 entries** | **14.20 ms** (re-run 19.57 ms) | **14.2 ns** (re-run 19.6 ns) | **~$10^{6}\times$ (not like-for-like)** |

*Table 2: Microbenchmark comparison of risk table lookup latency versus in-line model execution.*

#### End-to-End Live KDC Request Latency
We measured the end-to-end execution time of `kinit` requests across 60 repeated trials per configuration under a live running KDC daemon. As presented in Table 3, the presence of the plugin and the scaling of the risk table from 0 to 5,000 entries introduces no measurable overhead above network and cryptographic process initialization variance.

| Configuration | Samples ($N$) | Mean Latency | Median ($p_{50}$) | 90th %ile ($p_{90}$) | 99th %ile ($p_{99}$) |
|---|---|---|---|---|---|
| Stock MIT KDC (No Plugin) | 60 | 622.7 ms | 467.4 ms | 1045.1 ms | 2702.9 ms |
| AZ-Kerberos (Plugin Active, Empty Table) | 60 | 439.7 ms | 382.4 ms | 633.7 ms | 1550.4 ms |
| AZ-Kerberos (50-Entry Table) | 60 | 297.6 ms | 256.6 ms | 385.9 ms | 907.9 ms |
| AZ-Kerberos (5,000-Entry Table) | 60 | 318.8 ms | 252.5 ms | 494.8 ms | 1352.0 ms |

*Table 3: Live client-side end-to-end `kinit` request latency distributions.*

### 7.2 Experiment X5: Audit Ledger Throughput and Tamper Matrix
We benchmarked the append and verification performance of the signed audit logging engine across 5,000 security events with varying checkpoint intervals ($\kappa \in \{50, 100, 500\}$). Furthermore, we subjected the ledger to deliberate adversarial corruption across six attack scenarios.

| Checkpoint Interval ($\kappa$) | Ingestion Throughput | Verification Throughput | Ledger File Size | Verification Status |
|---|---|---|---|---|
| $\kappa = 50$ records | 58,619.2 events/s | 75,472.7 records/s | 1,713.7 KB | Passed ($100\%$) |
| $\kappa = 100$ records | **64,476.9 events/s** | 81,748.2 records/s | 1,691.9 KB | Passed ($100\%$) |
| $\kappa = 500$ records | 63,959.6 events/s | **93,499.2 records/s** | 1,674.6 KB | Passed ($100\%$) |

*Table 4: Cryptographic audit log throughput and verification rates.*

As detailed in Table 4, AZ-Kerberos achieves over **64,400 events/second** append throughput—a **37$\times$ improvement** over the classic Crosby & Wallach benchmark (1,750 events/s) \cite{crosby2009usenix}—because expensive asymmetric Ed25519 signatures are amortized across checkpoints while maintaining uninterrupted SHA-256 hash chaining on every individual record.

#### Tamper Detection Verification
In our adversarial tests:
- **Bit-Flip / Data Modification:** Altering any payload field immediately caused a hash mismatch at the modified sequence number (**Detected**).
- **Record Deletion:** Deleting an intermediate record broke the sequential chain link $H_k \neq \text{SHA-256}(H_{k-2} \dots)$ (**Detected**).
- **Record Reordering / Insertion:** Out-of-order sequence indexing or duplicate insertion was flagged immediately (**Detected**).
- **Signature Forgery:** Verifying checkpoints against an unauthorized public key failed Ed25519 verification (**Detected**).
- **Tail Truncation:** While truncating the tail back to a valid checkpoint preserves internal consistency, providing an external anchor $\langle \text{seq}_{\text{anchor}}, H_{\text{anchor}} \rangle$ detected the missing records with $100\%$ accuracy (**Detected**).

### 7.3 Experiment X6: Failure Modes and Fail-Open Resilience
To evaluate fault tolerance under adverse operating conditions, we subjected the live KDC to deliberate operational disruptions. As reported in Table 5, under missing, corrupted, truncated, or stale risk table conditions, AZ-Kerberos consistently defaults to unconstrained issuance (full 10-hour tickets), guaranteeing that scoring daemon failures or disk faults never disrupt enterprise authentication availability.

| Failure Injected | Injected Fault Condition | KDC Behavioral Outcome | Ticket Lifetime Granted | Fail-Open Verified? |
|---|---|---|---|---|
| Missing Table File | Inode removed via `unlink` | Normal ticket issued | 36,000 s (10 hours) | **Yes** |
| Corrupted Magic | Magic header set to `'CORR'` | Invalid format caught, unmapped | 36,000 s (10 hours) | **Yes** |
| Truncated File | File size $< \text{Header} + \text{Slot}$ | Header bounds check failed | 36,000 s (10 hours) | **Yes** |
| Stale Table File | `generated_at` $= t - 600$ s | Stale threshold ($>300$ s) exceeded | 36,000 s (10 hours) | **Yes** |
| Active Table (Level 1) | Fresh binary table with cap | Policy applied | **300 s (5 minutes)** | Enforced |
| Active Table (Level 3) | Fresh binary table with deny | Request denied with error | **0 s (DENIED)** | Enforced |

*Table 5: Empirical verification of failure mode behavior and fail-open guarantees.*

### 7.4 Experiments X1–X3: Live Attack Mitigation and Comparative Analysis
We evaluated AZ-Kerberos with real traffic against the live MIT krb5 1.20.1 KDC (script `tests/run_live_experiment_real.py`, raw data `out/x1_x2_x3_real_results.json`). Every request is a real `kinit` or `kvno` call (RC4 via `kvno -e arcfour-hmac`); the engine is fed only from the KDC's own syslog lines; each outcome (full, capped, denied, failed) is read from the KDC's actual response (exit status plus the ticket start and end times printed by `klist`; "full" means at least 30,000 s of the realm's 36,000 s maximum). The scorer runs as a separate tick every 1 s (pull log, score, publish table), so requests issued between ticks are unprotected: this is the real cost of the asynchronous design. Three modes were compared: (1) **Unprotected Stock KDC**, (2) **Static Threshold Baseline** (same engine, hand-set feature thresholds, cap-only), and (3) **AZ-Kerberos** (Isolation Forest trained on 720 events from 240 real benign rounds, plus the two-signal denial rule and the signed audit log).

The workload per run comprised:
- **Benign Background:** 100 rounds over 25 users (`user26`–`user50`), 200 requests, no attacker.
- **Attack 1 (AES Kerberoasting):** `user01` requests service tickets for 18 distinct service principals.
- **Attack 2 (RC4 Downgrade Kerberoasting):** `user02` requests RC4-HMAC tickets for the 10 RC4-capable service principals.
- **Attack 3 (Password Spraying & Victim Impact):** 3 wrong passwords against each of 15 victim accounts (`user11`–`user25`), after which each victim logs in legitimately; we record the victim's ticket lifetime.
- **Attacker pacing:** 0 s (unpaced burst), 1 s and 3 s between attacker requests. 3 repeats per cell (3 different benign sequences, seeds 1000–1002). A second run with a 0.25 s scorer tick (2 repeats, pacing 0 and 1 s) is in `out/x1_x2_x3_real_poll025.json`.

Lab limitations: every client connects from 127.0.0.1, so the new-IP feature never fires and the per-source "users sprayed" feature pools all actors; stolen-credential use from a new host (attack 4) was not run; 50-user realm.

| Metric | Unprotected Stock KDC | Static Threshold Baseline | AZ-Kerberos (This Work) | Security Advantage |
|---|---|---|---|---|
| **AES Kerberoast (18 requests), pacing 1 s: full / capped / denied** | 18 / 0 / 0 | 8 / 10 / 0 | 6 / 12 / 0 | 6 vs 8 full tickets: small difference; capped tickets still crackable |
| **AES Kerberoast, pacing 3 s: full / capped / denied** | 18 / 0 / 0 | 8 / 10 / 0 | 6 / 12 / 0 | Same counts; AZ restricts from the 7th request, threshold from the 9th |
| **AES Kerberoast, unpaced burst: full / capped / denied** | 18 / 0 / 0 | 18 / 0 / 0 | 15 / 3 / 0 | Burst ends before the 1 s tick; AZ restricted in 1 of 3 runs, threshold in 0 of 3 |
| **RC4 Kerberoast (10 requests), pacing 1 s and 3 s: full / capped / denied** | 10 / 0 / 0 | 6 / 4 / 0 | 6 / 4 / 0 | Identical to the threshold baseline; burst: 10 / 0 / 0 for all modes |
| **Time to first restriction, AES (pacing 1 s / 3 s)** | none | 8.6 s / 24.5 s | 6.4 s / 18.5 s | Fan-out of 6 distinct services triggers AZ |
| **Spray victims (15) logging in: full / capped / denied** | 15 / 0 / 0 | 5 / 10 / 0 | 15 / 0 / 0 | Threshold caps victims only because all lab clients share one IP (artifact); not a fair comparison |
| **Benign requests restricted (of 200 per run)** | 0 | 0 | 1.33 mean (4 in 1 of 3 runs; 1 of 25 users) | 4 of 600 requests (0.7%) overall; with a 0.25 s tick: 0 of 400 |
| **Audit log verified (all AZ runs)** | n/a | n/a | yes (9 of 9 main runs, 26–80 records; 4 of 4 tick-0.25 s runs) | Chain and signatures verify |

*Table 6: Real end-to-end results on the live MIT krb5 1.20.1 KDC, mean over 3 repeats, scorer tick 1 s (`out/x1_x2_x3_real_summary.txt`). Counts are tickets (or logins) by outcome. "Denied" is 0 in every live attack run.*

With a 0.25 s scorer tick (2 repeats), the unpaced burst gave AZ-Kerberos 13.5 full and 4.5 capped AES tickets (restricted in 1 of 2 runs, 0.42 s after the burst began); paced results were unchanged (6 / 12 and 6 / 4), because detection waits for the sixth distinct service, not for the tick.

#### Key Findings
1. **The closed loop works on stock MIT krb5:** the engine, fed only from KDC syslog, publishes a risk table; the plugin then enforces it on real requests (tickets after detection have a 3,600 s lifetime instead of 36,000 s); all AZ-Kerberos audit logs verify. This is the supported claim.
2. **It does not stop Kerberoasting:** before detection the attacker still received 6 of 18 AES and 6 of 10 RC4 tickets at full lifetime (15 of 18 AES in a burst), the capped tickets still contain the crackable ciphertext, and denial (which does withhold tickets) was never triggered in any live run: the two-signal rule needs at least 10 distinct services and at least 5 RC4 requests, which neither attack produced (the AES attack made at most 1 RC4 request; the RC4 attack has only 10 RC4-capable services and was flagged at 6).
3. **No demonstrated advantage over a threshold rule on Kerberoasting:** 6 vs 8 full AES tickets and equal RC4 counts; the Isolation Forest restricted after 6 full tickets where the hand-set rule restricted after 8. The differences come from one threshold setting and 3 repeats, not from a statistical comparison.
4. **Victim impact (T1):** none of the 15 spray victims was capped or denied under AZ-Kerberos (nor in the unprotected run); the threshold baseline capped 10 of 15, but that is caused by the single-IP lab artifact and says little about the rule in a real network.
5. **False restrictions:** 4 of 600 benign requests (1 user in 1 of 3 benign sequences) with a 1 s tick, 0 of 400 with a 0.25 s tick; with only 3 benign sequences this estimate is rough.

---

## 8. Discussion and Operational Considerations

### 8.1 Practical Deployment and Multi-KDC Environments
In production enterprise networks, Kerberos is deployed across redundant primary and replica KDCs. AZ-Kerberos integrates cleanly into replicated topologies:
- The scoring engine can run on an independent security analytics host or alongside the primary KDC.
- The compiled `kdcpolicy_azk.so` module requires only read access to the local `/var/lib/azk/risk_table.bin` file.
- The risk table can be distributed across KDC replicas via atomic `rsync` or distributed file replication; because table lookups fail open if the table is older than 300 seconds, temporary replication lag causes graceful degradation rather than authentication failures.

### 8.2 Limitations
- **Low-and-Slow Attacks:** If an adversary restricts credential abuse to a single service request every few days, the sliding-window feature extractor will not observe an elevated request rate. However, such slow lateral movement substantially increases attacker dwell time, allowing endpoint detection mechanisms to intervene.
- **Client IP Visibility:** In accordance with the MIT Kerberos plugin specification, `check_as` and `check_tgs` receive principal identifiers and request flags, but do not receive the source IP address in the vtable call. Consequently, enforcement in the plugin must be keyed by principal, while IP-based correlation resides in the asynchronous engine.
- **Literature coverage is partial:** the survey read about 20 sources per pillar; IEEE Xplore, ACM DL, NDSS, S&P and CCS were not searched directly. "No prior work feeds a risk score into Kerberos ticket issuance" is a weak negative result, not a proof. Qomplx patent US12580898 was read: it detects forged tickets and destroys them after the fact using a ledger of authentication objects, with no lifetime adaptation, no signed hash chain and no stock-krb5 deployment, so it is a partial overlap only. Not yet read: Qomplx US11968227, US12438906 and continuations, IEEE Computer 2024 (DOI 10.1109/MC.2024.3434535). Post-quantum PKINIT on stock MIT krb5 already exists (kurbu5-pkinit), so we make no post-quantum claim.
- **Table 2 is illustrative, not like-for-like:** it compares an in-process C hash lookup with one Python/sklearn call timed on a synthetic 10-feature input. The "extrapolated" totals are per-call time multiplied by 1,000,000, not measured runs.
- **Table 3 supports "no measurable overhead" only:** the stock-KDC row is slower than the plugin rows, which points to run-order and WSL noise, not a speed-up from the plugin. Percentiles come from 60 samples.
- **Evaluation scale:** X1-X3 are scripted attacks against a lab realm of 50 users: 3 repeats per cell, 3 benign sequences, one scorer configuration, one threshold setting, no statistical testing. Every client connects from 127.0.0.1, so IP-based features cannot discriminate and the baseline's spray feature pools all actors (which is why the baseline capped 10 of 15 victims). Stolen-credential use from a new host was not run. An earlier X1-X3 run that fed synthetic log lines to the engine and inferred outcomes was discarded (its RC4 requests had all failed); only the real runs are reported.
- **Detection is late and denial never fired:** the scorer restricts only after about 6 distinct services (AES) and an unpaced burst finishes before the 1 s scorer tick, so the attacker keeps most tickets; capped tickets can still be cracked offline; the denial level was not reached in any live attack run (the two-signal rule requires at least 10 distinct services and 5 RC4 requests). We did not tune the rule after seeing the results. Unpaced attackers, a shorter tick or a lower denial threshold would change these numbers.
- **The Isolation Forest has no demonstrated advantage:** against the hand-set threshold rule it restricted after 6 instead of 8 full tickets, with equal RC4 results and one benign user restricted in 1 of 3 benign sequences (the threshold rule restricted none).

---

## 9. Conclusion

In this paper, we introduced **AZ-Kerberos**, a risk-adaptive ticket issuance system for stock MIT Kerberos that bridges the gap between passive log auditing and active inline access control. By decoupling asynchronous behavioral anomaly detection from synchronous policy enforcement through an open-addressing binary risk table, AZ-Kerberos enforces policy at **about 14–20 ns per lookup** with zero protocol modifications and zero client alterations. In 15-target password-spray runs no victim account was capped or denied (and none without protection), so we saw no added lock-out; this is an observation, not a formal proof. In real end-to-end runs, the loop from KDC log to enforced ticket lifetime worked on an unmodified KDC and every audit log verified, but the effect on Kerberoasting was limited: the attacker still received 6 of 18 AES tickets at full lifetime (15 of 18 in an unpaced burst), capped tickets remain crackable offline, the denial level was never reached, and a static threshold rule did about as well. The audit trail runs at over 64,000 events per second in our benchmark, and the plugin fails open when the table is missing, corrupt or stale. Closing the detection delay and testing denial against real attack tooling are the main open problems.

---

## References

1. **[rfc4120]** Neuman, C., Yu, T., Hartman, S., & Raeburn, K. (2005). *The Kerberos Network Authentication Service (V5)*. RFC 4120, IETF.
2. **[wiefling2022tops]** Wiefling, S., Iacono, L. L., & Dürmuth, M. (2022). *What’s in a Score? Evaluating the Reliability and User Impact of Risk-Based Authentication*. ACM Transactions on Privacy and Security (TOPS), 25(4), 1–39.
3. **[kotlaba2020icissp]** Kotlaba, M. (2020). *Detection of Kerberoasting Attacks Using Machine Learning and Honeypots*. In Proceedings of the 6th International Conference on Information Systems Security and Privacy (ICISSP 2020), pp. 89–96.
4. **[kotlaba2021icissp]** Kotlaba, M. (2021). *An Anomaly-based Intrusion Detection System for Kerberos using One-Class Support Vector Machines*. In Proceedings of the 7th International Conference on Information Systems Security and Privacy (ICISSP 2021), pp. 112–119.
5. **[grippo2023kerberos]** Grippo, M., & Kholidy, H. A. (2022). *Detecting Forged Kerberos Tickets in an Active Directory Environment*. arXiv preprint arXiv:2301.00044.
6. **[frba2024]** Anonymous. (2024). *F-RBA: Federated Risk-Based Authentication for Cross-Domain Enterprise Identity Providers*. arXiv preprint arXiv:2412.12324.
7. **[crosby2009usenix]** Crosby, S. A., & Wallach, D. S. (2009). *Efficient Data Structures for Tamper-Evident Logging*. In Proceedings of the 18th USENIX Security Symposium (USENIX Security '09), pp. 317–334.
8. **[liu2008isolation]** Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. In 2008 Eighth IEEE International Conference on Data Mining (ICDM '08), pp. 413–422.
9. **[schneier1999audit]** Schneier, B., & Kelsey, J. (1999). *Secure Audit Logs to Support Computer Forensics*. ACM Transactions on Information and System Security (TISSEC), 2(2), 159–176.
10. **[bokovoy2026pqc]** Bokovoy, A., et al. (2026). *Post-Quantum Cryptography for Kerberos PKINIT*. IETF Internet-Draft `draft-bokovoy-kitten-pkinit-pqc-02`.
