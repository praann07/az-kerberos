# AZ-Kerberos — 22AIE314 Computer Security project

Risk-adaptive ticket issuance for **stock MIT Kerberos**: an asynchronous scorer reads KDC logs and publishes a risk table; a kdcpolicy plugin caps ticket lifetime or denies; every decision goes into a signed hash-chained audit log.

**Status (2026-11-22):** Python pipeline with 24 passing tests; C plugin compiled and running on MIT krb5 1.20.1 (WSL Ubuntu-24.04); X1–X6 measured on the live KDC. The closed loop works. The effect on attacks is modest (see "Honest results"). Not finished: author block in the paper, stolen-credential attack (not run), several patents and one IEEE Computer paper unread, single lab realm.

## Honest results (live KDC, real `kinit`/`kvno` calls, 3 repeats)
- Closed loop works on stock krb5: after detection, tickets are issued with the capped lifetime (3,600 s instead of 36,000 s); all signed audit logs verified.
- Does not stop Kerberoasting: attacker still got 6 of 18 AES tickets at full lifetime (15 of 18 in an unpaced burst). Capped tickets are still crackable offline.
- Denial level was never reached in any live attack run (tested only by X6 and manual smoke).
- No demonstrated advantage over a hand-set threshold rule (6 vs 8 full AES tickets, equal RC4).
- No spray victim capped or denied under AZ-Kerberos. 4 of 600 benign requests restricted (one user, one benign sequence).
- Lab limits: all clients 127.0.0.1, 50-user realm, no statistical test.
- An earlier X1–X3 result (`out/x1_x2_x3_evaluation_results.json`, `out/live_audit.log`) was synthetic and is superseded; do not cite it.

## Read in this order
1. `docs/01_briefing.md` — final 4-part briefing (overview, existing work, novelty gap, metrics)
2. `docs/02_architecture.md` — components, table layout, design decisions
3. `docs/03_threat_model.md` — threats, mitigations, honest status
4. `docs/04_evaluation_plan.md` — experiments, datasets, rules
5. `docs/05_plan_and_status.md` — what exists, live results, blockers, claim limits
6. `docs/06_verified_facts.md` — what was verified vs assumed
7. `survey_related_work.md` — full literature survey (partial)
8. `docs/conference_paper.md` (full text) and `docs/AZ-Kerberos_paper.pdf` (condensed 3-page IEEE version); `docs/presentation_slides.md`
9. `SETUP_REQUIREMENTS.txt` — how to rebuild the WSL lab

## Layout
```
src/azk/        logparse, features, scorer, engine, risktable, audit, simulator, demo
plugin/         kdcpolicy_azk.c (compiled to kdcpolicy_azk.so on the lab KDC)
tests/          test_azk.py, test_x6_failopen.py, benchmark_x4_latency.py, benchmark_x5_audit.py,
                run_live_experiment_real.py (real X1–X3), setup_lab_realm.py, set_risk.py,
                bench_lookup.c, real_kdc_lines_sample.txt
docs/           01..06, conference_paper.md/.tex, AZ-Kerberos_paper.pdf, presentation_slides.md
survey_related_work.md
out/            results: x1_x2_x3_real_results.json, x1_x2_x3_real_poll025.json (+ *_summary.txt),
                x4_latency_results.json, x5_audit_results.json, x6_failopen_results.json,
                live_audit_real*.log; run_real.sh (re-run X1–X3)
```

## Run (Windows git-bash, from this folder)
```
PY="/c/Users/Som Praneeth/AppData/Local/Programs/Python/Python312/python.exe"
PYTHONPATH=src "$PY" -m pytest tests -q          # 24 tests
PYTHONPATH=src "$PY" -m azk.demo out             # synthetic smoke demo
```
The live experiments need the WSL Ubuntu-24.04 lab (`SETUP_REQUIREMENTS.txt`); re-run X1–X3 with `out/run_real.sh`.
Needs: Python 3.12, `cryptography`, `scikit-learn`, `numpy`, `pytest`.
