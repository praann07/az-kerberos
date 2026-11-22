#!/bin/bash
# Real end-to-end X1-X3 on the live MIT krb5 KDC. Runs inside WSL Ubuntu-24.04.
cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC" || exit 1
export PYTHONPATH=src
PY=/home/som_praneeth/azk-venv/bin/python
$PY -m py_compile tests/run_live_experiment_real.py || { echo "SYNTAX ERROR"; exit 2; }
echo "=== MAIN: poll 1.0 s, delays 0,1,3, 3 repeats ==="
$PY tests/run_live_experiment_real.py --poll 1.0 --repeats 3 --attack-delays 0,1,3 --train 240 --out out/x1_x2_x3_real_results.json
echo "MAIN EXIT $?"
cp out/live_audit_real.log out/live_audit_real_main_last_run.log
echo "=== SENSITIVITY: poll 0.25 s, delays 0,1, 2 repeats ==="
$PY tests/run_live_experiment_real.py --poll 0.25 --repeats 2 --attack-delays 0,1 --train 240 --out out/x1_x2_x3_real_poll025.json
echo "SENS EXIT $?"
echo ALLDONE
