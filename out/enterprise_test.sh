#!/bin/bash
# Live test of enterprise-name bypass (finding 5): user01 is set to level 2 / 300 s cap.
cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC"
PY=/home/som_praneeth/azk-venv/bin/python
life() { klist 2>/dev/null | awk '/krbtgt/ {print "   ticket line:", $0}' ; klist 2>/dev/null | awk '/krbtgt/{getline x; print}' >/dev/null; }
show() { klist 2>&1 | grep -E "Default principal|krbtgt" ; }
run_case() {
  echo "== $1"
  kdestroy -A 2>/dev/null
  echo 'UserPassword1!' | kinit $2 2>&1 | head -2
  show
  kdestroy -A 2>/dev/null
}
sudo env PYTHONPATH=src $PY tests/set_risk.py user01@LAB.TEST 2 300 300
echo "##### $1 plugin"
run_case "plain kinit user01" user01@LAB.TEST
run_case "enterprise kinit -C -E user01@LAB.TEST" "-C -E user01@LAB.TEST"
