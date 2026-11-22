#!/bin/bash
cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC"
sudo env PYTHONPATH=src /home/som_praneeth/azk-venv/bin/python tests/set_risk.py user01@LAB.TEST 0 36000 604800
echo "--- last AZK_POLICY lines from journal (new plugin)"
sudo journalctl --no-pager -t azk-kdcpolicy -o short-iso-precise 2>/dev/null | grep AZK_POLICY | tail -3
echo "--- reset check"
echo 'UserPassword1!' | kinit user01@LAB.TEST >/dev/null 2>&1; klist | grep krbtgt; kdestroy -A
