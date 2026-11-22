#!/bin/bash
# Lab-only: does the KDC log escape '@' in names, and what does a TGS line with " for " in client / service look like?
set -u
export KRB5CCNAME=/tmp/azk_forcheck.cc
sudo kadmin.local -q 'addprinc -pw Pw1234567! "evil for x"' >/dev/null 2>&1
sudo kadmin.local -q 'addprinc -pw Pw1234567! "victim\@LAB.TEST for z"' >/dev/null 2>&1
echo Pw1234567! | kinit "evil for x@LAB.TEST" 2>&1 | head -2
kvno svc01/host.lab.test@LAB.TEST 2>&1 | head -2
kvno "svc a for z/host.lab.test@LAB.TEST" 2>&1 | head -2
kdestroy 2>/dev/null
echo Pw1234567! | kinit "victim\@LAB.TEST for z@LAB.TEST" 2>&1 | head -2
kvno svc02/host.lab.test@LAB.TEST 2>&1 | head -2
kdestroy 2>/dev/null
sleep 1
sudo journalctl --no-pager -t azk-kdcpolicy -o short-iso --since "-1 min" | grep -E "evil|victim|svc a" | sed 's/etypes {[^}]*}/etypes {..}/g'
sudo kadmin.local -q 'delprinc -force "evil for x"' >/dev/null 2>&1
sudo kadmin.local -q 'delprinc -force "victim\@LAB.TEST for z"' >/dev/null 2>&1
rm -f /tmp/azk_forcheck.cc
