#!/bin/bash
set -e
cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC/plugin"
gcc -shared -fPIC -O2 -Wall -o /tmp/kdcpolicy_azk_new.so kdcpolicy_azk.c $(pkg-config --cflags krb5)
echo "compiled ok"
sudo cp /tmp/kdcpolicy_azk_new.so /usr/lib/x86_64-linux-gnu/krb5/plugins/kdcpolicy/kdcpolicy_azk.so
nm -D /usr/lib/x86_64-linux-gnu/krb5/plugins/kdcpolicy/kdcpolicy_azk.so | grep initvt
if systemctl is-active krb5-kdc >/dev/null 2>&1; then sudo systemctl restart krb5-kdc; else sudo pkill krb5kdc; sleep 1; sudo /usr/sbin/krb5kdc -P /var/run/krb5-kdc.pid; fi
sleep 2
pgrep -a krb5kdc
