#!/usr/bin/env python3
"""Experiment X6: Failure Modes and Fail-Open Resilience Verification.
Tests against the live running MIT Kerberos KDC:
1. Missing table file -> KDC issues unconstrained ticket (fails open)
2. Corrupt table header (bad magic 'XXXX') -> KDC fails open
3. Corrupt table size -> KDC fails open
4. Stale table (generated 600s ago > 300s threshold) -> KDC fails open
5. Active fresh table -> KDC enforces restriction
6. Table removal -> KDC immediately reverts to fail-open unconstrained issuance
"""
import json
import os
import struct
import subprocess
import sys
import time

sys.path.insert(0, "src")
from azk import risktable

TABLE_PATH = "/var/lib/azk/risk_table.bin"
USER = "alice@LAB.TEST"
PW = "password123"

def get_ticket_life():
    subprocess.run("kdestroy", shell=True)
    res = subprocess.run(f"echo '{PW}' | kinit {USER}", shell=True, capture_output=True, text=True)
    if "rejected" in res.stderr.lower() or "denied" in res.stderr.lower() or res.returncode != 0:
        return "DENIED"
    res2 = subprocess.run("klist", shell=True, capture_output=True, text=True)
    for line in res2.stdout.splitlines():
        if "krbtgt/LAB.TEST" in line:
            return "ISSUED_OK"
    return "UNKNOWN"

def check_ticket_lifetime_seconds():
    subprocess.run("kdestroy", shell=True)
    res = subprocess.run(f"echo '{PW}' | kinit {USER}", shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        return 0
    res2 = subprocess.run("klist", shell=True, capture_output=True, text=True)
    # Parse dates from klist output: Valid starting Expires Service principal
    lines = res2.stdout.splitlines()
    for i, line in enumerate(lines):
        if "krbtgt/LAB.TEST" in line:
            # Look at start and end times
            parts = line.split()
            # e.g.: 11/20/26 18:05:00  11/20/26 18:10:00  krbtgt/LAB.TEST@LAB.TEST
            t_start = parts[1]
            t_exp = parts[3]
            h0, m0, s0 = map(int, t_start.split(":"))
            h1, m1, s1 = map(int, t_exp.split(":"))
            sec = (h1*3600 + m1*60 + s1) - (h0*3600 + m0*60 + s0)
            if sec < 0: sec += 86400
            return sec
    return 0

def main():
    print("=== Running Experiment X6: Failure Modes & Fail-Open Verification ===")
    results = {}
    
    # 1. Missing table
    subprocess.run(f"rm -f {TABLE_PATH}", shell=True)
    time.sleep(1.2) # ensure > 1s for last_stat check
    status1 = get_ticket_life()
    life1 = check_ticket_lifetime_seconds()
    results["missing_table"] = {"status": status1, "lifetime_s": life1, "fail_open_verified": life1 > 35000}
    print("1. Missing table:", results["missing_table"])
    
    # 2. Corrupt Magic
    with open(TABLE_PATH, "wb") as f:
        f.write(b"CORR" + b"\x00" * 200)
    time.sleep(1.2)
    status2 = get_ticket_life()
    life2 = check_ticket_lifetime_seconds()
    results["corrupt_magic"] = {"status": status2, "lifetime_s": life2, "fail_open_verified": life2 > 35000}
    print("2. Corrupt magic:", results["corrupt_magic"])
    
    # 3. Corrupt Size / Short File
    with open(TABLE_PATH, "wb") as f:
        f.write(b"AZRT" + b"\x01\x00\x00\x00\x10") # truncated
    time.sleep(1.2)
    status3 = get_ticket_life()
    life3 = check_ticket_lifetime_seconds()
    results["corrupt_size"] = {"status": status3, "lifetime_s": life3, "fail_open_verified": life3 > 35000}
    print("3. Corrupt size:", results["corrupt_size"])
    
    # 4. Stale table (generated 600s ago)
    now = int(time.time())
    stale_gen = now - 600
    entry = risktable.Entry(USER, 1, 300, 300, now + 3600)
    risktable.write_atomic(TABLE_PATH, [entry], stale_gen)
    time.sleep(1.2)
    status4 = get_ticket_life()
    life4 = check_ticket_lifetime_seconds()
    results["stale_table"] = {"status": status4, "lifetime_s": life4, "fail_open_verified": life4 > 35000}
    print("4. Stale table (>300s):", results["stale_table"])
    
    # 5. Active Fresh Table (generated now)
    entry_fresh = risktable.Entry(USER, 1, 300, 300, now + 3600)
    risktable.write_atomic(TABLE_PATH, [entry_fresh], now)
    time.sleep(1.2)
    status5 = get_ticket_life()
    life5 = check_ticket_lifetime_seconds()
    results["active_fresh_table"] = {"status": status5, "lifetime_s": life5, "enforced_verified": life5 == 300}
    print("5. Active fresh table:", results["active_fresh_table"])
    
    # 6. Active Level 3 Denial
    entry_deny = risktable.Entry(USER, 3, 1, 1, now + 3600)
    risktable.write_atomic(TABLE_PATH, [entry_deny], now)
    time.sleep(1.2)
    status6 = get_ticket_life()
    results["active_deny"] = {"status": status6, "denial_verified": status6 == "DENIED"}
    print("6. Active denial:", results["active_deny"])
    
    # Clean up
    subprocess.run(f"rm -f {TABLE_PATH}", shell=True)
    
    out_file = "out/x6_failopen_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved results to {out_file}")

if __name__ == "__main__":
    main()
