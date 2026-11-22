#!/usr/bin/env python3
"""Setup script for AZ-Kerberos lab realm LAB.TEST in WSL.
Creates 50 user principals and 20 service principals.
Some services are configured with arcfour-hmac (RC4) for Kerberoasting tests,
and others with aes256-cts.
"""
import subprocess
import sys

def run_kadmin(cmd):
    full_cmd = f"sudo kadmin.local -q '{cmd}'"
    res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error running {cmd}: {res.stderr}")
    return res.stdout

def main():
    print("Setting up users...")
    # 50 users
    for i in range(1, 51):
        uname = f"user{i:02d}"
        run_kadmin(f"addprinc -pw UserPassword{i}! {uname}@LAB.TEST")
    
    print("Setting up services...")
    # 20 services: first 10 AES, next 10 support RC4
    for i in range(1, 21):
        sname = f"svc{i:02d}/host.lab.test"
        if i <= 10:
            run_kadmin(f"addprinc -pw ServicePass{i}! -e aes256-cts-hmac-sha1-96:normal {sname}@LAB.TEST")
        else:
            run_kadmin(f"addprinc -pw ServicePass{i}! -e arcfour-hmac:normal,aes256-cts-hmac-sha1-96:normal {sname}@LAB.TEST")
            
    print("Principals created. Listing sample:")
    out = run_kadmin("listprincs")
    lines = [line.strip() for line in out.splitlines() if "@LAB.TEST" in line]
    print(f"Total principals in realm: {len(lines)}")

if __name__ == "__main__":
    main()
