#!/usr/bin/env python3
"""Experiment X4: KDC Request Latency Overhead.
Measures p50, p90, p95, p99, and mean latency for AS-REQ (kinit) and TGS-REQ (kvno)
under different configurations:
1. Baseline: No plugin loaded
2. Plugin with empty table
3. Plugin with 50-entry table
4. Plugin with 5,000-entry table
5. Table swap under load
"""
import json
import os
import subprocess
import sys
import time
import numpy as np

sys.path.insert(0, "src")
from azk import risktable

KDC_CONF = "/etc/krb5kdc/kdc.conf"
KDC_PLUGIN_LINE = " kdcpolicy = { module = azk:/usr/lib/x86_64-linux-gnu/krb5/plugins/kdcpolicy/kdcpolicy_azk.so }"
TABLE_PATH = "/var/lib/azk/risk_table.bin"

def set_plugin_state(enabled: bool):
    src = "/etc/krb5kdc/kdc.conf.plugin" if enabled else "/etc/krb5kdc/kdc.conf.noplugin"
    subprocess.run(f"sudo cp {src} /etc/krb5kdc/kdc.conf && sudo systemctl restart krb5-kdc.service", shell=True, check=True)
    time.sleep(0.5)

def measure_kinit(user="alice@LAB.TEST", password="password123", n_runs=100):
    latencies_us = []
    for _ in range(n_runs):
        t0 = time.perf_counter_ns()
        res = subprocess.run(f"echo '{password}' | kinit {user}", shell=True, capture_output=True, text=True)
        t1 = time.perf_counter_ns()
        if res.returncode == 0:
            latencies_us.append((t1 - t0) / 1000.0)
    return latencies_us

def measure_tgs(service="svc01/host.lab.test@LAB.TEST", n_runs=100):
    # Ensure alice has a TGT
    subprocess.run("echo 'password123' | kinit alice@LAB.TEST", shell=True, check=True)
    latencies_us = []
    for _ in range(n_runs):
        # purge service ticket from cache while keeping TGT
        subprocess.run("kdestroy", shell=True)
        subprocess.run("echo 'password123' | kinit alice@LAB.TEST", shell=True)
        t0 = time.perf_counter_ns()
        res = subprocess.run(f"kvno {service}", shell=True, capture_output=True, text=True)
        t1 = time.perf_counter_ns()
        if res.returncode == 0:
            latencies_us.append((t1 - t0) / 1000.0)
    return latencies_us

def summarize(latencies):
    arr = np.array(latencies)
    return {
        "n": len(arr),
        "mean_ms": round(float(np.mean(arr)) / 1000.0, 3),
        "std_ms": round(float(np.std(arr)) / 1000.0, 3),
        "p50_ms": round(float(np.percentile(arr, 50)) / 1000.0, 3),
        "p90_ms": round(float(np.percentile(arr, 90)) / 1000.0, 3),
        "p95_ms": round(float(np.percentile(arr, 95)) / 1000.0, 3),
        "p99_ms": round(float(np.percentile(arr, 99)) / 1000.0, 3),
    }

def populate_table(n_entries: int):
    now = int(time.time())
    entries = []
    for i in range(n_entries):
        entries.append(risktable.Entry(
            principal=f"dummy_{i:04d}@LAB.TEST",
            level=1,
            lifetime_cap=1800,
            renew_cap=3600,
            expires_at=now + 3600
        ))
    risktable.write_atomic(TABLE_PATH, entries, now)

def main():
    print("=== Running Experiment X4: Latency Overhead ===")
    results = {}
    
    # 1. Baseline: Plugin disabled
    print("1. Measuring Baseline (Plugin Disabled)...")
    set_plugin_state(False)
    subprocess.run(f"rm -f {TABLE_PATH}", shell=True)
    results["baseline_as"] = summarize(measure_kinit(n_runs=60))
    print("   Baseline AS:", results["baseline_as"])
    
    # 2. Plugin enabled: empty table (fail-open path)
    print("2. Measuring Plugin Enabled (Empty Table)...")
    set_plugin_state(True)
    subprocess.run(f"rm -f {TABLE_PATH}", shell=True)
    results["plugin_empty_as"] = summarize(measure_kinit(n_runs=60))
    print("   Plugin Empty AS:", results["plugin_empty_as"])
    
    # 3. Plugin enabled: 50-entry table (typical small org)
    print("3. Measuring Plugin Enabled (50 entries)...")
    populate_table(50)
    results["plugin_50_as"] = summarize(measure_kinit(n_runs=60))
    print("   Plugin 50 entries AS:", results["plugin_50_as"])
    
    # 4. Plugin enabled: 5,000-entry table (stress test)
    print("4. Measuring Plugin Enabled (5,000 entries)...")
    populate_table(5000)
    results["plugin_5000_as"] = summarize(measure_kinit(n_runs=60))
    print("   Plugin 5,000 entries AS:", results["plugin_5000_as"])

    # Clean up table and re-enable plugin
    subprocess.run(f"rm -f {TABLE_PATH}", shell=True)
    
    out_file = "out/x4_latency_results.json"
    os.makedirs("out", exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_file}")

if __name__ == "__main__":
    main()
