#!/usr/bin/env python3
"""Experiment X5: Audit Log Throughput and Tamper-Evidence Verification.
Measures:
1. Event append throughput (events/s) with Ed25519 checkpoint signing every 50, 100, 500 records.
2. Verification throughput (records/s).
3. Tamper detection matrix:
   - Record modification (bit flip)
   - Record deletion
   - Record insertion
   - Record reordering
   - Signature forgery without private key
   - Tail truncation (with and without anchor)
"""
import json
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, "src")
from azk import audit

def measure_throughput(n_events=5000, checkpoint_every=100):
    key = Ed25519PrivateKey.generate()
    path = f"/tmp/audit_bench_{checkpoint_every}.log"
    if os.path.exists(path):
        os.remove(path)
        
    log = audit.AuditLog(path, key, ckpt_every=checkpoint_every)
    
    t0 = time.perf_counter()
    for i in range(n_events):
        log.append("risk_update", {
            "client": f"user{i%50:02d}@LAB.TEST",
            "level": (i % 3) + 1,
            "prev_level": 0,
            "score": 0.85,
            "features": {"fail_n": i % 10, "svc_distinct": (i % 15) + 1},
            "event_ts": 1700000000 + i
        })
    log.close()
    t1 = time.perf_counter()
    append_time = t1 - t0
    append_rate = n_events / append_time
    
    # Measure verify time
    t2 = time.perf_counter()
    v_res = audit.verify(path, key.public_key())
    t3 = time.perf_counter()
    verify_time = t3 - t2
    verify_rate = n_events / verify_time
    
    file_size_kb = os.path.getsize(path) / 1024.0
    
    return {
        "n_events": n_events,
        "checkpoint_every": checkpoint_every,
        "append_rate_eps": round(append_rate, 1),
        "verify_rate_eps": round(verify_rate, 1),
        "file_size_kb": round(file_size_kb, 1),
        "verify_ok": v_res.ok
    }

def verify_tamper_matrix():
    key = Ed25519PrivateKey.generate()
    path = "/tmp/audit_tamper_test.log"
    if os.path.exists(path):
        os.remove(path)
    log = audit.AuditLog(path, key, ckpt_every=10)
    for i in range(35):
        log.append("risk_update", {"client": f"user{i}@LAB.TEST", "level": 1, "score": 0.5})
    log.close()
    
    with open(path, "r") as f:
        lines = f.readlines()
        
    matrix = {}
    
    # 0. Clean
    matrix["clean"] = audit.verify(path, key.public_key()).ok
    
    # 1. Modify data in record 5
    mod_lines = list(lines)
    rec = json.loads(mod_lines[5])
    rec["data"]["level"] = 3
    mod_lines[5] = json.dumps(rec) + "\n"
    with open("/tmp/t_mod.log", "w") as f: f.writelines(mod_lines)
    matrix["modified_record"] = not audit.verify("/tmp/t_mod.log", key.public_key()).ok
    
    # 2. Delete record 5
    del_lines = list(lines)
    del del_lines[5]
    with open("/tmp/t_del.log", "w") as f: f.writelines(del_lines)
    matrix["deleted_record"] = not audit.verify("/tmp/t_del.log", key.public_key()).ok
    
    # 3. Reorder records 5 and 6
    reord_lines = list(lines)
    reord_lines[5], reord_lines[6] = reord_lines[6], reord_lines[5]
    with open("/tmp/t_reord.log", "w") as f: f.writelines(reord_lines)
    matrix["reordered_records"] = not audit.verify("/tmp/t_reord.log", key.public_key()).ok
    
    # 4. Insert unauthorized record
    ins_lines = list(lines)
    ins_lines.insert(5, lines[3])
    with open("/tmp/t_ins.log", "w") as f: f.writelines(ins_lines)
    matrix["inserted_record"] = not audit.verify("/tmp/t_ins.log", key.public_key()).ok
    
    # 5. Forged key verification
    wrong_key = Ed25519PrivateKey.generate().public_key()
    matrix["forged_signature_detected"] = not audit.verify(path, wrong_key).ok
    
    # 6. Truncation back to previous checkpoint
    trunc_lines = lines[:15] # checkpoint was at 10
    with open("/tmp/t_trunc.log", "w") as f: f.writelines(trunc_lines)
    # Without anchor: truncation passes internal chain check (tested limitation)
    no_anchor_pass = audit.verify("/tmp/t_trunc.log", key.public_key()).ok
    # With anchor (knowing expected length 38):
    anchor = (len(lines), json.loads(lines[-1])["hash"])
    anchored_detect = not audit.verify("/tmp/t_trunc.log", key.public_key(), anchor=anchor).ok
    matrix["truncation_without_anchor_accepted"] = no_anchor_pass
    matrix["truncation_with_anchor_detected"] = anchored_detect
    
    return matrix

def main():
    print("=== Running Experiment X5: Audit Log Benchmarks ===")
    tp_50 = measure_throughput(5000, 50)
    tp_100 = measure_throughput(5000, 100)
    tp_500 = measure_throughput(5000, 500)
    
    print("Throughput results:")
    print("  cp=50 :", tp_50)
    print("  cp=100:", tp_100)
    print("  cp=500:", tp_500)
    
    tamper = verify_tamper_matrix()
    print("\nTamper Detection Matrix:")
    for k, v in tamper.items():
        print(f"  {k:38s}: {'DETECTED / OK' if v else 'FAILED'}")
        
    out = {
        "throughput": [tp_50, tp_100, tp_500],
        "tamper_matrix": tamper
    }
    os.makedirs("out", exist_ok=True)
    with open("out/x5_audit_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("\nSaved to out/x5_audit_results.json")

if __name__ == "__main__":
    main()
