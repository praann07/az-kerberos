#!/usr/bin/env python3
import sys, time
sys.path.insert(0, "src")
from azk import risktable

def main():
    if len(sys.argv) < 5:
        print("Usage: set_risk.py <principal> <level> <lifetime_cap> <renew_cap>")
        sys.exit(1)
    princ = sys.argv[1]
    lvl = int(sys.argv[2])
    life = int(sys.argv[3])
    renew = int(sys.argv[4])
    
    entries = []
    if lvl > 0:
        entries.append(risktable.Entry(
            principal=princ,
            level=lvl,
            lifetime_cap=life,
            renew_cap=renew,
            expires_at=int(time.time()) + 3600
        ))
    risktable.write_atomic("/var/lib/azk/risk_table.bin", entries, int(time.time()))
    print(f"Risk table updated for {princ}: level={lvl}, life={life}, renew={renew}")

if __name__ == "__main__":
    main()
