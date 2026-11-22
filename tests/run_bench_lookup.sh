#!/usr/bin/env bash
set -e
gcc -O3 tests/bench_lookup.c -o tests/bench_lookup
source ~/azk-venv/bin/activate
PYTHONPATH=src python3 - << 'EOF'
import sys, time
from azk import risktable
now = int(time.time())
e50 = [risktable.Entry(f"dummy_{i:04d}@LAB.TEST", 1, 300, 300, now + 3600) for i in range(50)]
risktable.write_atomic("/tmp/t50.bin", e50, now)

e5000 = [risktable.Entry(f"dummy_{i:04d}@LAB.TEST", 1, 300, 300, now + 3600) for i in range(5000)]
risktable.write_atomic("/tmp/t5000.bin", e5000, now)
EOF

echo "--- 50 entries table ---"
./tests/bench_lookup /tmp/t50.bin
echo "--- 5,000 entries table ---"
./tests/bench_lookup /tmp/t5000.bin
