cd "/mnt/c/Users/Som Praneeth/Desktop/COMPSEC"
PYTHONPATH=src /home/som_praneeth/azk-venv/bin/python tests/run_live_experiment_real.py --poll 1.0 --repeats 1 --train 80 --out out/x_real_smoke.json > out/x_real_smoke.log 2>&1
echo EXIT $? >> out/x_real_smoke.log