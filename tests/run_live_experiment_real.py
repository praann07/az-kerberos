#!/usr/bin/env python3
"""X1-X3 (REAL): attack detection, mitigation and baseline comparison on the live MIT krb5 KDC.

Run INSIDE WSL (needs kinit/kvno/klist, `sudo journalctl`, write access to /var/lib/azk):

    PYTHONPATH=src ~/azk-venv/bin/python tests/run_live_experiment_real.py --poll 1.0 --repeats 3

Unlike tests/run_live_experiment.py (superseded: it fed the engine SYNTHETIC log lines and inferred
issuance outcomes from engine state), here:
  * every request goes to the real KDC (kinit / kvno, including RC4 via `kvno -e arcfour-hmac`);
  * the engine is fed ONLY from the KDC's own syslog lines (journalctl, parsed by azk.logparse);
  * every outcome (full / capped / denied / failed) is read from the KDC's actual response:
    exit status of kinit/kvno and the ticket start/end times printed by klist;
  * the scorer runs as a separate "daemon tick" every --poll seconds (pull log, score, publish table),
    so requests issued between ticks are NOT protected -- the real asynchronous cost of the design.

Lab limitations (also reported in the JSON): every client connects from 127.0.0.1 (the kernel picks
that source for loopback), so the new_ip feature never fires and spray_users pools all actors; the
plugin has no client IP anyway. Attack 4 (stolen credential from a new host) is NOT run.
"""
import argparse
import json
import os
import random
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, "src")
from azk import audit, engine, features, logparse, scorer  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

TABLE_PATH = "/var/lib/azk/risk_table.bin"
AUDIT_PATH = "out/live_audit_real.log"
USERS = [f"user{i:02d}@LAB.TEST" for i in range(1, 51)]
SERVICES = [f"svc{i:02d}/host.lab.test@LAB.TEST" for i in range(1, 21)]
FULL_MIN = 30000          # seconds; the lab realm max_life is 36000
KL = re.compile(r"^(\d\d/\d\d/\d\d \d\d:\d\d:\d\d)\s+(\d\d/\d\d/\d\d \d\d:\d\d:\d\d)\s+(\S+)")
FMT = "%m/%d/%y %H:%M:%S"


def sh(cmd, env=None, inp=None):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, input=inp)


class Actor:
    def __init__(self, name):
        self.env = dict(os.environ, KRB5CCNAME=f"FILE:/tmp/azk_real_{name}")

    def destroy(self):
        sh("kdestroy", self.env)

    def _life(self, prefix):
        for line in sh("klist", self.env).stdout.splitlines():
            m = KL.match(line.strip())
            if m and m.group(3).startswith(prefix):
                return int((datetime.strptime(m.group(2), FMT) - datetime.strptime(m.group(1), FMT)).total_seconds())
        return None

    @staticmethod
    def _classify(r, life):
        if r.returncode != 0:
            return ("denied" if "policy rejects" in r.stderr else "failed"), None
        if life is None:
            return "failed", None
        return ("full" if life >= FULL_MIN else "capped"), life

    def kinit(self, user, password=None):
        n = int(user.split("@")[0].replace("user", ""))
        pw = password if password is not None else f"UserPassword{n}!"
        self.destroy()
        r = sh(f"kinit {user}", self.env, inp=pw + "\n")
        return self._classify(r, self._life("krbtgt/") if r.returncode == 0 else None)

    def kvno(self, service, etype=None):
        r = sh(f"kvno {'-e ' + etype + ' ' if etype else ''}{service}", self.env)
        return self._classify(r, self._life(service.split("@")[0]) if r.returncode == 0 else None)


class Journal:
    """Tail the KDC syslog lines with a journald cursor; yields parsed events exactly once."""

    def __init__(self):
        out = self._run("-n 1")
        self.cursor = self._cursor(out)

    @staticmethod
    def _cursor(out):
        cur = None
        for ln in out.splitlines():
            if ln.startswith("-- cursor:"):
                cur = ln.split(":", 1)[1].strip()
        return cur

    @staticmethod
    def _run(args):
        return sh(f"sudo journalctl --no-pager -t azk-kdcpolicy -o short-iso-precise --show-cursor {args}").stdout

    def pull(self):
        out = self._run(f'--after-cursor="{self.cursor}"')
        c = self._cursor(out)
        if c:
            self.cursor = c
        evs = [logparse.parse_line(ln) for ln in out.splitlines() if not ln.startswith("--")]
        return [e for e in evs if e is not None]


class Daemon:
    """Stands in for the scoring daemon: every `poll` seconds pull the log, feed the engine, publish."""

    def __init__(self, journal, eng, poll, publish):
        self.j, self.eng, self.poll, self.publish = journal, eng, poll, publish
        self.last = 0.0
        self.fed = 0

    def tick(self, force=False):
        if not force and time.time() - self.last < self.poll:
            return
        self.last = time.time()
        for ev in self.j.pull():
            self.eng.feed(ev)
            self.fed += 1
        if self.publish:
            self.eng.publish(TABLE_PATH, time.time())


def benign_round(actor, rnd, users, svcs, daemon=None):
    u, s = rnd.choice(users), rnd.choice(svcs)
    a = actor.kinit(u)
    t = actor.kvno(s) if a[0] in ("full", "capped") else ("failed", None)
    if daemon:
        daemon.tick()
    return u, a, t


def train(rnd, n):
    """Real benign traffic, captured from the KDC log, used to fit / calibrate the scorers."""
    print(f"[train] {n} real benign rounds ...", flush=True)
    sh(f"rm -f {TABLE_PATH}")
    j = Journal()
    act = Actor("benign")
    for _ in range(n):
        # all 50 users: the evaluation population must be known to the model (first run showed that training on
        # users 1-25 only made 'new_ip' fire for every unseen user 26-50, an artifact that biased the false-positive rate)
        benign_round(act, rnd, USERS, SERVICES[:8])
    evs = j.pull()
    print(f"[train] captured {len(evs)} real KDC events", flush=True)
    return evs


def build(mode, train_events, rnd):
    extractor = features.FeatureExtractor()
    extractor.learn_ips(train_events)
    feats = [f for f in (extractor.update(e) for e in train_events) if f]
    extractor.reset_windows()   # training traffic must not leak into the evaluation windows
    if mode == "threshold":
        model, lm = scorer.ThresholdRule(), scorer.LevelMap((0.5, 0.8, 1.0))
    elif mode == "unprotected":
        model, lm = scorer.ThresholdRule(), scorer.LevelMap((99.0, 99.0, 99.0))
    else:
        model = scorer.IForestScorer(n_estimators=100, seed=42)
        model.fit(feats)
        lm = scorer.LevelMap.calibrate([model.raw(f) for f in feats], alphas=(0.02, 0.005, 0.001))
    key = Ed25519PrivateKey.generate()
    alog = None
    if mode == "azk":
        if os.path.exists(AUDIT_PATH):
            os.remove(AUDIT_PATH)
        alog = audit.AuditLog(AUDIT_PATH, key, ckpt_every=10)
    eng = engine.Engine(extractor=extractor, scorer=model, levelmap=lm, audit=alog, hold_s=300,
                        cap_failures=True, require_two_signals_for_l3=(mode == "azk"), total_principals=50)
    return eng, alog, key


def tally(results):
    c = {"full": 0, "capped": 0, "denied": 0, "failed": 0}
    for st, _ in results:
        c[st] += 1
    return c


def one_run(mode, train_events, poll, seed, attack_delay=0.0):
    rnd = random.Random(seed)
    print(f"\n--- mode={mode} poll={poll}s seed={seed} attack_delay={attack_delay}s ---", flush=True)
    sh(f"rm -f {TABLE_PATH}")
    time.sleep(1.2)  # let the plugin's once-per-second stat notice the empty table
    eng, alog, key = build(mode, train_events, rnd)
    j = Journal()
    d = Daemon(j, eng, poll, publish=(mode != "unprotected"))
    m = {"mode": mode, "poll_s": poll, "seed": seed, "attack_delay_s": attack_delay}

    # ---- benign traffic (users 26-50): restricted = any request that was not issued at full lifetime
    act = Actor("benign")
    restricted_req = total_req = failed_req = 0
    restricted_users = set()
    for _ in range(100):
        u, a, t = benign_round(act, rnd, USERS[25:], SERVICES[:5], d)
        for st, _l in (a, t):
            total_req += 1
            if st in ("capped", "denied"):
                restricted_req += 1
                restricted_users.add(u)
            elif st == "failed":
                failed_req += 1
    m["benign"] = {"requests": total_req, "restricted_requests": restricted_req,
                   "failed_requests": failed_req, "restricted_principals": len(restricted_users)}

    def attack_loop(user, svcs, etype):
        atk = Actor("attacker_" + user[:6])
        st, _ = atk.kinit(user)
        t0 = time.time()
        res, t_restrict, first_level_t = [], None, None
        for s in svcs:
            r = atk.kvno(s, etype)
            res.append(r)
            if r[0] != "full" and t_restrict is None:
                t_restrict = round(time.time() - t0, 3)
            d.tick()
            if first_level_t is None and eng.state.get(user, [0])[0] > 0:
                first_level_t = round(time.time() - t0, 3)
            if attack_delay > 0:
                time.sleep(attack_delay)   # paced attacker: gives the async loop time to react between requests
        out = tally(res)
        out.update(requests=len(res), time_to_first_restriction_s=t_restrict,
                   engine_first_flag_s=first_level_t,
                   lifetimes_s=[l for _, l in res if l is not None])
        return out

    print("  attack 1: AES Kerberoasting (18 distinct SPNs)", flush=True)
    m["kerberoast_aes"] = attack_loop("user01@LAB.TEST", SERVICES[:18], None)
    print("  attack 2: RC4 Kerberoasting (10 distinct RC4-capable SPNs)", flush=True)
    m["kerberoast_rc4"] = attack_loop("user02@LAB.TEST", SERVICES[10:20], "arcfour-hmac")

    print("  attack 3: password spray (15 victims x 3 wrong passwords)", flush=True)
    spr = Actor("sprayer")
    victims = USERS[10:25]
    for v in victims:
        for _ in range(3):
            spr.kinit(v, password="WrongPassword!")
            d.tick()
    d.tick(force=True)
    time.sleep(max(poll, 1.2) + 0.3)  # table published, plugin re-stat'd
    d.tick(force=True)
    time.sleep(1.2)
    vres = [Actor("victim").kinit(v) for v in victims]   # the victims then log in legitimately
    c = tally(vres)
    m["spray"] = {"victims": len(victims), "legit_login_full": c["full"], "legit_login_capped": c["capped"],
                  "legit_login_denied": c["denied"], "legit_login_failed": c["failed"],
                  "victim_lifetimes_s": [l for _, l in vres if l is not None]}

    if alog:
        alog.close()
        v = audit.verify(AUDIT_PATH, key.public_key())
        m["audit"] = {"verified": bool(v.ok), "records": v.n}
    m["engine_events_fed"] = d.fed
    sh(f"rm -f {TABLE_PATH}")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--train", type=int, default=240)
    ap.add_argument("--attack-delays", default="0",
                    help="comma-separated pause (s) between attacker requests, e.g. 0,1,3 (0 = burst)")
    ap.add_argument("--out", default="out/x1_x2_x3_real_results.json")
    a = ap.parse_args()
    delays = [float(x) for x in a.attack_delays.split(",")]
    os.makedirs("out", exist_ok=True)
    train_events = train(random.Random(7), a.train)
    runs = []
    for rep in range(a.repeats):
        for delay in delays:
            for mode in ("unprotected", "threshold", "azk"):
                runs.append(one_run(mode, train_events, a.poll, 1000 + rep, delay))
                with open(a.out, "w") as f:
                    json.dump({"poll_s": a.poll, "attack_delays_s": delays, "repeats_done": rep,
                               "train_events": len(train_events), "runs": runs}, f, indent=2)
    print("\n=========== SUMMARY (mean over repeats; per-run values in the JSON) ===========")
    for delay in delays:
        print(f"--- attacker pacing {delay}s between requests, poll {a.poll}s ---")
        for mode in ("unprotected", "threshold", "azk"):
            rs = [r for r in runs if r["mode"] == mode and r["attack_delay_s"] == delay]
            if not rs:
                continue
            mean = lambda fn: round(statistics.mean(fn(r) for r in rs), 2)  # noqa: E731
            print(f"{mode:12s} n={len(rs)} AES full {mean(lambda r: r['kerberoast_aes']['full'])}/18  "
                  f"capped {mean(lambda r: r['kerberoast_aes']['capped'])}  denied {mean(lambda r: r['kerberoast_aes']['denied'])} | "
                  f"RC4 full {mean(lambda r: r['kerberoast_rc4']['full'])}/10 capped {mean(lambda r: r['kerberoast_rc4']['capped'])} "
                  f"denied {mean(lambda r: r['kerberoast_rc4']['denied'])} failed {mean(lambda r: r['kerberoast_rc4']['failed'])} | "
                  f"benign restricted req {mean(lambda r: r['benign']['restricted_requests'])}/{rs[0]['benign']['requests']} | "
                  f"victims denied {mean(lambda r: r['spray']['legit_login_denied'])} capped {mean(lambda r: r['spray']['legit_login_capped'])}")


if __name__ == "__main__":
    main()
