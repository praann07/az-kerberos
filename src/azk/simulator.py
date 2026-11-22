"""SYNTHETIC KDC log generator in the MIT krb5 line format (see logparse.py).

For pipeline testing only. Any detection number derived from this data reflects the assumptions written
below, not real-world behaviour, and must never be reported as an evaluation result. The real evaluation
needs logs from a live MIT KDC (docs/04_evaluation_plan.md).
"""
from __future__ import annotations

import random
from datetime import datetime, timezone

REALM = "EXAMPLE.COM"
NAMES = {18: "aes256-cts-hmac-sha1-96", 17: "aes128-cts-hmac-sha1-96", 23: "arcfour-hmac"}
DAY0 = datetime(2026, 11, 16, tzinfo=timezone.utc).timestamp()


def _n(e): return f"{NAMES[e]}({e})"


def _req(etypes): return f"{len(etypes)} etypes {{{', '.join(_n(e) for e in etypes)}}}"


def _rep(rep, tkt, ses): return f"etypes {{rep={_n(rep)}, tkt={_n(tkt)}, ses={_n(ses)}}}"


def _iso(ts): return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pre(ts): return f"{_iso(ts)} kdc krb5kdc[1](info): "


def as_needed(ts, ip, c):
    return (f"{_pre(ts)}AS_REQ ({_req([18, 17])}) {ip}: NEEDED_PREAUTH: {c} for krbtgt/{REALM}@{REALM}, "
            "Additional pre-authentication required")


def as_fail(ts, ip, c, status="PREAUTH_FAILED"):
    return f"{_pre(ts)}AS_REQ ({_req([18, 17])}) {ip}: {status}: {c} for krbtgt/{REALM}@{REALM}, Preauthentication failed"


def as_ok(ts, ip, c):
    return (f"{_pre(ts)}AS_REQ ({_req([18, 17])}) {ip}: ISSUE: authtime {int(ts)}, {_rep(18, 18, 18)}, "
            f"{c} for krbtgt/{REALM}@{REALM}")


def tgs_ok(ts, ip, c, svc, rc4=False):
    req = [23] if rc4 else [18, 17]
    rep = _rep(18, 23, 23) if rc4 else _rep(18, 18, 18)
    return f"{_pre(ts)}TGS_REQ ({_req(req)}) {ip}: ISSUE: authtime {int(ts)}, {rep}, {c} for {svc}"


def generate(seed: int = 1, n_users: int = 50, n_services: int = 20, attacks_each: int = 3) -> dict:
    """Return {"train","calib","test"}: lists of (line, label). Days 0-1 train, day 2 calibration, day 3 test."""
    rng = random.Random(seed)
    users = [f"user{i:02d}@{REALM}" for i in range(n_users)]
    svcs = [f"host/svc{i:02d}.example.com@{REALM}" for i in range(n_services)]
    ips = {u: (f"10.0.{i // 250}.{i % 250 + 1}", f"10.1.{i // 250}.{i % 250 + 1}") for i, u in enumerate(users)}
    fav = {u: rng.sample(svcs, 6) for u in users}

    def benign_day(day):
        out = []
        for u in users:
            for _ in range(rng.randint(2, 4)):
                t = DAY0 + day * 86400 + rng.uniform(8, 18) * 3600
                ip = ips[u][1] if rng.random() < 0.10 else ips[u][0]
                out.append((as_needed(t, ip, u), ""))
                t += 0.2
                if rng.random() < 0.01:
                    out.append((as_fail(t, ip, u), ""))
                    t += 3
                out.append((as_ok(t, ip, u), ""))
                for _k in range(rng.randint(3, 8)):
                    t += rng.uniform(5, 300)
                    out.append((tgs_ok(t, ip, u, rng.choice(fav[u])), ""))
        return out

    def attacks(day):
        out, t0 = [], DAY0 + day * 86400
        for a in range(attacks_each):
            ip = f"198.51.100.{10 + a}"
            v = rng.choice(users); t = t0 + rng.uniform(9, 17) * 3600       # Kerberoasting, AES tickets
            out += [(as_needed(t, ip, v), f"kerberoast_aes_{a}"), (as_ok(t + .2, ip, v), f"kerberoast_aes_{a}")]
            for i, s in enumerate(svcs):
                out.append((tgs_ok(t + 1 + i * 2.5, ip, v, s), f"kerberoast_aes_{a}"))
            ip = f"198.51.100.{30 + a}"
            v = rng.choice(users); t = t0 + rng.uniform(9, 17) * 3600       # Kerberoasting, RC4 downgrade
            out += [(as_needed(t, ip, v), f"kerberoast_rc4_{a}"), (as_ok(t + .2, ip, v), f"kerberoast_rc4_{a}")]
            for i, s in enumerate(svcs):
                out.append((tgs_ok(t + 1 + i * 2, ip, v, s, rc4=True), f"kerberoast_rc4_{a}"))
            ip = f"203.0.113.{10 + a}"
            t = t0 + rng.uniform(9, 17) * 3600                              # password spray, 2 successes
            victims = rng.sample(users, min(40, len(users)))
            for i, v in enumerate(victims):
                lab = f"spray_{a}"
                out.append((as_needed(t + i * 7, ip, v), lab))
                out.append((as_fail(t + i * 7 + .1, ip, v), lab))
                if i in (20, 35):
                    out.append((as_ok(t + i * 7 + 3, ip, v), lab))
            ip = f"198.51.100.{50 + a}"
            v = rng.choice(users); t = t0 + rng.uniform(9, 17) * 3600       # low-and-slow stolen credential
            out += [(as_needed(t, ip, v), f"slow_{a}"), (as_ok(t + .2, ip, v), f"slow_{a}")]
            for i in range(4):
                out.append((tgs_ok(t + 60 + i * 300, ip, v, rng.choice(fav[v])), f"slow_{a}"))
        return out

    def srt(x): return sorted(x, key=lambda p: p[0][:20])
    return {"train": srt(benign_day(0) + benign_day(1)), "calib": srt(benign_day(2)),
            "test": srt(benign_day(3) + attacks(3))}
