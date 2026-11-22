"""End-to-end SYNTHETIC smoke run: simulator -> parser -> features -> scorer -> engine -> risk table + audit log.

    python -m azk.demo [outdir]      (run with PYTHONPATH=src)

Output is a pipeline check, NOT an evaluation (see simulator.py docstring).
"""
from __future__ import annotations

import os
import sys
import time
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import risktable
from .audit import AuditLog, verify
from .engine import Engine
from .features import FeatureExtractor
from .logparse import parse_line
from .scorer import IForestScorer, LevelMap, ThresholdRule
from .simulator import generate

LAG_S = 5.0  # modelled delay: log tail + table publish before the plugin can see a new risk level


def _parse(pairs):
    return [(parse_line(l), lab) for l, lab in pairs]


def run(outdir: str = "out", seed: int = 1, attacks_each: int = 3) -> dict:
    os.makedirs(outdir, exist_ok=True)
    d = {k: _parse(v) for k, v in generate(seed, attacks_each=attacks_each).items()}
    ex = FeatureExtractor()
    ex.learn_ips(e for e, _ in d["train"])
    ex.reset_windows()
    train_f = [ex.update(e) for e, _ in d["train"]]
    scorer = IForestScorer(seed=seed).fit(train_f)
    ex.reset_windows()
    calib_raw = scorer.raw_many([ex.update(e) for e, _ in d["calib"]])
    lm = LevelMap.calibrate(calib_raw)

    audit_path = os.path.join(outdir, "audit.log")
    if os.path.exists(audit_path):
        os.remove(audit_path)
    key = Ed25519PrivateKey.generate()
    audit = AuditLog(audit_path, key, ckpt_every=64)
    ex.reset_windows()
    eng = Engine(ex, scorer, lm, audit, model_id="isolation_forest_v0")
    for e, _ in d["test"]:
        eng.feed(e)
    now = next(t[0].ts for t in eng.trace if t[3] >= 1)  # publish while the first restriction is held
    table_path = os.path.join(outdir, "risk_table.bin")
    eng.publish(table_path, now)
    anchor = audit.anchor()
    audit.close()
    vr = verify(audit_path, key.public_key(), anchor=anchor)

    # Baseline (static threshold rule) on the same test events, fresh windows.
    base, ex2 = ThresholdRule(), FeatureExtractor()
    ex2.known_ips = ex.known_ips
    base_alert = [base.alert(ex2.update(e)) for e, _ in d["test"]]

    n_benign = sum(1 for _, lab in d["test"] if not lab)
    tbl = risktable.RiskTable.load(table_path)
    res = {"audit": vr, "table_entries": len(eng.snapshot(now)),
           "table_lookup_ok": all(tbl.lookup(e.principal, now) == e for e in eng.snapshot(now)),
           "levelmap_cuts": lm.cuts, "underpowered_alphas": lm.underpowered, "n_calib": lm.n_calib,
           "attacks": {}}
    ev_idx = defaultdict(list)
    for i, (e, lab) in enumerate(d["test"]):
        if lab:
            ev_idx[lab].append(i)
    for lab, idxs in sorted(ev_idx.items()):
        row = {}
        for name, flags in (("iforest", [t[3] >= 1 for t in eng.trace]),
                            ("threshold", base_alert)):
            first = next((i for i in idxs if flags[i]), None)
            if first is None:
                row[name] = (False, 0, 0)
                continue
            t_det = d["test"][first][0].ts + LAG_S
            iss = [i for i in idxs if d["test"][i][0].ok and d["test"][i][0].ts >= t_det]
            tot = sum(1 for i in idxs if d["test"][i][0].ok)
            row[name] = (True, len(iss), tot)
        res["attacks"][lab] = row
    ben = [i for i, (_, lab) in enumerate(d["test"]) if not lab]
    res["false_restriction_events"] = {
        "iforest": sum(1 for i in ben if eng.trace[i][3] >= 1) / n_benign,
        "threshold": sum(1 for i in ben if base_alert[i]) / n_benign}
    restricted = {d["test"][i][0].client for i in ben if eng.trace[i][3] >= 1}
    targeted = {e.client for e, lab in d["test"] if lab}   # principals that appear in any attack event
    res["benign_principals_restricted_iforest"] = len(restricted)
    res["of_which_also_attack_targets"] = len(restricted & targeted)
    return res


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "out"
    t0 = time.time()
    r = run(out)
    print(f"SYNTHETIC smoke run ({time.time() - t0:.1f}s) - pipeline check, not an evaluation")
    a = r["audit"]
    print(f"audit verify ok={a.ok} records={a.n} signed_through={a.signed_through_seq} err={a.error}")
    print(f"risk table entries (published at first restriction): {r['table_entries']}, python reader round-trip ok: "
          f"{r['table_lookup_ok']}; level cuts: {[round(c, 3) for c in r['levelmap_cuts']]}")
    print(f"calibration events: {r['n_calib']}; alphas too small to resolve: {r['underpowered_alphas']}")
    print(f"benign events restricted: iforest {r['false_restriction_events']['iforest']:.4f}, "
          f"threshold {r['false_restriction_events']['threshold']:.4f}; "
          f"benign principals ever restricted (iforest): {r['benign_principals_restricted_iforest']} "
          f"(of which also targeted by an attack: {r['of_which_also_attack_targets']})")
    print("attack | iforest: detected, issuances after detect+lag / issuances | threshold: same")
    for lab, row in r["attacks"].items():
        f = lambda t: f"{'Y' if t[0] else 'N'} {t[1]}/{t[2]}"
        print(f"{lab:18s} | {f(row['iforest']):10s} | {f(row['threshold'])}")


if __name__ == "__main__":
    main()
