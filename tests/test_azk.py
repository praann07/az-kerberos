import json
import os
import shutil
import tempfile

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from azk import audit, risktable
from azk.engine import Engine
from azk.features import FeatureExtractor
from azk.logparse import parse_line
from azk.scorer import LevelMap, ThresholdRule
from azk import simulator as sim


# ---------- logparse ----------
def test_parse_as_issue_and_tgs_rc4():
    ev = parse_line(sim.as_ok(1000.0, "10.0.0.1", "alice@EXAMPLE.COM"))
    assert (ev.kind, ev.ok, ev.client, ev.ip) == ("AS", True, "alice@EXAMPLE.COM", "10.0.0.1")
    assert ev.rep_etypes == (18, 18, 18)
    ev = parse_line(sim.tgs_ok(1000.0, "10.0.0.1", "alice@EXAMPLE.COM", "host/a@EXAMPLE.COM", rc4=True))
    assert ev.kind == "TGS" and ev.service == "host/a@EXAMPLE.COM" and 23 in ev.rep_etypes


def test_parse_real_kdc_lines_from_live_mit_krb5():
    """Lines captured verbatim (hostname sanitised) from a live MIT krb5 1.20.1 KDC on 2026-11-20..22.

    Regression: TGS failure lines have NO comma after the etypes block; an earlier regex dropped them."""
    path = os.path.join(os.path.dirname(__file__), "real_kdc_lines_sample.txt")
    lines = [ln.rstrip("\n") for ln in open(path, encoding="utf-8") if ln.strip()]
    assert len(lines) == 10
    evs = [parse_line(ln) for ln in lines]
    assert all(e is not None for e in evs), [ln[:90] for ln, e in zip(lines, evs) if e is None]
    got = [(e.kind, e.status) for e in evs]
    assert got == [("AS", "NEEDED_PREAUTH"), ("AS", "ISSUE"), ("POLICY", "POLICY"), ("POLICY", "POLICY"),
                   ("AS", "AZK_RISK_DENY"), ("TGS", "ISSUE"), ("TGS", "AZK_RISK_DENY"),
                   ("TGS", "BAD_ENCRYPTION_TYPE"), ("AS", "PREAUTH_FAILED"), ("TGS", "LOOKING_UP_SERVER")]
    tgs_fail = evs[6]
    assert not tgs_fail.ok and tgs_fail.client == "alice@LAB.TEST" and tgs_fail.service == "svc03/host.lab.test@LAB.TEST"
    assert evs[1].ok and evs[1].client == "alice@LAB.TEST" and evs[1].ip == "127.0.0.1"
    assert evs[3].policy["deny"] in (1, True)


def test_parse_as_failure_and_needed_preauth():
    ev = parse_line(sim.as_fail(5.0, "1.2.3.4", "bob@EXAMPLE.COM"))
    assert ev.kind == "AS" and not ev.ok and ev.status == "PREAUTH_FAILED" and ev.client == "bob@EXAMPLE.COM"
    assert parse_line(sim.as_needed(5.0, "1.2.3.4", "bob@EXAMPLE.COM")).status == "NEEDED_PREAUTH"


def test_parse_policy_line_and_junk():
    ev = parse_line("2026-11-20T10:00:00Z kdc AZK_POLICY phase=AS client=a@R level=2 lifetime=600 renew=1 deny=0 table_gen=17")
    assert ev.kind == "POLICY" and ev.policy["level"] == 2 and ev.policy["table_gen"] == 17
    assert parse_line("2026-11-20T10:00:00Z kdc something else") is None
    assert parse_line("no timestamp AS_REQ nonsense") is None


# ---------- risktable ----------
def _entries(n):
    return [risktable.Entry(f"u{i}@EXAMPLE.COM", 1 + i % 3, 600, 1, 5000) for i in range(n)]


def test_risktable_roundtrip_and_miss():
    es = _entries(200)
    t = risktable.RiskTable(risktable.build(es, 1234))
    assert t.generated_at == 1234
    for e in es:
        assert t.lookup(e.principal, 100) == e
    assert t.lookup("nobody@EXAMPLE.COM", 100) is None


def test_risktable_expiry_stale_and_min_caps():
    t = risktable.RiskTable(risktable.build([risktable.Entry("a@R", 1, 0, 0, 100)], 50))
    e = t.lookup("a@R", 99)
    assert (e.lifetime_cap, e.renew_cap) == (1, 1)      # 0 would mean 'unconstrained' to the KDC
    assert t.lookup("a@R", 100) is None                 # expired
    assert t.is_stale(50 + 301) and not t.is_stale(50 + 299)


def test_risktable_rejects_garbage_and_long_names():
    with pytest.raises(ValueError):
        risktable.RiskTable(b"XXXX" + b"\0" * 28)
    with pytest.raises(ValueError):
        risktable.build([risktable.Entry("x" * 64, 1, 1, 1, 1)], 0)


def test_risktable_layout_offsets_match_c_plugin():
    data = risktable.build([risktable.Entry("a@R", 2, 600, 1, 4242)], 777)
    assert data[:4] == b"AZRT" and len(data) == 32 + 64 * 88
    assert int.from_bytes(data[12:20], "little") == 777            # generated_at offset 12
    slot = next(data[32 + i * 88: 32 + (i + 1) * 88] for i in range(64)
                if any(data[32 + i * 88: 32 + i * 88 + 8]))
    assert int.from_bytes(slot[0:8], "little") == risktable.fnv1a64(b"a@R")
    assert slot[8:11] == b"a@R"
    assert [int.from_bytes(slot[o:o + 4], "little") for o in (72, 76, 80, 84)] == [2, 600, 1, 4242]


def test_fnv1a64_known_vectors():
    assert risktable.fnv1a64(b"a") == 0xAF63DC4C8601EC8C       # published FNV-1a 64 test vector
    assert risktable.fnv1a64(b"foobar") == 0x85944171F73967E8


def test_write_atomic_replaces(tmp_path):
    p = str(tmp_path / "t.bin")
    risktable.write_atomic(p, _entries(3), 1)
    risktable.write_atomic(p, _entries(5), 2)
    assert risktable.RiskTable.load(p).generated_at == 2
    assert [f for f in os.listdir(tmp_path) if ".tmp." in f] == []


# ---------- audit ----------
def _make_log(tmp_path, n=10, every=4):
    p = str(tmp_path / "a.log")
    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(p, key, ckpt_every=every)
    for i in range(n):
        log.append("risk_update", {"client": f"u{i}", "level": 1})
    anchor = log.anchor()
    log.close()
    return p, key, anchor


def _lines(p):
    with open(p, "rb") as f:
        return f.read().splitlines()


def _write(p, lines):
    with open(p, "wb") as f:
        f.write(b"\n".join(lines) + b"\n")


def test_audit_clean_verifies(tmp_path):
    p, key, anchor = _make_log(tmp_path)
    r = audit.verify(p, key.public_key(), anchor)
    assert r.ok and r.signed_through_seq == r.last_seq


def test_audit_detects_edit_delete_reorder_insert(tmp_path):
    p, key, _ = _make_log(tmp_path)
    orig = _lines(p)
    rec = json.loads(orig[2]); rec["data"]["level"] = 0
    edited = orig[:]; edited[2] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    for bad in (edited, orig[:3] + orig[4:], orig[:3] + [orig[4], orig[3]] + orig[5:],
                orig[:3] + [orig[1]] + orig[3:]):
        _write(p, bad)
        assert not audit.verify(p, key.public_key()).ok
    _write(p, orig)
    assert audit.verify(p, key.public_key()).ok


def test_audit_forged_hashes_without_key_fail_signature(tmp_path):
    p, key, _ = _make_log(tmp_path)
    orig = _lines(p)
    prev, out = audit.GENESIS, []
    for ln in orig:                       # attacker recomputes every hash after changing record 1
        r = json.loads(ln)
        if r["seq"] == 1:
            r["data"]["level"] = 0
        r["prev"] = prev
        if r["type"] != "checkpoint":
            r["hash"] = audit.record_hash(prev, r["seq"], r["ts"], r["type"], r["data"])
        else:
            r["data"]["upto_hash"] = prev if False else r["data"]["upto_hash"]
            r["hash"] = audit.record_hash(prev, r["seq"], r["ts"], r["type"], r["data"])
        prev = r["hash"]
        out.append(json.dumps(r, sort_keys=True, separators=(",", ":")).encode())
    _write(p, out)
    assert not audit.verify(p, key.public_key()).ok


def test_audit_truncation_needs_anchor(tmp_path):
    p, key, anchor = _make_log(tmp_path, n=10, every=4)
    lines = _lines(p)
    cut = next(i for i in range(len(lines) - 2, 0, -1) if json.loads(lines[i])["type"] == "checkpoint")
    _write(p, lines[:cut + 1])            # drop tail back to an earlier checkpoint
    assert audit.verify(p, key.public_key()).ok                 # self-consistent: NOT detected without anchor
    r = audit.verify(p, key.public_key(), anchor)
    assert not r.ok and "truncated" in r.error                  # detected with external anchor


def test_audit_unsigned_tail_is_rewritable_but_flagged(tmp_path):
    p = str(tmp_path / "a.log")
    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(p, key, ckpt_every=100)
    for i in range(5):
        log.append("risk_update", {"i": i})
    log._f.close()                         # simulate a crash: no final checkpoint
    r = audit.verify(p, key.public_key())
    assert r.ok and r.signed_through_seq == -1                 # chain ok, nothing signed -> caller can see that


def test_audit_reopen_continues_chain(tmp_path):
    p, key, _ = _make_log(tmp_path, n=5)
    log = audit.AuditLog(p, key, ckpt_every=4)
    log.append("risk_update", {"x": 1}); log.close()
    assert audit.verify(p, key.public_key()).ok


# ---------- features / scorer / engine ----------
def test_features_spray_and_rc4():
    ex = FeatureExtractor()
    for i in range(12):
        f = ex.update(parse_line(sim.as_fail(100 + i, "9.9.9.9", f"v{i}@EXAMPLE.COM")))
    assert f["spray_users"] == 12
    ex = FeatureExtractor()
    for i in range(4):
        f = ex.update(parse_line(sim.tgs_ok(100 + i, "9.9.9.9", "a@EXAMPLE.COM", f"s{i}@EXAMPLE.COM", rc4=True)))
    assert f["rc4_n"] == 4 and f["svc_distinct"] == 4


def test_features_needed_preauth_not_a_failure():
    ex = FeatureExtractor()
    f = ex.update(parse_line(sim.as_needed(1, "1.1.1.1", "a@EXAMPLE.COM")))
    assert f["fail_n"] == 0 and f["spray_users"] == 0


def test_levelmap_monotone_and_underpowered():
    rng = np.random.default_rng(0)
    lm = LevelMap.calibrate(rng.normal(size=2000))
    assert list(lm.cuts) == sorted(lm.cuts)
    assert lm.underpowered == [0.001, 0.0001]
    assert lm.level(-10) == 0 and lm.level(1e9) == 3


def test_threshold_rule():
    base = ThresholdRule()
    f = dict(fail_n=0, spray_users=0, svc_distinct=0, rc4_n=0, new_ip=0, rate_per_min=0)
    assert not base.alert(f)
    assert base.alert({**f, "svc_distinct": 15})


class _FixedScorer:
    name = "fixed"
    def raw(self, feat): return feat["svc_distinct"] / 10.0


def test_engine_escalates_holds_and_expires(tmp_path):
    lm = LevelMap((0.5, 1.0, 2.0))
    p = str(tmp_path / "a.log")
    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(p, key)
    eng = Engine(FeatureExtractor(), _FixedScorer(), lm, log, hold_s=100)
    for i in range(8):    # 8 distinct services -> raw 0.8 -> level 1
        eng.feed(parse_line(sim.tgs_ok(1000 + i, "7.7.7.7", "a@EXAMPLE.COM", f"s{i}@EXAMPLE.COM")))
    assert eng.state["a@EXAMPLE.COM"][0] == 1
    snap = eng.snapshot(1010)
    assert snap[0].lifetime_cap == 3600
    assert eng.snapshot(1000 + 7 + 101) == []                  # hold expired
    path = str(tmp_path / "t.bin")
    eng.publish(path, 1010)
    assert risktable.RiskTable.load(path).lookup("a@EXAMPLE.COM", 1010).level == 1
    log.close()
    assert audit.verify(p, key.public_key()).ok
    types = [json.loads(l)["type"] for l in _lines(p)]
    assert "risk_update" in types and "table_publish" in types


def test_engine_binds_policy_applied_events_into_audit(tmp_path):
    p = str(tmp_path / "a.log")
    key = Ed25519PrivateKey.generate()
    log = audit.AuditLog(p, key)
    eng = Engine(FeatureExtractor(), _FixedScorer(), LevelMap((1, 2, 3)), log)
    eng.feed(parse_line("2026-11-20T10:00:00Z kdc AZK_POLICY phase=TGS client=a@R level=2 lifetime=600 renew=1 deny=0 table_gen=9"))
    log.close()
    rec = [json.loads(l) for l in _lines(p)][0]
    assert rec["type"] == "policy_applied" and rec["data"]["level"] == 2


def test_simulator_lines_all_parse():
    d = sim.generate(seed=3, n_users=10, n_services=8, attacks_each=1)
    assert all(parse_line(l) is not None for part in d.values() for l, _ in part)


def test_engine_t1_victim_lockout_and_circuit_breaker(tmp_path):
    class _HighScorer:
        name = "high"
        def raw(self, feat): return 3.5  # would map to Level 3

    lm = LevelMap((1.0, 2.0, 3.0))
    # Test 1: pure failure signal caps at Level 2 (never Level 3 denial)
    eng = Engine(FeatureExtractor(), _HighScorer(), lm, total_principals=10, circuit_breaker_frac=0.3)
    # Feed repeated preauth failures for victim@LAB.TEST
    for i in range(12):
        eng.feed(parse_line(sim.as_fail(1000 + i, "10.0.0.1", "victim@LAB.TEST")))
    assert eng.state["victim@LAB.TEST"][0] == 2  # capped at Level 2!
    assert eng.victim_lockout_mitigations >= 1

    # Test 2: circuit breaker trips when active restrictions exceed threshold (30% of 10 = 3)
    for u in ["u1@LAB.TEST", "u2@LAB.TEST", "u3@LAB.TEST"]:
        for i in range(10):
            eng.feed(parse_line(sim.as_fail(1050 + i, "10.0.0.1", u)))
    # With breaker tripped, next user is capped at Level 1 (mild cap), preventing DoS
    for i in range(10):
        eng.feed(parse_line(sim.as_fail(1060 + i, "10.0.0.1", "u4@LAB.TEST")))
    assert eng.breaker_tripped is True
    assert eng.state["u4@LAB.TEST"][0] == 1
