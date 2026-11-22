"""Hash-chained audit log with Ed25519-signed checkpoints.

Each record: {"seq","ts","prev","type","data","hash"}, hash = SHA-256(prev_bytes || canonical([seq,ts,type,data])).
A "checkpoint" record signs the hash of the record before it. What this does and does NOT protect
(stated plainly because hash chains are old and standard - see survey P4):
  * Edit / delete / reorder / insert before the last checkpoint: detected (hash chain + signature).
  * Records after the last checkpoint: only hash-linked, NOT signed. An attacker who can write the file
    can rewrite them and recompute hashes. close() writes a final checkpoint to minimise this window.
  * Tail truncation back to an earlier checkpoint stays internally consistent; it is detected only if the
    verifier holds an external anchor (seq, hash) saved elsewhere. verify(anchor=...) implements the check.
  * Key compromise: not forward-secure. Keep the signing key off the KDC host.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "00" * 32


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def record_hash(prev_hex: str, seq: int, ts: float, typ: str, data) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hex) + _canon([seq, ts, typ, data])).hexdigest()


def _ckpt_msg(seq: int, h_hex: str) -> bytes:
    return b"AZK-CKPT\x00" + struct.pack(">Q", seq) + bytes.fromhex(h_hex)


class AuditLog:
    def __init__(self, path: str, priv: Ed25519PrivateKey, ckpt_every: int = 64,
                 fsync: bool = False, clock=time.time):
        self.path, self.priv, self.ckpt_every, self.fsync, self.clock = path, priv, ckpt_every, fsync, clock
        self.seq, self.last_hash, self._since_ckpt, self._last_type = -1, GENESIS, 0, None
        if os.path.exists(path):
            with open(path, "rb") as f:
                for line in f:
                    r = json.loads(line)
                    self.seq, self.last_hash, self._last_type = r["seq"], r["hash"], r["type"]
                    self._since_ckpt = 0 if r["type"] == "checkpoint" else self._since_ckpt + 1
        self._f = open(path, "ab")

    def _write(self, typ: str, data) -> int:
        seq, ts = self.seq + 1, round(self.clock(), 6)
        h = record_hash(self.last_hash, seq, ts, typ, data)
        rec = {"seq": seq, "ts": ts, "prev": self.last_hash, "type": typ, "data": data, "hash": h}
        self._f.write(_canon(rec) + b"\n")
        self._f.flush()
        if self.fsync:
            os.fsync(self._f.fileno())
        self.seq, self.last_hash, self._last_type = seq, h, typ
        return seq

    def append(self, typ: str, data) -> int:
        seq = self._write(typ, data)
        self._since_ckpt += 1
        if self._since_ckpt >= self.ckpt_every:
            self.checkpoint()
        return seq

    def checkpoint(self) -> int:
        if self.seq < 0:
            raise ValueError("nothing to checkpoint")
        sig = self.priv.sign(_ckpt_msg(self.seq, self.last_hash)).hex()
        seq = self._write("checkpoint", {"upto_seq": self.seq, "upto_hash": self.last_hash, "sig": sig})
        self._since_ckpt = 0
        return seq

    def anchor(self) -> tuple:
        """(seq, hash) of the newest record; store this somewhere the KDC host cannot write."""
        return (self.seq, self.last_hash)

    def close(self) -> None:
        if self.seq >= 0 and self._last_type != "checkpoint":
            self.checkpoint()
        self._f.close()


@dataclass
class VerifyResult:
    ok: bool
    n: int = 0
    last_seq: int = -1
    last_hash: str = GENESIS
    signed_through_seq: int = -1
    error: Optional[str] = None


def verify(path: str, pub: Ed25519PublicKey, anchor: Optional[tuple] = None) -> VerifyResult:
    res = VerifyResult(ok=False)
    prev, expect, anchor_ok = GENESIS, 0, anchor is None
    try:
        with open(path, "rb") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    res.error = f"unparseable record at expected seq {expect}"
                    return res
                if r.get("seq") != expect:
                    res.error = f"sequence gap/reorder: got {r.get('seq')} expected {expect}"
                    return res
                if r["prev"] != prev:
                    res.error = f"broken chain link at seq {expect}"
                    return res
                if record_hash(prev, r["seq"], r["ts"], r["type"], r["data"]) != r["hash"]:
                    res.error = f"record hash mismatch at seq {expect}"
                    return res
                if r["type"] == "checkpoint":
                    d = r["data"]
                    if d["upto_seq"] != expect - 1 or d["upto_hash"] != prev:
                        res.error = f"checkpoint at seq {expect} does not cover previous record"
                        return res
                    try:
                        pub.verify(bytes.fromhex(d["sig"]), _ckpt_msg(d["upto_seq"], d["upto_hash"]))
                    except InvalidSignature:
                        res.error = f"bad checkpoint signature at seq {expect}"
                        return res
                    res.signed_through_seq = expect
                if anchor is not None and expect == anchor[0]:
                    if r["hash"] != anchor[1]:
                        res.error = f"anchor mismatch at seq {expect}"
                        return res
                    anchor_ok = True
                prev, expect = r["hash"], expect + 1
    except FileNotFoundError:
        res.error = "log file missing"
        return res
    res.n, res.last_seq, res.last_hash = expect, expect - 1, prev
    if not anchor_ok:
        res.error = f"log truncated: anchor seq {anchor[0]} not present (log ends at {expect - 1})"
        return res
    res.ok = True
    return res
