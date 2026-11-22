"""Binary risk table: written atomically by the scorer, mmap'd read-only by plugin/kdcpolicy_azk.c.

Layout (little-endian, packed) - MUST match the C structs in plugin/kdcpolicy_azk.c:
  header (32 B):  magic 'AZRT' | version u32 | nslots u32 | generated_at u64 | 12 B pad
  slot  (88 B):   key u64 (FNV-1a 64 of principal, 0 = empty) | name char[64] | level u32 |
                  lifetime_cap u32 (s) | renew_cap u32 (s) | expires_at u32 (unix s)
Open addressing, linear probing, nslots a power of two. Lookup is O(1) expected, no allocation.
A cap of 0 means "no constraint" to the KDC (krb5 src/kdc/policy.c update_ticket_times), so the writer
never emits 0 for a cap on a restricted entry (min 1).
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

MAGIC = b"AZRT"
VERSION = 1
NAME_LEN = 64
HDR = struct.Struct("<4sIIQ12x")
SLOT = struct.Struct("<Q64sIIII")
assert HDR.size == 32 and SLOT.size == 88
DENY_LEVEL = 3


def fnv1a64(b: bytes) -> int:
    h = 0xCBF29CE484222325
    for c in b:
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h or 1


@dataclass(frozen=True)
class Entry:
    principal: str
    level: int
    lifetime_cap: int
    renew_cap: int
    expires_at: int


def build(entries: list, generated_at: int) -> bytes:
    n = max(len(entries), 1)
    nslots = 64
    while nslots < 4 * n:
        nslots *= 2
    slots = [None] * nslots
    for e in entries:
        nb = e.principal.encode()
        if len(nb) >= NAME_LEN:
            raise ValueError(f"principal too long for table ({len(nb)} >= {NAME_LEN}): {e.principal[:20]}...")
        h = fnv1a64(nb)
        i = h & (nslots - 1)
        while slots[i] is not None:
            i = (i + 1) & (nslots - 1)
        life = max(1, e.lifetime_cap)
        ren = max(1, e.renew_cap)
        slots[i] = SLOT.pack(h, nb, e.level, life, ren, e.expires_at)
    empty = b"\x00" * SLOT.size
    return HDR.pack(MAGIC, VERSION, nslots, generated_at) + b"".join(s or empty for s in slots)


def write_atomic(path: str, entries: list, generated_at: int) -> bytes:
    data = build(entries, generated_at)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # readers keep the old inode mapped until they remap
    return data


class RiskTable:
    """Reference reader implementing exactly the lookup the C plugin performs."""

    def __init__(self, data: bytes):
        magic, ver, nslots, gen = HDR.unpack_from(data, 0)
        if magic != MAGIC or ver != VERSION:
            raise ValueError("bad risk table header")
        if len(data) != HDR.size + nslots * SLOT.size or nslots & (nslots - 1):
            raise ValueError("bad risk table size")
        self.data, self.nslots, self.generated_at = data, nslots, gen

    @classmethod
    def load(cls, path: str) -> "RiskTable":
        with open(path, "rb") as f:
            return cls(f.read())

    def is_stale(self, now: float, stale_after: float = 300.0) -> bool:
        return now - self.generated_at > stale_after

    def lookup(self, principal: str, now: float):
        nb = principal.encode()
        h = fnv1a64(nb)
        i = h & (self.nslots - 1)
        for _ in range(self.nslots):
            key, name, level, life, ren, exp = SLOT.unpack_from(self.data, HDR.size + i * SLOT.size)
            if key == 0:
                return None
            if key == h and name.rstrip(b"\x00") == nb:
                return Entry(principal, level, life, ren, exp) if exp > now else None
            i = (i + 1) & (self.nslots - 1)
        return None
