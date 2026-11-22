"""Sliding-window per-principal features computed from parsed KDC events (async path only)."""
from __future__ import annotations

from collections import defaultdict, deque

from .logparse import Event, RC4_ETYPES

FEATURES = ["fail_n", "spray_users", "svc_distinct", "rc4_n", "new_ip", "rate_per_min"]

# NEEDED_PREAUTH is the normal first leg of a preauth exchange, not a failure.
_BENIGN_NONISSUE = {"NEEDED_PREAUTH"}


class FeatureExtractor:
    def __init__(self, window_s: float = 300.0):
        self.window_s = window_s
        self.known_ips: dict[str, set] = defaultdict(set)   # frozen after fit; attacker IPs never learned
        self._by_client: dict[str, deque] = defaultdict(deque)
        self._fail_by_ip: dict[str, deque] = defaultdict(deque)

    def learn_ips(self, events) -> None:
        """Baseline pass: record which source addresses each principal normally uses."""
        for ev in events:
            if ev.kind in ("AS", "TGS") and ev.ok:
                self.known_ips[ev.client].add(ev.ip)

    def reset_windows(self) -> None:
        self._by_client.clear()
        self._fail_by_ip.clear()

    def update(self, ev: Event):
        """Return a feature dict for ev.client after absorbing ev, or None for non-request events."""
        if ev.kind not in ("AS", "TGS"):
            return None
        cutoff = ev.ts - self.window_s
        dq = self._by_client[ev.client]
        rc4 = ev.kind == "TGS" and ev.ok and any(e in RC4_ETYPES for e in ev.rep_etypes)
        dq.append((ev.ts, ev.kind, ev.ok, ev.status, ev.service, rc4))
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        fq = self._fail_by_ip[ev.ip]
        if ev.kind == "AS" and not ev.ok and ev.status not in _BENIGN_NONISSUE:
            fq.append((ev.ts, ev.client))
        while fq and fq[0][0] < cutoff:
            fq.popleft()
        fail_n = sum(1 for _t, k, ok, st, _s, _r in dq
                     if k == "AS" and not ok and st not in _BENIGN_NONISSUE)
        svcs = {s for _t, k, ok, _st, s, _r in dq if k == "TGS" and ok}
        return {
            "fail_n": float(fail_n),
            "spray_users": float(len({c for _t, c in fq})),
            "svc_distinct": float(len(svcs)),
            "rc4_n": float(sum(1 for *_x, r in dq if r)),
            "new_ip": 0.0 if ev.ip in self.known_ips[ev.client] else 1.0,
            "rate_per_min": len(dq) / (self.window_s / 60.0),
        }


def vector(feat: dict) -> list:
    return [feat[k] for k in FEATURES]
