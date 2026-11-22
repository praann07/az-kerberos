"""Async scoring engine: events in -> per-principal risk state -> risk table + audit records out.

Nothing here runs on the KDC request path. The only thing the KDC sees is the published table.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from . import risktable
from .audit import AuditLog
from .features import FeatureExtractor

# level -> (lifetime_cap_s, renew_cap_s). Level 3 = deny. Caps only TIGHTEN (krb5 policy.c uses ts_min).
# renew=1 s is the closest expressible "no useful renewal" because 0 means "unconstrained" - TO BE TESTED on a real KDC.
DEFAULT_POLICY = {1: (3600, 4 * 3600), 2: (600, 1), 3: (1, 1)}


def count_elevated_signals(feat: dict) -> int:
    signals = 0
    if feat.get("fail_n", 0) >= 5: signals += 1
    if feat.get("spray_users", 0) >= 5: signals += 1
    if feat.get("svc_distinct", 0) >= 10: signals += 1
    if feat.get("rc4_n", 0) >= 5: signals += 1
    if feat.get("new_ip", 0) >= 1: signals += 1
    if feat.get("rate_per_min", 0) >= 20: signals += 1
    return signals


class Engine:
    def __init__(self, extractor: FeatureExtractor, scorer, levelmap, audit: Optional[AuditLog] = None,
                 hold_s: float = 900.0, policy: dict = DEFAULT_POLICY, model_id: str = "",
                 cap_failures: bool = True, max_failure_level: int = 2,
                 require_two_signals_for_l3: bool = True,
                 circuit_breaker_frac: float = 0.25, total_principals: int = 50):
        self.ex, self.scorer, self.levelmap, self.audit = extractor, scorer, levelmap, audit
        self.hold_s, self.policy, self.model_id = hold_s, policy, model_id
        self.cap_failures = cap_failures
        self.max_failure_level = max_failure_level
        self.require_two_signals_for_l3 = require_two_signals_for_l3
        self.circuit_breaker_frac = circuit_breaker_frac
        self.total_principals = total_principals
        self.breaker_tripped = False
        self.victim_lockout_mitigations = 0
        self.state: dict[str, list] = {}   # client -> [level, expires_ts]
        self.dropped_oversized = 0         # restricted names too long for a table slot (skipped)
        self.ambiguous_events = 0          # log lines whose client/service split was not unique (informational)
        self.trace: list = []              # (event, raw_score, instantaneous_level, effective_level)

    def feed(self, ev) -> None:
        if getattr(ev, "ambiguous", False):
            self.ambiguous_events += 1
        if ev.kind == "POLICY":
            if self.audit:
                self.audit.append("policy_applied", {"client": ev.client, "event_ts": ev.ts, **ev.policy})
            return
        feat = self.ex.update(ev)
        if feat is None:
            return
        raw = self.scorer.raw(feat)
        lvl = self.levelmap.level(raw)

        # Threat T1 Mitigation: Victim lock-out protection
        # Pre-authentication events (AS phase) alone MUST NEVER escalate to Level 3 denial.
        # An attacker without valid credentials cannot Kerberoast or query TGS.
        # If no service ticket anomalies exist (svc_distinct == 0 and rc4_n == 0),
        # cap at max_failure_level (default 2: short lifetime, never denial).
        if self.cap_failures and lvl > self.max_failure_level:
            if feat.get("svc_distinct", 0) == 0 and feat.get("rc4_n", 0) == 0:
                lvl = self.max_failure_level
                self.victim_lockout_mitigations += 1

        # Require two independent elevated signals for Level 3 denial
        elevated = count_elevated_signals(feat)
        if self.require_two_signals_for_l3 and lvl >= 3 and elevated < 2:
            lvl = 2
            self.victim_lockout_mitigations += 1

        # Global circuit breaker: prevent mass restrictions if spray targets wide realm
        active_restricted = sum(1 for c, (l, exp) in self.state.items() if exp > ev.ts and l >= 2)
        if active_restricted >= self.total_principals * self.circuit_breaker_frac:
            if not self.breaker_tripped:
                self.breaker_tripped = True
                if self.audit:
                    self.audit.append("circuit_breaker_tripped", {
                        "event_ts": ev.ts, "active_restricted": active_restricted,
                        "threshold": self.total_principals * self.circuit_breaker_frac})
            if lvl >= 2:
                lvl = 1  # degrade to mild lifetime cap, never lock out the realm

        st = self.state.get(ev.client)
        if st and ev.ts >= st[1]:
            del self.state[ev.client]
            st = None
        cur = st[0] if st else 0
        if lvl > 0 and lvl >= cur:
            self.state[ev.client] = [lvl, ev.ts + self.hold_s]
            if lvl != cur and self.audit:
                self.audit.append("risk_update", {
                    "client": ev.client, "level": lvl, "prev_level": cur, "score": round(raw, 6),
                    "features": {k: round(v, 3) for k, v in feat.items()},
                    "model_id": self.model_id or getattr(self.scorer, "name", ""), "event_ts": ev.ts})
        eff = self.state[ev.client][0] if ev.client in self.state else 0
        self.trace.append((ev, raw, lvl, eff))

    def snapshot(self, now: float) -> list:
        out = []
        for client, (lvl, exp) in self.state.items():
            if exp > now:
                # Principal names come from the log and are attacker-controlled (a failed AS_REQ
                # logs any name). A name that does not fit a table slot must be skipped, not
                # raise: risktable.build() is strict, and one exception here would stop every
                # table publish, i.e. fail open for all principals.
                if len(client.encode()) >= risktable.NAME_LEN:
                    self.dropped_oversized += 1
                    continue
                life, ren = self.policy[min(lvl, max(self.policy))]
                out.append(risktable.Entry(client, lvl, life, ren, int(exp)))
        return out

    def publish(self, path: str, now: float) -> bytes:
        entries = self.snapshot(now)
        data = risktable.write_atomic(path, entries, int(now))
        if self.audit:
            self.audit.append("table_publish", {
                "generated_at": int(now), "n_entries": len(entries),
                "sha256": hashlib.sha256(data).hexdigest(),
                "entries": [[e.principal, e.level, e.lifetime_cap, e.renew_cap, e.expires_at] for e in entries]})
        return data
