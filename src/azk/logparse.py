"""Parse MIT krb5 KDC log lines.

Line formats are taken from the krb5 source (src/kdc/kdc_log.c log_as_req/log_tgs_req and
src/kdc/kdc_util.c ktypes2str/rep_etypes2str, master branch, fetched 2026-11-20):

  AS_REQ (N etypes {name(id), ...}) ADDR: ISSUE: authtime T, etypes {rep=n(id), tkt=n(id), ses=n(id)}, CLIENT for SERVICE
  AS_REQ (N etypes {...}) ADDR: STATUS: CLIENT for SERVICE[, message]
  TGS_REQ (N etypes {...}) ADDR: STATUS: authtime T, [etypes {...},] CLIENT for SERVICE[, message]

Our own plugin emits (see plugin/kdcpolicy_azk.c):
  AZK_POLICY phase=AS|TGS client=C level=L lifetime=S renew=S deny=0|1 table_gen=EPOCH

Real-line check (2026-11-22, MIT krb5 1.20.1-6ubuntu2.10 on WSL Ubuntu 24.04, logging = SYSLOG:INFO:DAEMON):
the format strings above match live output, except that TGS failure lines have no comma after the
etypes block (handled in _TGS), and the ADDR token is printed as e.g. "127.0.0.1". tests/test_azk.py
includes lines copied from a live journal (tests/real_kdc_lines_sample.txt).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

RC4_ETYPES = frozenset({23, 24})  # arcfour-hmac, arcfour-hmac-exp

_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)\s")
_BSD = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}:\d{2}:\d{2})\s")
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
# Security: every pattern is applied with .match() at the START of the syslog *message* (after the
# timestamp, optional host and optional "tag[pid](info):" token), never .search() anywhere in the line.
# Principal names are attacker-controlled (a failed AS_REQ logs whatever name was sent), so a name
# containing "AZK_POLICY phase=AS client=..." must not be parsed as a policy line.
_MSG_START = re.compile(r"^(?:\S+\s+)?(?:[^\s:]+:\s+)?(?=(?:AS_REQ|TGS_REQ) \(|AZK_POLICY )")
_REQ = re.compile(r"(AS_REQ|TGS_REQ) \((\d+) etypes \{([^}]*)\}\) (\S+): ([A-Z0-9_]+): (.*)$")
_ETID = re.compile(r"\((\d+)\)")
# Client groups are (.+?)/(.+): principal names may contain spaces; a strict \S+ would make such
# lines unparseable and let an attacker hide failed attempts from the counters.
_AS_OK = re.compile(r"authtime (\d+), (etypes \{[^}]*\}), (.+) for (\S+)$")
# Greedy client + service token that must contain "@" (the KDC always prints the full principal):
# the split is the LAST " for <principal>", so a name that itself contains " for krbtgt/X@Y, ..."
# stays inside the client field instead of misattributing the failure to another principal.
# KDC message text (e.g. "KDC has no support for encryption type") has no "@" token after " for ".
_AS_FAIL = re.compile(r"(.+) for (\S+@\S+?)(?:, (.*))?$")
# Real MIT krb5 1.20.1 output: ISSUE lines have "etypes {...}, CLIENT" but failure lines
# (AZK_RISK_DENY, LOOKING_UP_SERVER, BAD_ENCRYPTION_TYPE) have "etypes {...} CLIENT" with NO comma.
_TGS = re.compile(r"authtime (\d+),(?: (etypes \{[^}]*\}),?)?\s*(.+) for (\S+@\S+?)(?:, (.*))?$")
# Greedy client + end anchor: the numeric fields at the end of the line are written by our plugin,
# so the split point is the LAST " level=" even if the principal name itself contains one.
_POLICY = re.compile(
    r"AZK_POLICY phase=(AS|TGS) client=(.+) level=(\d+) lifetime=(\d+) renew=(\d+) deny=(\d) table_gen=(\d+)\s*$")


@dataclass(frozen=True)
class Event:
    ts: float
    kind: str                      # "AS" | "TGS" | "POLICY"
    ok: bool
    status: str
    ip: str
    client: str
    service: str
    req_etypes: tuple = ()
    rep_etypes: tuple = ()         # (rep, tkt, ses) enctype ids that were present
    policy: Optional[dict] = None  # POLICY events only


def _split_timestamp(line: str, year: Optional[int]) -> tuple:
    """Return (epoch or None, rest-of-line after the timestamp)."""
    m = _ISO.match(line)
    if m:
        dt = datetime.fromisoformat(m.group(1))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp(), line[m.end():]
    m = _BSD.match(line)
    if m and year:
        dt = datetime(year, _MONTHS[m.group(1)], int(m.group(2)),
                      *map(int, m.group(3).split(":")), tzinfo=timezone.utc)
        return dt.timestamp(), line[m.end():]
    return None, line


def parse_line(line: str, year: Optional[int] = None, default_ts: Optional[float] = None) -> Optional[Event]:
    """Return an Event, or None for lines that are neither KDC requests nor AZK_POLICY lines.

    Patterns are anchored at the start of the syslog message (see _MSG_START), so attacker-chosen
    principal names later in the line cannot forge or hide events.
    """
    ts, rest = _split_timestamp(line, year)
    if ts is None:
        ts = default_ts
    if ts is None:
        return None
    ms = _MSG_START.match(rest)
    if not ms:
        return None
    line = rest[ms.end():]
    pm = _POLICY.match(line)
    if pm:
        ph, client, lvl, life, ren, deny, gen = pm.groups()
        return Event(ts, "POLICY", True, "POLICY", "", client, "", policy={
            "phase": ph, "level": int(lvl), "lifetime": int(life), "renew": int(ren),
            "deny": int(deny), "table_gen": int(gen)})
    m = _REQ.match(line)
    if not m:
        return None
    kind, _n, etypes_s, ip, status, body = m.groups()
    req_et = tuple(int(x) for x in _ETID.findall(etypes_s))
    ok = status == "ISSUE"
    rep_et: tuple = ()
    if kind == "AS_REQ":
        if ok:
            b = _AS_OK.match(body)
            if not b:
                return None
            rep_et = tuple(int(x) for x in _ETID.findall(b.group(2)))
            client, service = b.group(3), b.group(4)
        else:
            b = _AS_FAIL.match(body)
            if not b:
                return None
            client, service = b.group(1), b.group(2)
        return Event(ts, "AS", ok, status, ip, client, service, req_et, rep_et)
    b = _TGS.match(body)
    if not b:
        return None
    if b.group(2):
        rep_et = tuple(int(x) for x in _ETID.findall(b.group(2)))
    return Event(ts, "TGS", ok, status, ip, b.group(3), b.group(4), req_et, rep_et)


def parse_lines(lines, year: Optional[int] = None):
    for ln in lines:
        ev = parse_line(ln.rstrip("\n"), year)
        if ev is not None:
            yield ev
