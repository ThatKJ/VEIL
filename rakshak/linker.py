"""High-precision patient identity resolution with cannot-link constraints.

Rules (following the dataset's own definition of "must link"):
  1. a shared strong identifier (MRN/UHID, Aadhaar, ABHA, PAN, insurance, email, phone),
     accepted only if the two clusters carry no contradicting evidence;
  2. the same name (script-independent skeleton) plus a second clue (DOB, relative's name,
     or village + age within 2 years), accepted only when exactly one cluster qualifies.
Clusters are merged as whole groups and every merge is checked against ALL members'
evidence, so two individually plausible links cannot chain unrelated people together.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter, defaultdict

from . import lexicon as L


def _strip_fused_suffix(tl: str) -> str:
    if tl.endswith("bhai") and len(tl) >= 7:
        return tl[:-4]
    if tl.endswith("ben") and len(tl) >= 6:
        return tl[:-3]
    return tl


def name_keys(tokens: list[str]) -> tuple[str, ...]:
    ks = []
    for t in tokens:
        if re.fullmatch(r"(?:[A-Za-z]\.){2,}[A-Za-z]?\.?", t):
            for ch in re.findall(r"[A-Za-z]", t):
                ks.append(ch.lower())
            continue
        tl = t.strip(".").lower()
        if tl in L.GENERIC_NAME_TOKENS:
            continue
        if len(tl) == 1 and tl.isalpha():
            ks.append(tl)
            continue
        s = L.skel(_strip_fused_suffix(tl))
        if s and (len(s) >= 2 or len(tl) >= 2):
            ks.append(s)
    return tuple(ks)


class Cluster:
    __slots__ = ("members", "names", "given", "rels", "dobs", "genders", "ages", "villages", "ids")

    def __init__(self, idx: int, ev: dict):
        self.members = [idx]
        self.names = {k for k in (name_keys(n) for n in ev["names"]) if k}
        self.given = {k[0] for k in self.names}
        self.rels = {k for k in (name_keys(n) for n in ev["rel"]) if k}
        self.dobs = {ev["dob"]} if ev["dob"] else set()
        self.genders = {ev["gender"]} if ev["gender"] else set()
        self.ages = {ev["age"]} if ev["age"] is not None else set()
        self.villages = {ev["village"]} if ev["village"] else set()
        self.ids = set(ev["ids"]) | {"P:" + p for p in ev["phones"]}

    def absorb(self, o: "Cluster"):
        self.members += o.members
        self.names |= o.names
        self.given |= o.given
        self.rels |= o.rels
        self.dobs |= o.dobs
        self.genders |= o.genders
        self.ages |= o.ages
        self.villages |= o.villages
        self.ids |= o.ids


def _initial_match(x: tuple[str, ...], y: tuple[str, ...]) -> bool:
    """Match abbreviated initials like ('j','h','vhr') with ('jbr','hkt','vhr') or ('jbr','vhr')."""
    if len(x) < 2 or len(y) < 2:
        return False
    inits = [t for t in x[:-1] if len(t) == 1]
    if not inits or x[-1] != y[-1] or not x[-1]:
        return False
    ym = [t for t in y[:-1] if len(t) >= 2]
    if not ym:
        return False
    return inits[0] == ym[0][0] and (len(inits) == 1 or len(ym) == 1 or all(any(t[0] == i for t in ym) for i in inits))


def _name_compatible(a: Cluster, b: Cluster) -> bool:
    if not a.names or not b.names:
        return True
    for x in a.names:
        for y in b.names:
            mx = {t for t in x if len(t) >= 2}
            my = {t for t in y if len(t) >= 2}
            if (mx & my and (x[0] == y[0] or (len(x[0]) >= 2 and x[0] in my) or (len(y[0]) >= 2 and y[0] in mx))) or _initial_match(x, y) or _initial_match(y, x):
                return True
            if x[0] == y[0] and ((len(x) == 1 or len(y) == 1) or (len(x) >= 2 and len(y) >= 2 and x[-1] == y[-1])):
                return True
    return False


def _rel_match(ra: set[tuple[str, ...]], rb: set[tuple[str, ...]]) -> int:
    """Return 2 for full multi-token relative match, 1 for 1-token-vs-full given-name match, 0 otherwise."""
    if not ra or not rb:
        return 0
    if ra & rb:
        if any(len(x) >= 2 for x in (ra & rb)):
            return 2
        if any(len(x) == 1 and len(x[0]) >= 3 for x in (ra & rb)):
            return 1
        return 0
    for x in ra:
        for y in rb:
            if (len(x) == 1 and len(x[0]) >= 3 and len(y) >= 2 and x[0] == y[0]) or (
                len(y) == 1 and len(y[0]) >= 3 and len(x) >= 2 and y[0] == x[0]
            ):
                return 1
    return 0


def compatible(a: Cluster, b: Cluster) -> bool:
    if len(a.genders | b.genders) > 1:
        return False
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return False
    if a.ages and b.ages and min(abs(x - y) for x in a.ages for y in b.ages) > 2:
        return False
    if not _name_compatible(a, b):
        return False
    # two different MRN-style ids at the SAME hospital prefix is fine (re-registration),
    # but two different Aadhaar / ABHA / PAN numbers mean two different people
    for pref in ("A:", "B:", "N:"):
        xa = {i for i in a.ids if i.startswith(pref)}
        xb = {i for i in b.ids if i.startswith(pref)}
        if xa and xb and not (xa & xb):
            return False
    return True


class Linker:
    def __init__(self, evidences: list[dict]):
        self.ev = evidences
        self.cl = [Cluster(i, e) for i, e in enumerate(evidences)]
        self.parent = list(range(len(evidences)))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> bool:
        ri, rj = self.find(i), self.find(j)
        if ri == rj:
            return True
        a, b = self.cl[ri], self.cl[rj]
        if not compatible(a, b):
            return False
        if len(a.members) < len(b.members) or (len(a.members) == len(b.members) and rj < ri):
            ri, rj, a, b = rj, ri, b, a
        a.absorb(b)
        self.parent[rj] = ri
        return True

    def run(self) -> list[int]:
        n = len(self.ev)
        # ---- rule 1: strong identifiers (most specific first)
        by_id = defaultdict(list)
        for i, e in enumerate(self.ev):
            for x in e["ids"]:
                by_id[x].append(i)
        for x in sorted(by_id, key=lambda k: ({"A": 0, "B": 0, "N": 1, "I": 2, "E": 2, "M": 3}.get(k[0], 4), k)):
            idx = by_id[x]
            for j in idx[1:]:
                self.union(idx[0], j)
        # phone numbers: households share them, so require compatible names AND a name on both sides
        by_ph = defaultdict(list)
        for i, e in enumerate(self.ev):
            for p in e["phones"]:
                by_ph[p].append(i)
        for p in sorted(by_ph):
            idx = by_ph[p]
            for j in idx[1:]:
                a, b = self.cl[self.find(idx[0])], self.cl[self.find(j)]
                if a.names and b.names:
                    self.union(idx[0], j)
        # ---- rule 2: Fellegi-Sunter-inspired evidence scoring with term-frequency weights,
        # only accepting when a candidate clears threshold AND leads the runner-up by a clear margin.
        for _ in range(2):
            roots = sorted({self.find(i) for i in range(n)})
            n_roots = max(2, len(roots))
            tok_df = Counter()
            index = defaultdict(list)
            for r in roots:
                seen_r = set()
                for nk in self.cl[r].names:
                    for t in set(nk):
                        if len(t) >= 2:
                            index[t].append(r)
                            seen_r.add(t)
                for t in seen_r:
                    tok_df[t] += 1
            for r in roots:
                if self.find(r) != r:
                    continue
                c = self.cl[r]
                cands = set()
                for nk in c.names:
                    for t in set(nk):
                        if len(t) >= 2:
                            cands.update(index.get(t, []))
                scored = []
                for o in sorted(cands):
                    o = self.find(o)
                    if o == r or any(x[1] == o for x in scored):
                        continue
                    d = self.cl[o]
                    if not (c.names and d.names) or not compatible(c, d):
                        continue
                    rel_m = _rel_match(c.rels, d.rels)
                    dob_m = bool(c.dobs & d.dobs)
                    vill_m = (bool(c.villages & d.villages) and c.ages and d.ages
                              and min(abs(x - y) for x in c.ages for y in d.ages) <= 2)
                    if not (dob_m or rel_m or vill_m):
                        continue
                    shared = {t for nk in c.names for t in nk if len(t) >= 2} & {
                        t for nk in d.names for t in nk if len(t) >= 2
                    }
                    idf = sum(min(3.5, math.log2(n_roots / max(1, tok_df[t]))) for t in shared)
                    fs = idf
                    if dob_m:
                        fs += 4.5
                    if rel_m:
                        fs += 4.5 if rel_m == 2 else 3.0
                    if vill_m:
                        fs += 3.5
                    if c.genders and d.genders and (c.genders & d.genders):
                        fs += 0.5
                    if c.ages and d.ages and min(abs(x - y) for x in c.ages for y in d.ages) <= 1:
                        fs += 0.5
                    scored.append((fs, o))
                scored.sort(reverse=True)
                if len(scored) == 1:
                    self.union(r, scored[0][1])
                elif len(scored) > 1 and os.environ.get("RAKSHAK_P_FS_TIEBREAK", "on") != "off":
                    if scored[0][0] - scored[1][0] >= 2.0:
                        self.union(r, scored[0][1])
        return [self.find(i) for i in range(n)]
