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

from collections import defaultdict

from . import lexicon as L


def name_keys(tokens: list[str]) -> tuple[str, ...]:
    ks = []
    for t in tokens:
        tl = t.strip(".").lower()
        if tl in L.GENERIC_NAME_TOKENS:
            continue
        s = L.skel(t)
        if len(s) >= 2:
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


def _name_compatible(a: Cluster, b: Cluster) -> bool:
    if not a.names or not b.names:
        return True
    for x in a.names:
        for y in b.names:
            if set(x) & set(y) and (x[0] == y[0] or x[0] in y or y[0] in x):
                return True
    return False


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
        # ---- rule 2: same name + second clue, only if unambiguous
        for _ in range(2):
            roots = sorted({self.find(i) for i in range(n)})
            index = defaultdict(list)
            for r in roots:
                for nk in self.cl[r].names:
                    for t in set(nk):
                        index[t].append(r)
            for r in roots:
                if self.find(r) != r:
                    continue
                c = self.cl[r]
                cands = set()
                for nk in c.names:
                    for t in set(nk):
                        cands.update(index.get(t, []))
                good = []
                for o in sorted(cands):
                    o = self.find(o)
                    if o == r or o in good:
                        continue
                    d = self.cl[o]
                    clue = bool(c.dobs & d.dobs) or bool(c.rels & d.rels) or (
                        bool(c.villages & d.villages) and c.ages and d.ages
                        and min(abs(x - y) for x in c.ages for y in d.ages) <= 2)
                    if clue and compatible(c, d):
                        good.append(o)
                if len(good) == 1:
                    self.union(r, good[0])
        return [self.find(i) for i in range(n)]
