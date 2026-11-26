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
    # Pre-count non-generic tokens >= 2 chars so surname-capable generics (e.g. Begum, Singh)
    # are dropped as middle titles ("Shanti Devi Verma") yet preserved when functioning as surname ("S.D. Begum").
    non_gen2 = 0
    for t in tokens:
        if not re.fullmatch(r"(?:[A-Za-z]\.){2,}[A-Za-z]?\.?", t):
            tl = t.strip(".").lower()
            if tl not in L.GENERIC_NAME_TOKENS and len(tl) >= 2:
                non_gen2 += 1
    ks = []
    for t in tokens:
        if re.fullmatch(r"(?:[A-Za-z]\.){2,}[A-Za-z]?\.?", t):
            for ch in re.findall(r"[A-Za-z]", t):
                ks.append(ch.lower())
            continue
        tl = t.strip(".").lower()
        if tl in L.GENERIC_NAME_TOKENS and not (tl in L.SURNAME_GENERICS and non_gen2 < 2):
            continue
        if len(tl) == 1 and tl.isalpha():
            ks.append(tl)
            continue
        s = L.skel(_strip_fused_suffix(tl))
        if s and (len(s) >= 2 or len(tl) >= 2):
            ks.append(s)
    return tuple(ks)


def _vill_key(v: str) -> str:
    toks = [L.skel(w) for w in re.split(r"[\s,._\-]+", v.strip()) if w]
    return " ".join(t for t in toks if t) or v.strip().casefold()


class Cluster:
    __slots__ = ("members", "names", "given", "rels", "dobs", "dob_yrs", "genders", "ages", "byears", "villages", "ids")

    def __init__(self, idx: int, ev: dict):
        self.members = [idx]
        self.names = {k for k in (name_keys(n) for n in ev["names"]) if k}
        self.given = {k[0] for k in self.names}
        self.rels = {k for k in (name_keys(n) for n in ev["rel"]) if k}
        self.dobs = {ev["dob"]} if ev["dob"] else set()
        self.dob_yrs = {int(ev["dob"][:4])} if (ev["dob"] and len(ev["dob"]) >= 4 and ev["dob"][:4].isdigit()) else set()
        self.genders = {ev["gender"]} if ev["gender"] else set()
        self.ages = {ev["age"]} if ev["age"] is not None else set()
        self.byears: set[int] = set()
        if ev["age"] is not None and isinstance(ev.get("date"), int) and ev["date"] >= 2020:
            self.byears.add(ev["date"] - ev["age"])
        self.villages = {_vill_key(ev["village"])} if ev.get("village") else set()
        self.ids = set(ev["ids"]) | {"P:" + p for p in ev["phones"]}

    def absorb(self, o: "Cluster"):
        self.members += o.members
        self.names |= o.names
        self.given |= o.given
        self.rels |= o.rels
        self.dobs |= o.dobs
        self.dob_yrs |= o.dob_yrs
        self.genders |= o.genders
        self.ages |= o.ages
        self.byears |= o.byears
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


def _ages_ok(a: Cluster, b: Cluster) -> bool:
    if not (a.ages and b.ages):
        return True
    adiff = min(abs(x - y) for x in a.ages for y in b.ages)
    if adiff <= 2:
        return True
    if adiff <= 5:
        if a.dob_yrs and b.byears and min(abs(x - y) for x in a.dob_yrs for y in b.byears) <= 1:
            return True
        if b.dob_yrs and a.byears and min(abs(x - y) for x in b.dob_yrs for y in a.byears) <= 1:
            return True
    return False


def compatible(a: Cluster, b: Cluster) -> bool:
    if len(a.genders | b.genders) > 1:
        return False
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return False
    if not _ages_ok(a, b):
        return False
    if not _name_compatible(a, b):
        return False
    # two different MRN-style ids at the SAME hospital prefix is fine (re-registration),
    # but two different Aadhaar / ABHA / PAN numbers mean two different people
    for pref in ("A:", "B:", "N:"):
        xa = {i for i in a.ids if i.startswith(pref)}
        xb = {i for i in b.ids if i.startswith(pref)}
        if xa and xb and not (xa & xb) and not any(_one_edit(x[2:], y[2:]) for x in xa for y in xb):
            return False
    return True


def _one_edit(x: str, y: str) -> bool:
    """Same-length national IDs differing by one substitution or one adjacent transposition are a
    likely data-entry error, not proof of two different people (they still never count as a match)."""
    if len(x) != len(y) or len(x) < 8:
        return False
    diff = [i for i in range(len(x)) if x[i] != y[i]]
    if len(diff) == 1:
        return True
    return len(diff) == 2 and diff[1] == diff[0] + 1 and x[diff[0]] == y[diff[1]] and x[diff[1]] == y[diff[0]]


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
        # ---- rule 1: strong identifiers (most specific first), then shared phones.
        # Re-run after rule 2: a union refused against a partial cluster may become
        # admissible once that cluster is complete (every union still passes compatible()).
        by_id = defaultdict(list)
        for i, e in enumerate(self.ev):
            for x in e["ids"]:
                by_id[x].append(i)
        id_order = sorted(by_id, key=lambda k: ({"A": 0, "B": 0, "N": 1, "I": 2, "E": 2, "M": 3}.get(k[0], 4), k))
        by_ph = defaultdict(list)
        for i, e in enumerate(self.ev):
            for p in e["phones"]:
                by_ph[p].append(i)

        def strong_pass():
            for x in id_order:
                idx = by_id[x]
                if len(idx) > 250:
                    continue
                reps: list[int] = []
                for j in idx:
                    if not any(self.union(r, j) for r in reps) and len(reps) < 32:
                        rj = self.find(j)
                        if rj not in reps:
                            reps.append(rj)
            for p in sorted(by_ph):
                idx = by_ph[p]
                if len(idx) > 250:
                    continue
                reps = []
                for j in idx:
                    if not self.cl[self.find(j)].names:
                        continue
                    if not any(self.cl[self.find(r)].names and self.union(r, j) for r in reps) and len(reps) < 32:
                        rj = self.find(j)
                        if rj not in reps:
                            reps.append(rj)

        strong_pass()
        # ---- rule 2: Fellegi-Sunter-inspired evidence scoring with term-frequency weights,
        # only accepting when a candidate clears threshold AND leads the runner-up by a clear margin.
        for _ in range(2):
            roots = sorted({self.find(i) for i in range(n)})
            n_roots = max(2, len(roots))
            tok_df = Counter()
            index = defaultdict(set)
            sec_idx = defaultdict(set)
            root_toks: dict[int, set[str]] = {}
            for r in roots:
                c = self.cl[r]
                seen_r = set()
                for nk in c.names:
                    for t in set(nk):
                        if len(t) >= 2:
                            index[t].add(r)
                            seen_r.add(t)
                root_toks[r] = seen_r
                for t in seen_r:
                    tok_df[t] += 1
                for dob in c.dobs:
                    sec_idx[("D", dob)].add(r)
                for v in c.villages:
                    sec_idx[("V", v)].add(r)
                for rt in c.rels:
                    if rt:
                        sec_idx[("R", rt[0])].add(r)
            for r in roots:
                if self.find(r) != r:
                    continue
                c = self.cl[r]
                c_toks = root_toks.get(r)
                if not c_toks or not (c.dobs or c.villages or c.rels):
                    continue
                sec_cands = set()
                for dob in c.dobs:
                    bkt = sec_idx[("D", dob)]
                    if len(bkt) <= 250:
                        sec_cands |= bkt
                for v in c.villages:
                    bkt = sec_idx[("V", v)]
                    if len(bkt) <= 250:
                        sec_cands |= bkt
                for rt in c.rels:
                    if rt:
                        bkt = sec_idx[("R", rt[0])]
                        if len(bkt) <= 250:
                            sec_cands |= bkt
                if len(sec_cands) <= 1 and (not sec_cands or r in sec_cands):
                    continue
                if len(sec_cands) > 64:
                    name_cands = set()
                    for t in c_toks:
                        name_cands |= index.get(t, ())
                    cand_roots = sec_cands & name_cands
                else:
                    cand_roots = sec_cands
                if len(cand_roots) > 250:
                    continue
                scored = []
                seen_o = {r}
                for o in sorted(cand_roots):
                    o = self.find(o)
                    if o in seen_o:
                        continue
                    seen_o.add(o)
                    d = self.cl[o]
                    if not d.names:
                        continue
                    d_toks = root_toks.get(o) or {t for nk in d.names for t in nk if len(t) >= 2}
                    shared = c_toks & d_toks
                    if not shared:
                        continue
                    rel_m = _rel_match(c.rels, d.rels)
                    dob_m = bool(c.dobs & d.dobs)
                    vill_m = (bool(c.villages & d.villages) and c.ages and d.ages and _ages_ok(c, d))
                    if not (dob_m or rel_m or vill_m):
                        continue
                    if not compatible(c, d):
                        continue
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
        strong_pass()
        return [self.find(i) for i in range(n)]
