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


_ES: frozenset = frozenset()
_ET: tuple = ()
_GENDER_FS = {"M": frozenset(("M",)), "F": frozenset(("F",))}
_AGE_FS = {i: frozenset((i,)) for i in range(125)}
_YEAR_FS = {y: frozenset((y,)) for y in range(1880, 2045)}
_RX_INIT_RUN = re.compile(r"(?:[A-Za-z]\.){2,}[A-Za-z]?\.?")
_RX_INIT_CHR = re.compile(r"[A-Za-z]")
_RX_NON_INDIC = re.compile(r"[^0-9a-z\u0B00-\u0DFF]")
_RX_VILL_SPLIT = re.compile(r"[\s,._\-]+")


def _uniq_tup(items) -> tuple:
    seen: list = []
    for x in items:
        if x and x not in seen:
            seen.append(x)
    return tuple(seen)


def _merge_coll(a, b):
    if not b:
        return a
    if not a:
        return b
    if isinstance(a, set):
        return a | (b if isinstance(b, (set, frozenset)) else set(b))
    if isinstance(b, set):
        return set(a) | b
    if len(a) + len(b) <= 6:
        out = list(a)
        for x in b:
            if x not in out:
                out.append(x)
        return tuple(out)
    return set(a) | set(b)


def _has_overlap(a, b) -> bool:
    if not a or not b:
        return False
    if len(a) == 1 and len(b) == 1 and not isinstance(a, (set, frozenset)) and not isinstance(b, (set, frozenset)):
        return a[0] == b[0]
    sa = a if isinstance(a, (set, frozenset)) else set(a)
    return any(x in sa for x in b)


def name_keys(tokens: list[str]) -> tuple[str, ...]:
    # Split any raw HL7 caret/underscore sub-tokens cleanly before phonetic skeleton folding.
    flat: list[str] = []
    for raw_t in tokens:
        if "^" in raw_t or "_" in raw_t:
            flat.extend(p for p in re.split(r"[\^_]+", raw_t) if p)
        else:
            flat.append(raw_t)
    tokens = flat
    # Pre-count non-generic tokens >= 2 chars so surname-capable generics (e.g. Begum, Singh)
    # are dropped as middle titles ("Shanti Devi Verma") yet preserved when functioning as surname ("S.D. Begum").
    non_gen2 = 0
    for t in tokens:
        if not _RX_INIT_RUN.fullmatch(t):
            tl = t.strip(".").lower()
            if tl not in L.GENERIC_NAME_TOKENS and len(tl) >= 2:
                non_gen2 += 1
    ks = []
    for t in tokens:
        if _RX_INIT_RUN.fullmatch(t):
            for ch in _RX_INIT_CHR.findall(t):
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
        elif not s:
            u = _RX_NON_INDIC.sub("", tl)
            if len(u) >= 2 and not u.isdigit():
                ks.append("~" + u)
    return tuple(ks)


def _vill_key(v: str) -> str:
    toks = [L.skel(w) for w in _RX_VILL_SPLIT.split(v.strip()) if w]
    return " ".join(t for t in toks if t) or v.strip().casefold()


class Cluster:
    __slots__ = ("size", "names", "rels", "dobs", "dob_yrs", "genders", "ages", "byears", "villages", "ids")

    def __init__(self, idx: int, ev):
        self.size = 1
        if hasattr(ev, "_r"):
            ev = ev._r
        if isinstance(ev, dict):
            ev_names = ev["names"]
            ev_rel = ev["rel"]
            dob = ev["dob"]
            g = ev["gender"]
            age = ev["age"]
            dt_yr = ev.get("date")
            vill = ev.get("village")
            ev_ids = ev["ids"]
            ev_phones = ev["phones"]
        else:
            ev_names = ev.names
            ev_rel = ev.rel
            dob = ev.dob
            g = ev.gender
            age = ev.age
            dt_yr = ev.date
            vill = ev.village
            ev_ids = ev.ids
            ev_phones = ev.phones
        if ev_names:
            self.names = _uniq_tup(name_keys(n) for n in ev_names)
        else:
            self.names = _ET
        self.rels = _uniq_tup(name_keys(n) for n in ev_rel) if ev_rel else _ET
        if dob:
            self.dobs = (dob,)
            if len(dob) >= 4 and dob[:4].isdigit():
                yr = int(dob[:4])
                self.dob_yrs = _YEAR_FS.get(yr) or frozenset((yr,))
            else:
                self.dob_yrs = _ES
        else:
            self.dobs = _ET
            self.dob_yrs = _ES
        self.genders = (_GENDER_FS.get(g) or frozenset((g,))) if g else _ES
        if age is not None:
            self.ages = _AGE_FS.get(age) or frozenset((age,))
            if isinstance(dt_yr, int) and dt_yr >= 2020:
                by = dt_yr - age
                self.byears = _YEAR_FS.get(by) or frozenset((by,))
            else:
                self.byears = _ES
        else:
            self.ages = _ES
            self.byears = _ES
        self.villages = (_vill_key(vill),) if vill else _ET
        if ev_ids or ev_phones:
            s: list[str] = list(ev_ids)
            for p in ev_phones:
                ps = "P:" + p
                if ps not in s:
                    s.append(ps)
            self.ids = tuple(s) if len(s) <= 6 else set(s)
        else:
            self.ids = _ET

    def absorb(self, o: "Cluster"):
        self.size += o.size
        self.names = _merge_coll(self.names, o.names)
        self.rels = _merge_coll(self.rels, o.rels)
        self.dobs = _merge_coll(self.dobs, o.dobs)
        if o.dob_yrs:
            self.dob_yrs = (set(self.dob_yrs) if self.dob_yrs is _ES or isinstance(self.dob_yrs, frozenset) else self.dob_yrs) | o.dob_yrs
        if o.genders and o.genders != self.genders:
            self.genders = (set(self.genders) if self.genders is _ES or isinstance(self.genders, frozenset) else self.genders) | o.genders
        if o.ages and o.ages != self.ages:
            self.ages = (set(self.ages) if self.ages is _ES or isinstance(self.ages, frozenset) else self.ages) | o.ages
        if o.byears and o.byears != self.byears:
            self.byears = (set(self.byears) if self.byears is _ES or isinstance(self.byears, frozenset) else self.byears) | o.byears
        self.villages = _merge_coll(self.villages, o.villages)
        self.ids = _merge_coll(self.ids, o.ids)


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


def _near(u: str, v: str) -> bool:
    if u.startswith(v) or v.startswith(u):
        return min(len(u), len(v)) >= 2
    if abs(len(u) - len(v)) > 1:
        return False
    if len(u) == len(v):
        return sum(p != q for p, q in zip(u, v)) <= 1
    s, t = (u, v) if len(u) < len(v) else (v, u)
    return any(t[:i] + t[i + 1:] == s for i in range(len(t)))


def _given_conflict(x: tuple[str, ...], y: tuple[str, ...]) -> bool:
    """Two full names sharing a family/house name but with outright different remaining given names
    ('Kizhakkethil Dheerubi' vs 'Kizhakkethil Bedham'): relatives, not one person.
    Never conflict across untransliterated non-Latin ('~...') tokens."""
    if any(t.startswith("~") for t in x) != any(t.startswith("~") for t in y):
        return False
    ux = [t for t in x if len(t) >= 2 and not t.startswith("~") and t not in y]
    uy = [t for t in y if len(t) >= 2 and not t.startswith("~") and t not in x]
    if ux and uy and not any(_near(u, v) for u in ux for v in uy):
        return True
    # initials-first names ('K. P. Dapee'): the first initial abbreviates the family/house name,
    # so it must match one of the other name's remaining full tokens
    for a, ub in ((x, uy), (y, ux)):
        ia = [t for t in a[:-1] if len(t) == 1]
        if len(ia) >= 2 and ub and not any(u[0] == ia[0] for u in ub):
            return True
    return False


def _name_compatible(a: Cluster, b: Cluster) -> bool:
    if not a.names or not b.names:
        return True
    ma = [x for x in a.names if sum(len(t) >= 2 for t in x) >= 2]
    mb = [y for y in b.names if sum(len(t) >= 2 for t in y) >= 2]
    if ma and mb and os.environ.get("RAKSHAK_P_GIVEN_VETO", "on") != "off":
        if all(_given_conflict(x, y) for x in ma for y in mb):
            return False
    for x in a.names:
        for y in b.names:
            mx = {t for t in x if len(t) >= 2}
            my = {t for t in y if len(t) >= 2}
            if _given_conflict(x, y) and os.environ.get("RAKSHAK_P_GIVEN_VETO", "on") != "off":
                continue
            if (mx & my and (x[0] == y[0] or (len(x[0]) >= 2 and x[0] in my) or (len(y[0]) >= 2 and y[0] in mx))) or _initial_match(x, y) or _initial_match(y, x):
                return True
            if x[0] == y[0] and ((len(x) == 1 or len(y) == 1) or (len(x) >= 2 and len(y) >= 2 and x[-1] == y[-1])):
                return True
    return False


def _rel_match(ra, rb) -> int:
    """Return 2 for full multi-token relative match, 1 for 1-token-vs-full given-name match, 0 otherwise."""
    if not ra or not rb:
        return 0
    sa = ra if isinstance(ra, (set, frozenset)) else set(ra)
    common = [x for x in rb if x in sa]
    if common:
        if any(len(x) >= 2 for x in common):
            return 2
        if any(len(x) == 1 and len(x[0]) >= 3 for x in common):
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
    if a.ages and b.ages:
        lo_a, hi_a = min(a.ages), max(a.ages)
        lo_b, hi_b = min(b.ages), max(b.ages)
        if max(hi_a, hi_b) - min(lo_a, lo_b) > 7:
            if not (a.dob_yrs and b.byears and min(abs(x - y) for x in a.dob_yrs for y in b.byears) <= 1) and not (
                b.dob_yrs and a.byears and min(abs(x - y) for x in b.dob_yrs for y in a.byears) <= 1
            ):
                return False
        adiff = min(abs(x - y) for x in a.ages for y in b.ages)
        if adiff <= 2:
            return True
        if adiff <= 5:
            if a.dob_yrs and b.byears and min(abs(x - y) for x in a.dob_yrs for y in b.byears) <= 1:
                return True
            if b.dob_yrs and a.byears and min(abs(x - y) for x in b.dob_yrs for y in a.byears) <= 1:
                return True
        return False
    if a.dob_yrs and b.byears and min(abs(x - y) for x in a.dob_yrs for y in b.byears) > 8:
        return False
    if b.dob_yrs and a.byears and min(abs(x - y) for x in b.dob_yrs for y in a.byears) > 8:
        return False
    return True


def compatible(a: Cluster, b: Cluster) -> bool:
    if a.genders and b.genders and a.genders != b.genders and len(a.genders | b.genders) > 1:
        return False
    if a.dobs and b.dobs and not _has_overlap(a.dobs, b.dobs):
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
    def __init__(self, evidences: list[dict], release: bool = False):
        self.ev = evidences
        self.cl = [Cluster(i, e) for i, e in enumerate(evidences)]
        self.parent = list(range(len(evidences)))
        self._release = release

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
        if a.size < b.size or (a.size == b.size and rj < ri):
            ri, rj, a, b = rj, ri, b, a
        a.absorb(b)
        self.parent[rj] = ri
        self.cl[rj] = None
        return True

    def run(self) -> list[int]:
        n = len(self.ev)
        # ---- rule 1: strong identifiers (most specific first), then shared phones.
        # Scalar-first storage keeps singleton IDs as int (avoiding millions of 1-elem lists).
        by_id: dict[str, int | list[int]] = {}
        by_ph: dict[str, int | list[int]] = {}
        for i, e in enumerate(self.ev):
            if isinstance(e, dict):
                e_ids, e_phones = e["ids"], e["phones"]
            else:
                e_ids, e_phones = e.ids, e.phones
            for x in e_ids:
                cur = by_id.get(x)
                if cur is None:
                    by_id[x] = i
                elif isinstance(cur, int):
                    by_id[x] = [cur, i]
                else:
                    cur.append(i)
            for p in e_phones:
                cur = by_ph.get(p)
                if cur is None:
                    by_ph[p] = i
                elif isinstance(cur, int):
                    by_ph[p] = [cur, i]
                else:
                    cur.append(i)
            if self._release:
                if isinstance(e, dict):
                    e["names"] = ()
                    e["rel"] = ()
                    e["village"] = None
                    e["date"] = None
                else:
                    e.names = _ET
                    e.rel = _ET
                    e.village = None
                    e.date = None
        self.ev = []

        id_order = sorted(
            (k for k, v in by_id.items() if isinstance(v, list)),
            key=lambda k: ({"A": 0, "B": 0, "N": 1, "I": 2, "E": 2, "M": 3}.get(k[0], 4), k),
        )
        by_id_multi = {k: by_id[k] for k in id_order}
        del by_id
        ph_order = sorted(k for k, v in by_ph.items() if isinstance(v, list))
        by_ph_multi = {k: by_ph[k] for k in ph_order}
        del by_ph

        def strong_pass():
            for x in id_order:
                idx = by_id_multi[x]
                if len(idx) > 250:
                    continue
                need_names = x.startswith("E:")
                reps: list[int] = []
                for j in idx:
                    if need_names and not self.cl[self.find(j)].names:
                        continue
                    if not any((not need_names or self.cl[self.find(r)].names) and self.union(r, j) for r in reps) and len(reps) < 32:
                        rj = self.find(j)
                        if rj not in reps:
                            reps.append(rj)
            for p in ph_order:
                idx = by_ph_multi[p]
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
        if any(c is not None and (c.dobs or c.villages or c.rels) for c in self.cl):
            for _ in range(2):
                roots = sorted({self.find(i) for i in range(n)})
                n_roots = max(2, len(roots))
                tok_df: Counter = Counter()
                sec_idx: dict[tuple[str, str], int | set[int]] = {}
                root_toks: dict[int, set[str]] = {}
                sec_roots = []
                for r in roots:
                    c = self.cl[r]
                    if not c.names:
                        continue
                    seen_r = {t for nk in c.names for t in nk if len(t) >= 2}
                    if not seen_r:
                        continue
                    for t in seen_r:
                        tok_df[t] += 1
                    if not (c.dobs or c.villages or c.rels):
                        continue
                    root_toks[r] = seen_r
                    sec_roots.append(r)
                    for dob in c.dobs:
                        key = ("D", dob)
                        b = sec_idx.get(key)
                        if b is None:
                            sec_idx[key] = r
                        elif isinstance(b, int):
                            if b != r:
                                sec_idx[key] = {b, r}
                        else:
                            b.add(r)
                    for v in c.villages:
                        key = ("V", v)
                        b = sec_idx.get(key)
                        if b is None:
                            sec_idx[key] = r
                        elif isinstance(b, int):
                            if b != r:
                                sec_idx[key] = {b, r}
                        else:
                            b.add(r)
                    for rt in c.rels:
                        if rt:
                            key = ("R", rt[0])
                            b = sec_idx.get(key)
                            if b is None:
                                sec_idx[key] = r
                            elif isinstance(b, int):
                                if b != r:
                                    sec_idx[key] = {b, r}
                            else:
                                b.add(r)

                if not sec_roots:
                    break
                tok_index: dict[str, set[int]] | None = None
                for r in sec_roots:
                    if self.find(r) != r:
                        continue
                    c = self.cl[r]
                    c_toks = root_toks.get(r)
                    if not c_toks:
                        continue
                    sec_cands = set()
                    for dob in c.dobs:
                        bkt = sec_idx.get(("D", dob))
                        if isinstance(bkt, set) and len(bkt) <= 250:
                            sec_cands |= bkt
                    for v in c.villages:
                        bkt = sec_idx.get(("V", v))
                        if isinstance(bkt, set) and len(bkt) <= 250:
                            sec_cands |= bkt
                    for rt in c.rels:
                        if rt:
                            bkt = sec_idx.get(("R", rt[0]))
                            if isinstance(bkt, set) and len(bkt) <= 250:
                                sec_cands |= bkt
                    if len(sec_cands) <= 1:
                        continue
                    if len(sec_cands) > 64:
                        if tok_index is None:
                            tok_index = defaultdict(set)
                            for rr, rtoks in root_toks.items():
                                for t in rtoks:
                                    tok_index[t].add(rr)
                        name_cands = set()
                        for t in c_toks:
                            name_cands |= tok_index.get(t, ())
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
                        dob_m = _has_overlap(c.dobs, d.dobs)
                        vill_m = (_has_overlap(c.villages, d.villages) and c.ages and d.ages and _ages_ok(c, d))
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
