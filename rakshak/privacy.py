"""Quasi-identifier policy: per-patient date shifts, truthful age bands, adaptive generalisation.

Three policies (config/policy.yaml `qi_mode`):
  mask      direct identifiers only: exact ages, exact DOB shift, tehsil and PIN prefix kept
  fixed     everyone gets the same transforms: 5-year bands, DOB shifted, tehsil dropped, PIN prefix
  adaptive  (default) patient-level risk control: every patient's quasi-identifiers are POOLED
            across all of their records (all files, scripts, hospitals). Patients whose pooled
            profile falls in a small equivalence class of the release, or who carry a rare
            condition, are generalised further (no birth year, wider band, no PIN prefix).
            Everyone else keeps the most useful truthful values.
The release-level class size is a proxy for the attacker's registry class (the registry is a
superset of patients, so k_release is a conservative lower bound).
"""
from __future__ import annotations

from collections import Counter

from .engine import shift_days


def days_for(key: str | None, max_days: int) -> int:
    return shift_days(key, max_days) if key else 0


def band_of(age: int, width: int) -> str:
    if width <= 1:
        return str(age)
    if age >= 85 and width >= 10:
        return "85+"
    lo = (age // width) * width
    return f"{lo}-{lo + width - 1}"


class Rule:
    __slots__ = ("band", "dob", "pin", "tehsil", "reason")

    def __init__(self, band=5, dob="shift", pin="drop", tehsil="drop", reason="default"):
        self.band, self.dob, self.pin, self.tehsil, self.reason = band, dob, pin, tehsil, reason


def consistent_band(ages: list[int], width: int) -> tuple[int, int] | None:
    """One truthful band per patient covering every observed age (no intersection leak across records)."""
    if not ages or width <= 1:
        return None
    lo_a, hi_a = min(ages), max(ages)
    w = width
    while w <= 40:
        lo = (lo_a // w) * w
        if hi_a <= lo + w - 1:
            return lo, lo + w - 1
        w *= 2
    return (lo_a // 10) * 10, ((hi_a // 10) * 10) + 9


class Plan:
    def __init__(self, default: Rule, rules: dict, report: dict, bands: dict | None = None):
        self.default, self.rules, self.report = default, rules, report
        self.bands = bands or {}

    def rule(self, key) -> Rule:
        return self.rules.get(key, self.default)

    def band_fn(self, key):
        w = self.rule(key).band
        fixed = self.bands.get((key, w))

        def f(age):
            if fixed and fixed[0] <= age <= fixed[1]:
                if fixed[0] >= 85:
                    return "85+"
                return f"{fixed[0]}-{fixed[1]}"
            return band_of(age, w)
        return f


def _profile(members) -> dict:
    g = Counter(m.ev["gender"] for m in members if m.ev["gender"])
    ages = [m.ev["age"] for m in members if m.ev["age"] is not None]
    dobs = [m.ev["dob"] for m in members if m.ev["dob"]]
    dist = Counter(str(m.ev.get("district")).strip().lower() for m in members if m.ev.get("district"))
    conds = set()
    for m in members:
        conds |= m.ev.get("conds", set())
    birth = int(dobs[0][:4]) if dobs else None
    return {"g": g.most_common(1)[0][0] if g else None, "age": max(ages) if ages else None, "birth": birth,
            "dist": dist.most_common(1)[0][0] if dist else None, "conds": conds}


def _all_bands(groups, widths):
    out = {}
    for members in groups.values():
        key = next((m.key for m in members if m.key), None)
        ages = [m.ev["age"] for m in members if m.ev["age"] is not None]
        if key and ages:
            for w in widths:
                b = consistent_band(ages, w)
                if b:
                    out[(key, w)] = b
    return out


def plan(groups, policy) -> Plan:
    p = _plan(groups, policy)
    if str(policy.get("consistent_bands", "on")) == "on":
        p.bands = _all_bands(groups, {5, 10, int(policy.get("age_band_years", 5))})
    return p


def _plan(groups, policy) -> Plan:
    mode = str(policy.get("qi_mode", "adaptive"))
    base_band = int(policy.get("age_band_years", 5))
    if mode == "mask":
        return Plan(Rule(band=1, dob="shift", pin="keep6", tehsil="keep", reason="mask"), {}, {"mode": mode})
    default = Rule(band=base_band, dob="shift", pin=str(policy.get("pin_mode", "drop")), tehsil="drop", reason="fixed")
    if mode == "fixed":
        return Plan(default, {}, {"mode": mode})

    esc_dob = "year_drop" if str(policy.get("escalate_dob", "drop")) == "drop" else "shift"
    k_min = int(policy.get("min_group_size", 5))
    rare_max = int(policy.get("rare_condition_max_patients", 3))
    profiles = {}
    for members in groups.values():
        key = next((m.key for m in members if m.key), None)
        if key:
            profiles[key] = _profile(members)

    cond_count = Counter(c for p in profiles.values() for c in p["conds"])

    def cell(p, band, with_birth):
        a = p["age"] // band if p["age"] is not None else None
        return (p["dist"], p["g"], a, p["birth"] if with_birth else None)

    rules, why = {}, Counter()
    cells5 = Counter(cell(p, base_band, True) for p in profiles.values())
    cells5n = Counter(cell(p, base_band, False) for p in profiles.values())
    cells10 = Counter(cell(p, 10, False) for p in profiles.values())
    for key, p in profiles.items():
        rare = any(cond_count[c] <= rare_max for c in p["conds"])
        old = p["age"] is not None and p["age"] >= 80
        if rare or old:
            rules[key] = Rule(band=10, dob=esc_dob, pin="drop", tehsil="drop", reason="rare" if rare else "old")
        elif cells5[cell(p, base_band, True)] >= k_min:
            continue                                  # already hidden in a crowd: keep the useful values
        elif cells5n[cell(p, base_band, False)] >= k_min:
            rules[key] = Rule(band=base_band, dob=esc_dob, pin="drop", tehsil="drop", reason="k_birth")
        elif cells10[cell(p, 10, False)] >= k_min:
            rules[key] = Rule(band=10, dob=esc_dob, pin="drop", tehsil="drop", reason="k_band")
        else:
            rules[key] = Rule(band=10, dob=esc_dob, pin="drop", tehsil="drop", reason="k_all")
        why[rules[key].reason] += 1
    return Plan(default, rules, {"mode": mode, "patients": len(profiles), "escalated": dict(why)})
