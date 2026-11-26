"""Quasi-identifier policy: per-patient date shifts and truthful age bands.

v1 = fixed policy (5-year bands everywhere). The adaptive, patient-level risk engine
plugs in through `plan()`: it may widen bands for patients whose pooled profile is rare.
"""
from __future__ import annotations

from .engine import shift_days


def days_for(key: str | None, max_days: int) -> int:
    return shift_days(key, max_days) if key else 0


def band_of(age: int, width: int) -> str:
    lo = (age // width) * width
    return f"{lo}-{lo + width - 1}"


class Plan:
    def __init__(self, default_width: int, widths: dict):
        self.default, self.widths = default_width, widths

    def band_fn(self, key):
        w = self.widths.get(key, self.default)
        return lambda age: band_of(age, w)


def plan(groups, policy) -> Plan:
    return Plan(int(policy.get("age_band_years", 5)), {})
