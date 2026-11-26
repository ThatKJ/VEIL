#!/usr/bin/env python3
"""VEIL (Track 3: Secret Wards, Team The Aevos): python3 main.py --input <dir> --output <dir>"""
import argparse
import os
import sys
from pathlib import Path

from rakshak.pipeline import load_policy, run

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="VEIL clinical privacy firewall (Team The Aevos)")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    if not os.environ.get("RAKSHA_SECRET", "").strip():
        sys.stderr.write("error: RAKSHA_SECRET environment variable must be set and non-empty.\n")
        sys.exit(2)
    inp = Path(a.input)
    if not inp.is_dir():
        sys.stderr.write("error: --input must be an existing directory.\n")
        sys.exit(2)
    out = Path(a.output)
    (out / "sanitized").mkdir(parents=True, exist_ok=True)
    sys.exit(run(inp, out, load_policy(HERE / "config" / "policy.yaml")))
