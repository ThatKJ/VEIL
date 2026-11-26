#!/usr/bin/env python3
"""Secret Wards submission entry point: python main.py --input <dir> --output <dir>"""
import argparse
import sys
from pathlib import Path

from rakshak.pipeline import load_policy, run

HERE = Path(__file__).resolve().parent

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Rakshak privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    out = Path(a.output)
    (out / "sanitized").mkdir(parents=True, exist_ok=True)
    sys.exit(run(Path(a.input), out, load_policy(HERE / "config" / "policy.yaml")))
