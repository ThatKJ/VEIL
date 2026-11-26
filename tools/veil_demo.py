#!/usr/bin/env python3
"""VEIL 90-second demo (offline, synthetic data only, dev/demo tool — not part of the submission runtime).

    python3 tools/veil_demo.py --dataset <synthetic dataset dir with input/ truth/ attacker/> \
        --harness <path to harness/> --out <demo output dir>

Everything printed is computed now from the real engine output; nothing is hardcoded:
  1. one synthetic patient fragmented across hospitals, formats and scripts
  2. direct masking vs fixed QI policy vs VEIL adaptive policy, attacked by the local attacker re-implementation
  3. identity resolution: one pseudonym across the fragments, the homonym kept apart
  4. clinical values of that patient, input vs output
  5. an intentionally injected processing defect caught by the Privacy Passport, then repaired by re-running VEIL
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import veil_passport as V  # noqa: E402


def run_engine(inp: Path, out: Path, policy: dict | None = None, secret: str = "veil-demo-secret"):
    env = {**os.environ, "RAKSHA_SECRET": secret}
    if policy:
        env["RAKSHAK_EXPERIMENT"] = "1"
        env.update({f"RAKSHAK_P_{k.upper()}": v for k, v in policy.items()})
    if out.exists():
        shutil.rmtree(str(out) + ".old", ignore_errors=True)
        shutil.move(str(out), str(out) + ".old")
    subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                   check=True, capture_output=True, env=env)


def evaluate(harness: Path, out: Path, dataset: Path) -> dict:
    m = out.parent / (out.name + ".metrics.json")
    subprocess.run([sys.executable, str(harness / "evaluate.py"), "--output", str(out), "--dataset", str(dataset),
                    "--save", str(m)], check=True, capture_output=True)
    return json.loads(m.read_text())


def say(lines, s=""):
    print(s)
    lines.append(s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--harness", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    D, H, OUT = Path(a.dataset), Path(a.harness), Path(a.out)
    OUT.mkdir(parents=True, exist_ok=True)
    T = json.loads((D / "truth" / "truth.json").read_text(encoding="utf-8"))
    L: list[str] = []

    # ---- 1. pick the synthetic patient with the most fragments across scripts/files
    frag = defaultdict(list)
    for rel, f in T["files"].items():
        for loc, u in f["units"].items():
            if u.get("patient") and u.get("link") == "required":
                scripts = {e["script"] for e in u["entities"]}
                frag[u["patient"]].append((rel, loc, scripts))
    pid = max(frag, key=lambda p: (len({s for _, _, ss in frag[p] for s in ss}), len({r for r, _, _ in frag[p]})))
    files = sorted({r for r, _, _ in frag[pid]})
    scripts = sorted({s for _, _, ss in frag[pid] for s in ss})
    say(L, "# VEIL demo — measured on synthetic data")
    say(L, f"\n## 1. One synthetic patient, fragmented\nPatient {pid}: {len(frag[pid])} records in {len(files)} files, "
           f"scripts {', '.join(scripts)}; e.g. {', '.join(files[:4])}")

    # ---- 2. three policies, same input, same attacker
    say(L, "\n## 2. Conventional masking vs VEIL (local attacker re-implementation of docs/ATTACKS.md)")
    say(L, "| Policy | A4 profile re-identification (vs raw) | A5 targeted (vs raw) | Clinical probes kept | Temporal | Est. total (local) |")
    say(L, "|---|---|---|---|---|---|")
    results = {}
    for name, pol in (("direct masking only", {"qi_mode": "mask"}), ("fixed QI policy", {"qi_mode": "fixed"}),
                      ("VEIL adaptive (default)", None)):
        o = OUT / ("release_" + re.sub(r"\W+", "_", name))
        run_engine(D / "input", o, pol)
        m = evaluate(H, o, D)
        results[name] = (o, m)
        c = m["privacy"].get("components_relative_to_raw", {})
        say(L, f"| {name} | {c.get('A4_profile_reid', float('nan')):.2f} | {c.get('A5_targeted', float('nan')):.2f} | "
               f"{m['utility']['clinical_probes']:.3f} | {m['utility']['temporal']:.2f} | {m['estimate']['est_total']:.1f} |")

    # ---- 3. identity resolution
    o, m = results["VEIL adaptive (default)"]
    rep = json.loads((o / "report.json").read_text())
    import hashlib
    sha_out = {e["input_sha256"]: e.get("output") for e in rep["files"]}
    recs = defaultdict(dict)
    for line in (o / "records.jsonl").read_text().splitlines():
        r = json.loads(line)
        recs[r["file"]][r["loc"]] = r["patient"]
    psns = Counter()
    for rel, loc, _ in frag[pid]:
        out_file = sha_out.get(T["files"][rel]["sha256"])
        if out_file:
            psns[recs.get(out_file, {}).get(loc) or recs.get(out_file, {}).get("doc")] += 1
    main_psn, n_main = psns.most_common(1)[0]
    say(L, f"\n## 3. Identity resolution\n{n_main}/{sum(psns.values())} of {pid}'s records carry the same pseudonym "
           f"{main_psn}; other labels: {dict((k, v) for k, v in psns.items() if k != main_psn) or 'none'}.")
    pairs = T.get("traps", {}).get("homonym_pairs", [])
    if pairs:
        p1, p2 = pairs[0]

        def psn_of(p):
            c = Counter()
            for rel, f in T["files"].items():
                for loc, u in f["units"].items():
                    if u.get("patient") == p:
                        of = sha_out.get(f["sha256"])
                        c[recs.get(of, {}).get(loc)] += 1
            c.pop(None, None)
            return c.most_common(1)[0][0] if c else None
        a1, a2 = psn_of(p1), psn_of(p2)
        say(L, f"Homonym trap ({p1} vs {p2}, identical names): pseudonyms {a1} vs {a2} -> "
               f"{'kept apart' if a1 != a2 else 'MERGED'}; dataset false-merge pairs = {m['identity']['false_merge_pairs']}.")

    # ---- 4. clinical values for that patient
    keep = tot = 0
    for rel, loc, _ in frag[pid]:
        u = T["files"][rel]["units"][loc]
        of = sha_out.get(T["files"][rel]["sha256"])
        if not of:
            continue
        txt = V.norm((o / of).read_text(encoding="utf-8", errors="replace"))
        for p in u.get("preserve") or []:
            tot += 1
            keep += V.norm(p["text"]) in txt
    say(L, f"\n## 4. Clinical integrity\n{keep}/{tot} medical values of {pid} survive verbatim "
           f"(dataset probes kept {m['utility']['clinical_probes']:.3f}, temporal {m['utility']['temporal']:.2f}).")

    # ---- 5. defect injection -> Passport -> repair
    bad = OUT / "release_with_injected_defect"
    if bad.exists():
        shutil.rmtree(str(bad) + ".old", ignore_errors=True)
        shutil.move(str(bad), str(bad) + ".old")
    shutil.copytree(o, bad)
    target = next(p for p in sorted((bad / "sanitized").rglob("*.txt")) if re.search(r"\d+\s*mg", p.read_text(encoding="utf-8")))
    t = target.read_text(encoding="utf-8")
    target.write_text(re.sub(r"(\d+)\s*mg", lambda x: f"{int(x.group(1)) + 50} mg", t, count=1) + "\nCall 9876501234\n",
                      encoding="utf-8")
    R_bad = V.audit(D / "input", bad)
    say(L, f"\n## 5. Release assurance\nInjected defect (one raw phone, one altered dose) into {target.relative_to(bad)}.")
    say(L, "Privacy Passport flags: " + "; ".join(R_bad["residual_risks"]))
    R_ok = V.audit(D / "input", o)
    say(L, f"Repair = re-run VEIL from the immutable input: residual risks {len(R_ok['residual_risks'])}, "
           f"clinical expressions kept {R_ok['clinical']['protected_values_kept_pct']}%, "
           f"pseudonyms placed {R_ok['identity']['pseudonym_present_in_exported_file']}.")
    (OUT / "passport.html").write_text(V.render_html(R_ok, m), encoding="utf-8")
    (OUT / "passport_defect.html").write_text(V.render_html(R_bad, None), encoding="utf-8")
    say(L, "\nPassports: passport.html (clean release), passport_defect.html (injected defect).")
    say(L, "\n_All numbers: local re-implementation on synthetic data; not the official evaluator; no anonymity guarantee._")
    (OUT / "DEMO.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
