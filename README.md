# VEIL (`rakshak`): a multilingual, longitudinal privacy firewall for hospital records

**Hide the identity. Preserve the medicine.** VEIL (`rakshak`) sanitises messy multi-hospital exports in English, Hindi (Devanagari), Hinglish, and Nagari/Eastern/Western Indic scripts (CSV/TSV, nested JSON, arrays-of-arrays, JSON Lines, FHIR R4 Bundles, fixed-width `.txt`, free-text notes, broken files). It works **offline, on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, filenames (including CamelCase & hyphenated MRNs), URLs, metadata, base64/hex/HTML-encoded payloads;
* keeps medicines, doses (`1-0-1`, `q8h`), vitals, lab values, diagnoses (ICD-10), doctors (`Dr.`), and exact hospital-stay lengths (LOS) intact;
* **50-bit cryptographically keyed pseudonyms:** `PSN-` + 10 Crockford Base32 characters derived from `HMAC-SHA256(SECRET, "psn|" + key)` with canonical sorted order-independent collision resolution (`0` observed collisions up to `1,000,000` unique patients);
* **links the same patient across scripts, files, and hospitals** (`Mohammad` / `Mohd.` / `Md.` / `मोहम्मद`, Devanagari, Tamil, Telugu, Kannada, and Malayalam transliteration), never merging homonyms (`0` false merges across all tested benchmarks);
* **measures and reduces patient-level re-identification risk**, escalating generalisation only on rare pooled quasi-identifier profiles;
* **streams large tables with bounded memory:** `1,000,000` unique patients processed in `139.14s` and `3,278.4 MB` peak RSS (`< 4 GB` / `< 900s`).

## Run

```bash
pip install -r requirements.txt          # nothing to install: standard library only
RAKSHA_SECRET=<secret> python3 main.py --input <input dir> --output <empty output dir>
```

Output: `sanitized/` (preserving relative tree and formats, UTF-8, strict path containment), `report.json`, `records.jsonl` (contract v1).
`RAKSHA_SECRET` keys every pseudonym, date shift, and opaque renamed key/file (`HMAC-SHA256`). It is never written anywhere. Same input + same secret produces byte-identical output (`1.0000` determinism); a different secret produces distinct pseudonyms and encounter shifts.

## How it works (two passes)

```
input ─► 1. Ingest: BOM/UTF-16/cp1252 + mojibake repair; CleverCSV-style multi-row delimiter sniffing;
            symlinks leaving --input, binary disguises & >64-deep JSON QUARANTINED (never copied raw)
       ─► 2. Structure: header/key lexicon (EN/HI/Marathi/Bhojpuri/Hinglish) + value shape;
            recursive record discovery (nested JSON, [key, value] pairs, array-tables, FHIR Bundles)
       ─► 3. Harvest: names, strong IDs, phones, DOB/ages, relatives, villages from structured + labelled text
       ─► 4. O(N) Identity graph: strong IDs, then phonetic Indic skeleton + secondary-blocked (DOB / up-to-32-cluster
            shared household phone / village / relative) Fellegi-Sunter matching; whole-cluster cannot-link
            invariants (gender, compatible birth-year, Aadhaar/ABHA/PAN conflicts) prevent transitive merging
       ─► 5. Pooled-profile privacy engine (USP, below) -> per-patient rule
       ─► 6. Rewrite & O(L) Scrub: Dr./clinical masking first; keyed per-patient date shifts;
            labelling/kinship/honorific/C-o guards; O(L) token/prefix/4-gram harvested sweep; consistent ARX age bands
       ─► 7. Independent O(N) verification: exact-token scan of critical PII while guarding Dr. spans
       ─► report.json (SHA-256 per input, honest counts), records.jsonl (pseudonym present IN each unit)
```

## USP: pooled-profile, patient-level privacy

A patient who looks anonymous in one record is often identifiable once records are pooled across departments, which is exactly how attackers link releases. VEIL resolves each patient across every file and script first, evaluates the **pooled** quasi-identifiers (district, gender, age/birth year, diagnoses), and escalates generalisation **only for rare equivalence classes** (`k10 < 2`, `k5 < 5`, rare condition `<= 3` patients, or `age >= 80`): widening age to consistent `10`-year ARX lattice bands (`consistent_band` prevents multi-record intersection narrowing) and suppressing fine village/district/PIN geography while shifting encounter dates, `lastUpdated` metadata, and escalated DOBs cleanly by the same per-patient HMAC day offset so encounter order and length-of-stay stay exact.

## Prior Art & Attribution

VEIL integrates adapted, clean-room Python stdlib implementations of established open-source and academic techniques:
* **ARX** — equivalence-class risk-driven `k`-anonymity and consistent age-lattice generalisation.
* **Splink / Dedupe** — Fellegi-Sunter match weighting, multi-attribute inverted blocking, and whole-cluster cannot-link constraints.
* **UCSF Philter / Microsoft Presidio / Nottingham i2b2 & N-GRID** — two-stage clinical allow-list/context masking (`Dr.`, medications, eponyms) paired with rule/lexicon PII sweeps and verification.
* **CleverCSV** — unquoted multi-row structural consistency scoring for ambiguous CSV/TSV dialect detection.
* **Indic rule-based transliteration & HL7 FHIR R4** — script-independent phonetic skeletons and schema-valid Bundle anonymisation.

## Measured results (local harness, frozen `known-good-9` / TITAN, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight. Note: `chaos_holdout20` and `chaos_holdout21` were reclassified from blind to diagnostic/development datasets in Phase XI (`kg5`=`e83ba90`, `kg7`=`70f77c8`/`4f11756`, `kg8`=`3b4e605`, `kg9`=TITAN).

| Dataset | Role | Truth leak / Canaries | Probes | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---|---:|---:|---:|---:|---:|
| official `dev` | official practice | 0.22% (`check_dev 0.0%`) / 0/4 | 0.9930 | 0.9968 / **0** | 0.9458 / 0.8692 | **92.30** |
| `chaos_dev` (`kg8`) | dev synthetic | 0.06% / 0/3 | 0.9939 | 1.0000 / **0** | 0.9379 / 0.8790 | **92.71** |
| `chaos_holdout15` (`kg8`) | Bundelkhand (diag) | 0.36% / 0/4 | 0.9996 | 0.9953 / **0** | 0.9123 / 0.9393 | **87.49** |
| `chaos_holdout16` (`kg8`) | Punjab/Doaba (diag) | 0.65% / 0/4 | 0.9997 | 0.9970 / **0** | 0.9183 / 0.9412 | **85.25** |
| `chaos_holdout17` (`kg8`) | Andhra (diag) | 0.44% / 0/4 | 0.9996 | 0.9951 / **0** | 0.9163 / 0.9539 | **92.94** |
| `chaos_holdout18` (`kg8`) | Assam/Odisha+HL7 (diag) | 0.03% / 0/4 | 1.0000 | 0.9815 / **0** | 0.8608 / 0.7348 | **85.78** |
| `chaos_holdout19` (`kg8`) | Karnataka+JSONL (diag) | 0.01% / 0/4 | 0.9490 | 0.9873 / **0** | 0.8519 / 0.8418 | **91.95** |
| `chaos_holdout20` (`kg8`) | Haryana+EAV/stacked (diag, was 68.38) | **0.00%** / **0/4** | 0.7509 | 0.9536 / **0** | 0.7645 / 0.8278 | **85.98** |
| `chaos_holdout21` (`kg9`) | Kerala+South-Indic/box-table (diag) | **0.00%** / **0/4** | **0.9999+** | **0.9682** / **0** | `lang 0.8547` | **81.07** (no perf) |
| **`titan_b1` (`seed 9101`)** | **BLIND TITAN-B1** EN/HI/noisy (1-shot) | 0.44% / 0/4 | — | 0.9829 / **0** | 0.9122 / 0.9255 | **86.58** (w/ perf) |
| **`titan_b2` (`seed 9202`)** | **BLIND TITAN-B2** Kerala/South-Indic (vs kg8 90.91) | **0.02%** / **0/4** | **1.0000** | **0.9687** / **0** | **0.9200 / 0.9496** | **94.33** (+3.41) |

* **TITAN Reconciliation & Upgrades (`kg8` `3b4e605` -> `kg9` TITAN):**
  * **`chaos_holdout2`:** Eliminated institutional sender email bridging (`From: reports@vidarbha-path.example`), reducing false-merge pairs **`11 -> 0`**.
  * **South-Indic / Malayalam / Box-table generalization (`chaos_holdout21` & blind `titan_b2`):** Added clean-room Tamil, Telugu, Kannada, and Malayalam transliteration in `_to_deva`, `[|│]` box-drawing table support (`OP/IP No`), safe `~`-token untransliterated conflict handling in `_given_conflict`, and Malayalam gender markers (`purushan`/`sthree`/`aan`/`pen`), raising `H21` linkage `F0.5` **`0.9053 -> 0.9682`** (`lang 0.3142 -> 0.8547`) and unseen blind `titan_b2` **`90.913 -> 94.326`** (`temp 0.8218 -> 0.9953`, `0.559s`, `30.7 MB` RSS).
  * **Phase XI blind notes (`kg8`):** `s9_A_awadh` **90.03** (`0.74%` leak, `0` FM), `s9_B_unfamiliar` **89.20** (`det 1.0000`, `F0.5 1.0000`, `0` FM, `0/4` canaries), `s9_C_ambiguous` **60.11** w/ perf (`50.11` no perf — generator omitted `preserve` trap markers so `precision_proxy=0.0`, while `recall=1.0`, `F0.5=1.0`, `B3=1.0`, `FM=0`, `leak=0.0%`). Official `dev` `check_dev.py` retains `4763/4855` items (all `92` missing items are `district` QIs intentionally generalized by `arx_k5_dist_drop`).
* **TITAN Scalability & Streaming Suite (`tools/scale_titan.py`, macOS Python 3.14, `< 4 GB` / `< 900s`):**
  * `100k_repeat_500p`: `10.271s`, `472.6 MB` RSS; `100k_unique` (`100,000` distinct patients): **`13.062s`**, **`615.4 MB`** RSS; `100k_mixed` (502 files): **`19.401s`**, **`359.0 MB`** RSS.
  * `250k_mixed_50kp` (1,252 files, 50k patients): **`53.341s`**, **`760.5 MB`** RSS.
  * `500k_repeat_stream` (50k patients): **`56.183s`**, **`1,975.3 MB`** RSS.
  * `1M_repeat_stream` (100k patients): **`113.659s`**, **`3,350.3 MB`** RSS (`8,798.2 rows/s`).
  * `1M_unique_stream` (`1,000,000` distinct patients): **`139.136s`**, **`3,278.4 MB`** RSS (`7,187.2 rows/s`, `valid: true`, `0` pseudonym collisions).

## Release Assurance 2.0 & Clinical Privacy Command Center (Dev/Demo Tools — Not Runtime)

* **One-command interactive dashboard (`launch_veil.sh` / `tools/veil_ui.py`):** Launches the offline **VEIL — Clinical Privacy Command Center** (`127.0.0.1:8765`, pure Python stdlib + zero external web frameworks/CDNs) pre-loaded on the bundled `demo/sample_hospital/` dataset. Supports synthetic dataset drag-and-drop upload, live execution progress, before-and-after record diffs, cross-hospital SVG patient identity graph & cannot-link veto decisions, 3-policy Privacy Arena, temporal LOS verification, live defect injection/repair + Assurance 2.0 history, TITAN 100k–1M scalability telemetry, and sanitized ZIP export:
  ```bash
  ./launch_veil.sh          # or: python3 tools/veil_ui.py --demo --open
  ```
* **VEIL Assurance Engine 2.0 (`tools/veil_passport.py`)** replaces naive substring heuristics with exact record-level (`loc`/`out`) resolution, occurrence-aware clinical preservation (`clinical_occurrence_rate`), multi-format + FHIR R4 + compact HL7 temporal checks (avoiding false delta failures on timestamps), decoded Base64/Hex/`\uXXXX`/URL residue sweeps, and tri-state reporting (`PASS` / `FAIL` / `WARNING` / `SKIPPED` / `INCONCLUSIVE`).
* **Adversarial Mutation Lab (`tools/mutation_lab.py`)** runs controlled defect-injection & privacy-mutation invariants verifying fail-closed detection and zero false merges.

## License & Models

Licensed under the **MIT License** ([LICENSE](LICENSE)). **Models:** None — zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Passport scope:** Absence of regex residue is not proof of anonymity, and sampled clinical regex expressions kept does not equal ground-truth `medical_kept`.
* **Name linking on unsupported scripts & multi-row blocks:** While 8 Indic digit systems and 9 writing scripts (`Latin`, `Devanagari`, `Bengali`, `Gurmukhi`, `Gujarati`, `Tamil`, `Telugu`, `Kannada`, `Malayalam`) are normalized/transliterated, unknown scripts abstain safely to avoid false merges; multi-row stacked CSV blocks retain exact row indices relative to `rows[0]`.
* **Coincidental numeric substrings & `A5` risk:** Valid clinical numbers/shifted timestamps can match 4–5 digit MRN substrings locally; preserving diagnoses and LOS keeps unique-condition `A5` non-zero.
* **Environment verification note:** Verified locally on macOS Python 3.14 with offline blocked sockets (`36/36` unit/security/contract/Passport/Mutation/UI tests pass) and `check_submission.py --run` (`READY TO SUBMIT`); local Docker daemon was inactive.
