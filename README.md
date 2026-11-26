# VEIL (`rakshak`): a multilingual, longitudinal privacy firewall for hospital records

**Hide the identity. Preserve the medicine.** VEIL (`rakshak`) sanitises messy multi-hospital exports in English, Hindi (Devanagari), Hinglish, and Nagari/Eastern/Western Indic scripts (CSV/TSV, nested JSON, arrays-of-arrays, JSON Lines, FHIR R4 Bundles, fixed-width `.txt`, free-text notes, broken files). It works **offline, on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, filenames (including CamelCase & hyphenated MRNs), URLs, metadata, base64/hex/HTML-encoded payloads;
* keeps medicines, doses (`1-0-1`, `q8h`), vitals, lab values, diagnoses (ICD-10), doctors (`Dr.`), and exact hospital-stay lengths (LOS) intact;
* **50-bit cryptographically keyed pseudonyms:** `PSN-` + 10 Crockford Base32 characters derived from `HMAC-SHA256(SECRET, "psn|" + key)` with canonical sorted order-independent collision resolution (`0` observed collisions up to `1,000,000` unique patients);
* **links the same patient across scripts, files, and hospitals** (`Mohammad` / `Mohd.` / `Md.` / `मोहम्मद`, Devanagari, Tamil, Telugu, Kannada, and Malayalam transliteration), never merging homonyms (`0` false merges across all tested benchmarks);
* **measures and reduces patient-level re-identification risk**, escalating generalisation only on rare pooled quasi-identifier profiles;
* **streams large tables with bounded memory:** `1,000,000` unique patients processed in `128.93s` and `3,176.2 MB` peak RSS (`< 4 GB` / `< 900s`), `1,000,000` repeated records in `113.16s / 3,206.6 MB`.

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
* **ARX** — equivalence-class risk-driven `k`-anonymity, minimal-loss `5`-year district-drop lattice step (`k_dist`), and consistent age-lattice generalisation.
* **Splink / Dedupe** — Fellegi-Sunter match weighting, multi-attribute inverted blocking, honorific/kinship token stripping, and whole-cluster cannot-link constraints (beating generic Splink-TF `0.71–0.98` with `0` false merges across every suite).
* **pyDeid / UCSF Philter / Microsoft Presidio / medspaCy / Nottingham i2b2 & N-GRID** — clinical allow-list/eponym protection (`Addison's disease`, `Parkinson's`, `McBurney sign`, `CPAP`), clinician/nurse titles (`Dr.`, `Sr.`, `SN`, `DEO`), clinical disambiguation (`S/O` complaints vs kinship, `C/O`, `Asha`/`ASHA`), inline KV prose boundary safety, and independent verification.
* **CleverCSV** — unquoted multi-row structural consistency scoring for ambiguous CSV/TSV dialect detection.
* **Indic rule-based transliteration & HL7 FHIR R4** — script-independent phonetic skeletons across 10 Indic writing blocks & 9 numeral systems (`\u0900-\u0DFF`, Assamese `ৰ`/`ৱ`, Odia) and schema-valid Bundle anonymisation.

## Measured results (local harness, frozen CHAMPION, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight. Note: `chaos_holdout20` and `chaos_holdout21` were reclassified from blind to diagnostic/development datasets in Phase XI (`kg8`=`3b4e605`, `kg9`=`815ae1c` TITAN, `kg10`=`2beffe2` CHAMPION).

| Dataset | Role | Truth leak (`check_dev`) / Canaries | Med kept | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---|---:|---:|---:|---:|---:|
| official `dev` | official practice | **0.0%** / 0/4 | 98.1% | 1.00 / **0** | 0.9463 / 0.8690 | **92.31** (`0.69s`) |
| `chaos_dev` | dev synthetic | **0.0%** / 0/3 | 98.1% | 1.00 / **0** | 0.9379 / 0.8911 | **93.01** (`0.41s`) |
| `chaos_holdout2` | diag validation | 0.1% / 0/4 | 99.7% | 0.99 / **0** | 0.8952 / 0.9789 | **95.20** (`0.35s`) |
| `chaos_holdout16` | Punjab/Doaba (diag) | 0.1% / 0/4 | **100.0%** | **1.00** / **0** | 0.9186 / 0.9470 | **85.41** (`0.61s`) |
| `chaos_holdout18` | Assam/Odisha+HL7 (diag) | **0.0%** / 0/4 | **100.0%** | **0.99** (`96.2%` R) / **0** | 0.8610 / 0.7614 | **87.22** (`0.53s`) |
| `chaos_holdout19` | Karnataka+JSONL (diag) | 0.7% / 0/4 | **100.0%** | 0.99 / **0** | 0.8714 (`1.000` prb) / 0.8582 | **93.54** (`0.47s`) |
| `chaos_holdout20` | Haryana+EAV/stacked (diag) | 0.1% / 0/4 | **100.0%** | 0.94 / **0** | 0.7630 / 0.8419 | **86.07** (`0.80s`) |
| `chaos_holdout21` | Kerala+South-Indic/box-table (diag) | 0.2% / 0/4 | **99.9%** | 0.97 / **0** | 0.9218 / 0.9157 | **89.20** (`0.58s`) |
| **`champion_b1` (`seed 9501`)** | **BLIND CHAMPION-B1** (1-shot, unseen) | 0.1% / 0/4 | **99.7%** | **1.00** / **0** | 0.8903 / **0.9775** | **95.90** (`0.33s`) |

* **CHAMPION Open-Source Model Transfer & Ablations (`kg9` `815ae1c` -> `kg10` CHAMPION):**
  * **Clinical Context, `pyDeid` & Bug Fixes:** Eliminated `kv_rewrite` inline-clause truncation on free-text notes (stopping `MRN:` inside parenthesized clauses from truncating clinical prose), preserved `SN` Staff Nurse titles (rescuing `223/223` lost staff probes on `chaos_holdout19`, **`92.36 -> 93.54`**, `probes: 0.949 -> 1.000`), added `pyDeid`-style medical eponym (`Addison's`/`Parkinson's`/`McBurney sign`) & `CPAP`/`PEEP`/`S/O acute appendicitis` disambiguation, and added `Bharti No` vs `Bharti`/`Chhutti` labels.
  * **Assamese, Odia & Honorific Record Linkage:** Folded Assamese `ৰ`/`ৱ`, Odia `\u0B00-\u0B7F` letters & `\u0B66-\u0B6F` digits (`9` Indic digit scripts, `10` scripts), HL7 `^` split tokens, stripped honorific/kinship noise (`Mr`/`Ms`/`Mrs`/`Sardar`/`Khura`/`Baideu`/`Putek`), and fixed 2-digit elder DOB century wrap (`age >= 75`), lifting `chaos_holdout18` **`86.44 -> 87.22`** (`FS: 170 -> 77`, `R: 0.916 -> 0.962`, `FM=0`), `H16` (`FS: 40 -> 29`), and `H21` (**`89.20`**).
  * **Evidence-Gated Rejections (Model & Matcher Tournaments):**
    * *Classical CRFs (`python-crfsuite`):* Trained compact `52–71 KB` L-BFGS single & dual CRFs on synthetic `train1`/`val1`; standalone CRF (`Clin=1.000, F1=0.685`) looked promising in isolation, yet end-to-end selective fusion (`G2`) across 5 datasets added **`+0.0000` recall** while slightly hurting `dev` probes (`0.9930 -> 0.9911`) and adding `+7%` latency -> rejected cleanly to keep VEIL deterministic & zero-dependency.
    * *Aho-Corasick Matchers (`ahocorasick_rs` vs pure Python):* Micro-benchmarks on 1,200 multi-word notes showed `ahocorasick_rs` `3x–36x` faster (`1–2ms`), while end-to-end `100k_unique` CSV/mixed execution measured Python `_TokenSetSub` at **`12.794s`** vs Rust `ahocorasick_rs` at `13.154s` (`-2.8%`) -> pure-Python `TokenSetSub` retained.
    * *ARX Minimal-Loss Lattice Step:* Added `k_dist` (`(None, gender, age//5, no_birth) >= k_min` before `age//10` widening), keeping `11/53` `dev` and `10/61` `H18` patients in 5-year age bands at `k >= 5`.
  * **Phase XI & TITAN notes:** Zero false merges (`FM = 0`) across `dev`, `chaos_dev`, `H1..H5`, `H15..H21`, `S9_A..C`, `titan_b1..b2` (`titan_b2` = `94.33`), `champion_b1` (`95.90`), and `W1..W5`. Official `dev` `check_dev.py` retains `4763/4855` items (`92` intentional `district` suppressions under `arx_k5_dist_drop`).
* **TITAN/CHAMPION Scalability & Memory Optimization (`tools/scale_titan.py`, macOS Python 3.14, `< 4 GB` / `< 900s`):**
  * Scalar-first singleton compression + lazy token indexing in `Linker.run()` and streaming chunk release reduced peak RSS across every cardinality tier:
    * `100k_repeat_500p`: `10.38s`, `461.2 MB` RSS; `100k_unique`: `12.38s`, **`516.9 MB`** RSS (`-98.5 MB` vs `kg9`); `100k_homonym_hh`: `10.66s`, **`443.2 MB`** RSS; `100k_mixed` (`502` files): `19.49s`, `332.2 MB` RSS.
    * `250k_mixed_50kp` (`1,252` files): `53.74s`, **`732.6 MB`** RSS (`-27.9 MB` vs `kg9`); `500k_repeat_50kp`: `55.59s`, **`1,766.6 MB`** RSS (`-208.7 MB` vs `kg9`); `500k_unique`: `63.42s`, `2,095.3 MB` RSS.
    * `1M_repeat_100kp`: `113.16s`, **`3,206.6 MB`** RSS (`-143.7 MB` vs `kg9`); `1M_unique` (`1,000,000` distinct pseudonyms, `0` collisions): **`128.93s`**, **`3,176.2 MB`** RSS (`7,756.3 rows/s`, `valid: true`, `-102.2 MB` & `-10.2s` vs `kg9`).

## Release Assurance 3.0 & Clinical Privacy Command Center (Dev/Demo Tools — Not Runtime)

* **One-command interactive dashboard (`launch_veil.sh` / `tools/veil_ui.py`):** Launches the offline **VEIL — Clinical Privacy Command Center** (`127.0.0.1:8765`, pure Python stdlib + zero external web frameworks/CDNs) pre-loaded on the bundled `demo/sample_hospital/` dataset. Supports synthetic dataset drag-and-drop upload, live execution progress, before-and-after record diffs, cross-hospital SVG patient identity graph & cannot-link veto decisions, 3-policy Privacy Arena, temporal LOS verification, live defect injection/repair + Assurance 3.0 history, TITAN 100k–1M scalability telemetry, and sanitized ZIP export:
  ```bash
  ./launch_veil.sh          # or: python3 tools/veil_ui.py --demo --open
  ```
* **VEIL Assurance Engine 3.0 (`tools/veil_passport.py`):** Zero-ground-truth release verification with overall `verdict` (`PASS` / `FAIL` / `WARNING` / `SKIPPED`), institutional vs patient role discrimination (separating FHIR `Organization`/`hospital` entities while still failing if direct PII co-occurs on the same line), exact `loc/out` record-level & cross-record per-patient temporal chronology (`dev` official practice: **`privacy 197/197 PASS`**, **`clinical 2361/2361 PASS`**, **`temporal 724/724 PASS`**, **`cross_record 48/48`**, **`identity 774/774 PASS`**, **`structural 200/200 PASS`**), occurrence-aware clinical checks, and decoded Base64/Hex/`\uXXXX`/URL residue sweeps.
* **Adversarial Mutation Lab (`tools/mutation_lab.py`):** Runs controlled defect-injection & privacy-mutation invariants verifying fail-closed detection and zero false merges (`38/38` unit tests + `180/180` Hypothesis fuzzing properties passing).

## License & Models

Licensed under the **MIT License** ([LICENSE](LICENSE)). **Models:** None — zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Passport scope:** Absence of regex residue is not proof of anonymity, and sampled clinical regex expressions kept does not equal ground-truth `medical_kept`.
* **Name linking on unsupported scripts & multi-row blocks:** While 9 Indic digit systems and 10 writing scripts (`Latin`, `Devanagari`, `Bengali/Assamese`, `Gurmukhi`, `Gujarati`, `Odia`, `Tamil`, `Telugu`, `Kannada`, `Malayalam`) are normalized/transliterated, unknown scripts abstain safely to avoid false merges; multi-row stacked CSV blocks retain exact row indices relative to `rows[0]`.
* **Coincidental numeric substrings & `A5` risk:** Valid clinical numbers/shifted timestamps can match 4–5 digit MRN substrings locally; preserving diagnoses and LOS keeps unique-condition `A5` non-zero.
* **Environment verification note:** Verified locally on macOS Python 3.14 with offline blocked sockets (`38/38` unit/security/contract/Assurance 3.0/Mutation/UI tests pass), Hypothesis fuzzing (`180/180` dev property checks), and `check_submission.py --run` (`READY TO SUBMIT`); local Docker daemon was inactive.
