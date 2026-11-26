# VEIL (`rakshak` package): Verifiable Entity Integrity Layer

**Team:** **The Aevos** (Leader: **Ishan Kumar**; Members: **Kirtan**, **Aryan Verma**, **Ukani Het**) · **Track:** Track 3 — Secret Wards · **Repository:** https://github.com/ThatKJ/VEIL

**Hide the identity. Preserve the medicine.** VEIL (internal Python package `rakshak`) sanitises messy multi-hospital exports in English, Hindi (Devanagari), Hinglish, and Nagari/Eastern/Western Indic scripts (CSV/TSV, nested JSON, arrays-of-arrays, JSON Lines, FHIR R4 Bundles, fixed-width `.txt`, free-text notes, broken files). It works **offline, on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, filenames (including CamelCase & hyphenated MRNs), URLs, metadata, base64/hex/HTML-encoded payloads;
* keeps medicines, doses (`1-0-1`, `q8h`), vitals, lab values, diagnoses (ICD-10), doctors (`Dr.`), and exact hospital-stay lengths (LOS) intact;
* **50-bit cryptographically keyed pseudonyms:** `PSN-` + 10 Crockford Base32 characters derived from `HMAC-SHA256(SECRET, "psn|" + key)` with canonical sorted order-independent collision resolution (`0` observed collisions up to `1,000,000` unique patients);
* **links the same patient across scripts, files, and hospitals** (`Mohammad` / `Mohd.` / `Md.` / `मोहम्मद`, Devanagari, Tamil, Telugu, Kannada, and Malayalam transliteration), enforcing whole-cluster cannot-link invariants (`0` false merges across `dev`, `chaos_dev`, diagnostic suites `H1–H21`, `s9903`/`s9904`, and untouched OMEGA blind `9961–9964`);
* **measures and reduces patient-level re-identification risk**, escalating generalisation only on rare pooled quasi-identifier profiles;
* **streams large tables with bounded memory:** `1,000,000` unique patients processed in `56.44s` and `2,481.1 MB` peak RSS (`< 4 GB` / `< 900s`), `1,000,000` repeated records in `41.75s / 1,818.6 MB`, and `1.25M` mixed nominal lines (`943,750` physical records / `6,252` files) in `90.37s / 1,623.8 MB`.

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
* **Indic rule-based transliteration & HL7 FHIR R4** — script-independent phonetic skeletons across `9` Indic scripts + Latin (`\u0900-\u0D7F`, Assamese `ৰ`/`ৱ`, Odia) & `9` numeral systems and schema-valid Bundle anonymisation.

## Measured results (local harness, OMEGA `87ebe5d`, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight. Note: `chaos_holdout20` and `chaos_holdout21` were reclassified from blind to diagnostic/development datasets (`kg8`=`3b4e605`, `kg9`=`815ae1c` TITAN, `kg10`=`2beffe2` CHAMPION, `87ebe5d` OMEGA core).

| Dataset | Role | Truth leak (`check_dev`) / Canaries | Med kept | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---|---:|---:|---:|---:|---:|
| official `dev` | official practice | **0.0%** / 0/4 | 98.1% | 1.00 / **0** | 0.9463 / 0.8690 | **92.49** (`0.72s`, `32.3 MB`) |
| `chaos_dev` | dev synthetic | **0.0%** / 0/3 | 98.1% | 1.00 / **0** | 0.9379 / 0.8911 | **93.01** (`0.41s`) |
| `chaos_holdout2` | diag validation | 0.1% / 0/4 | 99.7% | 0.99 / **0** | 0.8952 / 0.9789 | **95.20** (`0.35s`) |
| `chaos_holdout16` | Punjab/Doaba (diag) | 0.1% / 0/4 | **100.0%** | **1.00** / **0** | 0.9186 / 0.9470 | **85.41** (`0.61s`) |
| `chaos_holdout18` | Assam/Odisha+HL7 (diag) | **0.0%** / 0/4 | **100.0%** | **0.99** (`96.2%` R) / **0** | 0.8610 / 0.7614 | **87.22** (`0.53s`) |
| `chaos_holdout19` | Karnataka+JSONL (diag) | 0.0% / 0/4 | **100.0%** | **0.99** / **0** | — / — | **93.57** (OMEGA) |
| `chaos_holdout20` | Haryana+EAV/stacked (diag) | 0.1% / 0/4 | **100.0%** | 0.94 / **0** | 0.7630 / 0.8419 | **86.07** (`0.80s`) |
| `chaos_holdout21` | Kerala+South-Indic/box-table (diag) | — / 0/4 | **99.9%+** | **0.999** / **0** | — / — | **89.71** (OMEGA) |
| **`omega_blind` (`9961–9964`)** | **BLIND OMEGA** (1-shot, unseen) | **0/16 canaries** | — | **0.997–0.998+** / **0** | — | **89.19 mean** (`92.73` max) |

* **CHAMPION Open-Source Model Transfer & Ablations (`kg9` `815ae1c` -> `kg10` CHAMPION):**
  * **Clinical Context, `pyDeid` & Bug Fixes:** Eliminated `kv_rewrite` inline-clause truncation on free-text notes (stopping `MRN:` inside parenthesized clauses from truncating clinical prose), preserved `SN` Staff Nurse titles (rescuing `223/223` lost staff probes on `chaos_holdout19`, **`92.36 -> 93.54`**, `probes: 0.949 -> 1.000`), added `pyDeid`-style medical eponym (`Addison's`/`Parkinson's`/`McBurney sign`) & `CPAP`/`PEEP`/`S/O acute appendicitis` disambiguation, and added `Bharti No` vs `Bharti`/`Chhutti` labels.
  * **Assamese, Odia & Honorific Record Linkage:** Folded Assamese `ৰ`/`ৱ`, Odia `\u0B00-\u0B7F` letters & `\u0B66-\u0B6F` digits (`9` Indic digit scripts, `10` scripts), HL7 `^` split tokens, stripped honorific/kinship noise (`Mr`/`Ms`/`Mrs`/`Sardar`/`Khura`/`Baideu`/`Putek`), and fixed 2-digit elder DOB century wrap (`age >= 75`), lifting `chaos_holdout18` **`86.44 -> 87.22`** (`FS: 170 -> 77`, `R: 0.916 -> 0.962`, `FM=0`), `H16` (`FS: 40 -> 29`), and `H21` (**`89.20`**).
  * **Evidence-Gated Rejections (Model & Matcher Tournaments):**
    * *Classical CRFs (`python-crfsuite`):* Trained compact `52–71 KB` L-BFGS single & dual CRFs on synthetic `train1`/`val1`; standalone CRF (`Clin=1.000, F1=0.685`) looked promising in isolation, yet end-to-end selective fusion (`G2`) across 5 datasets added **`+0.0000` recall** while slightly hurting `dev` probes (`0.9930 -> 0.9911`) and adding `+7%` latency -> rejected cleanly to keep VEIL deterministic & zero-dependency.
    * *Aho-Corasick Matchers (`ahocorasick_rs` vs pure Python):* Micro-benchmarks on 1,200 multi-word notes showed `ahocorasick_rs` `3x–36x` faster (`1–2ms`), while end-to-end `100k_unique` CSV/mixed execution measured Python `_TokenSetSub` at **`12.794s`** vs Rust `ahocorasick_rs` at `13.154s` (`-2.8%`) -> pure-Python `TokenSetSub` retained.
    * *ARX Minimal-Loss Lattice Step:* Added `k_dist` (`(None, gender, age//5, no_birth) >= k_min` before `age//10` widening), keeping `11/53` `dev` and `10/61` `H18` patients in 5-year age bands at `k >= 5`.
  * **Phase XI–OMEGA (`87ebe5d`) notes:** Zero false merges (`FM = 0`) across `dev`, `chaos_dev`, `H1..H5`, `H15..H21`, `S9_A..C`, `titan_b1..b2` (`titan_b2` = `94.33`), `champion_b1` (`95.90`), `W1..W5`, diagnostic seeds `s9903` (`FM: 32 -> 0` via `sambandhi` & kin lexicons) & `s9904` (`FM: 3 -> 0` via household `Ration:` IDs & `_is_kv_cont` inheritance), and untouched OMEGA blind suites `9961..9964` (`89.19` mean, `+0.38` over `87aba54`). Official `dev` `check_dev.py` retains `4763/4855` items (`92` intentional `district` suppressions under `arx_k5_dist_drop`), cutting `A4` attacker profiles from `101` raw to `54` output (`A4: 0.1915`). APEX (`d6c0d3e`) + OMEGA (`87ebe5d`) further fix `0091-` 14-digit mobile prefixes, `STRUCT_KEYS` non-FHIR scoping, `CLIN_PROTECT` before digit runs, multi-patient FHIR Bundle date routing & `YYYY`/`YYYY-MM` `birthDate` safety, `PYTHONHASHSEED`-independent `verify_text`, and strictly PII-free stdout (`files 200 sanitized 193 quarantined 7 records 817`).
* **APEX Extreme-Scale & Compact-Memory Engine (`tools/scale_titan.py`, macOS Python 3.14, `< 4 GB` / `< 900s`):**
  * Compact `__slots__` `Rec`/`Cluster` representations, pure memoized `text_evidence`, O(L) rarest-gram/token indexer gating, ASCII/digit pre-guards in `scrub_text`, and bounded 2-CPU `os.fork` Pass-2 CoW parallelism with text-weighted LPT load balancing:
    * `100k_repeat_500p`: `3.61s`, `209.6 MB` RSS; `100k_unique`: **`5.54s`**, **`374.8 MB`** RSS; `100k_homonym_hh`: `4.27s`, **`199.1 MB`** RSS; `100k_mixed` (`502` files, `75,500` records): **`6.80s`**, **`176.0 MB`** RSS.
    * `250k_mixed_50kp` (`1,252` files, `188,750` records): **`18.16s`**, **`337.7 MB`** RSS; `500k_repeat_50kp`: **`22.21s`**, **`862.9 MB`** RSS; `500k_unique`: **`27.97s`**, **`1,687.8 MB`** RSS.
    * `1M_repeat_100kp`: **`41.75s`**, **`1,818.6 MB`** RSS; `1M_unique` (`1,000,000` distinct pseudonyms, `0` collisions): **`56.44s`**, **`2,481.1 MB`** RSS (`17,717.6 rows/s`, `valid: true`, `2.28x` faster & `-695 MB` vs `known-good-12`); **`1.25M_mixed_250kp`** (`6,252` files, `943,750` physical records / `1,250,000` nominal lines, `0` loss): **`90.37s` / `1,623.8 MB`** RSS (`7.56x` faster & `-1.30 GB` vs `known-good-12`, `valid: true`).

## Release Assurance 3.0 & Clinical Privacy Command Center (Dev/Demo Tools — Not Runtime)

* **One-command interactive dashboard (`launch_veil.sh` / `tools/veil_ui.py`):** Launches the offline **VEIL — Clinical Privacy Command Center** (`127.0.0.1:8765`, pure Python stdlib + zero external web frameworks/CDNs) pre-loaded on the bundled `demo/sample_hospital/` dataset. Supports synthetic dataset drag-and-drop upload, live execution progress, before-and-after record diffs, cross-hospital SVG patient identity graph & cannot-link veto decisions, 3-policy Privacy Arena, temporal LOS verification, live defect injection/repair + Assurance 3.0 history, TITAN 100k–1M scalability telemetry, and sanitized ZIP export:
  ```bash
  ./launch_veil.sh          # or: python3 tools/veil_ui.py --demo --open
  ```
* **VEIL Assurance Engine 3.0 (`tools/veil_passport.py`):** Zero-ground-truth release verification (`21.6x–23.0x` faster on 10k-unique CSVs: `13.99s -> 0.61s–0.65s`, context-aware Crockford Base32 PSN boundary filtering, exact `is_relative_to` `records.jsonl` containment) with overall `verdict` (`PASS` / `FAIL` / `WARNING` / `SKIPPED`), institutional vs patient role discrimination, exact `loc/out` record-level & cross-record per-patient temporal chronology (`dev` official practice: **`privacy 196/196 PASS`**, **`clinical 2361/2361 PASS` (`100.0%`)**, **`temporal 724/724 PASS`**, **`identity 774/774 PASS`**, **`structural 200/200 PASS`**), and decoded Base64/Hex/`\uXXXX`/URL residue sweeps.
* **Adversarial Mutation Lab (`tools/mutation_lab.py`):** Runs controlled defect-injection & privacy-mutation invariants verifying fail-closed detection and zero false merges (`60/60` unit/security/Assurance/UI/Playwright tests passing, incl. bounded 2-CPU determinism, OMEGA core hardening & Playwright E2E across all 7 UI views; `180/180` Hypothesis properties verified on Champion baseline, not re-run post-edit due to env module absence).

## Security & Encryption-at-Rest Design

* **Exact data-lifecycle boundaries (RAM vs. Disk):**
  * *Held in process memory (RAM) only:* Pass 1 parsed tables/records, harvested identifier sets (`Harvest`), identity clusters (`Linker`), and `RAKSHA_SECRET` HMAC state. Freed incrementally via `gc.collect()` before export.
  * *Written to disk by official CLI (`main.py`):* Strictly finalized redacted/pseudonymized files (`sanitized/` written via `.veil_tmp_* -> os.replace` and unlinked on failure), `records.jsonl` (`records.jsonl.tmp -> os.replace`, unlinked on failure), and SHA-256 `report.json`. Neither `main.py` nor `rakshak/` writes raw patient inputs or unencrypted intermediate PII to `TMPDIR`, `HOME`, quarantine, or swap files; input folders are never modified.
  * *Not an encryption substitute:* Deleting transient buffers or avoiding scratch files does **not** encrypt persisted storage at rest. `HMAC-SHA256` with `RAKSHA_SECRET` provides keyed non-reversible pseudonymization and date offsets, **not** encryption at rest. VEIL uses no custom cryptography; persistent input/archive confidentiality requires host OS / volume full-disk encryption (e.g., dm-crypt/LUKS or KMS-backed storage) and external key management (`RAKSHA_SECRET` kept strictly in env/vault, failing closed `exit 2` if missing/empty).
* **Dev/Demo Command Center (`tools/veil_ui.py` — synthetic data only):** Staging synthetic uploads into a temporary directory followed by immediate `shutil.rmtree` cleanup leaves plaintext briefly on the temp filesystem during synchronous subprocess execution and is **not** encrypted storage at rest. Use `tools/veil_ui.py` strictly with **synthetic demonstration data**, or run on encrypted `tmpfs`/FDE volumes.

## License & Models

Licensed under the **MIT License** ([LICENSE](LICENSE), Copyright © 2026 **The Aevos**). **Models:** None — zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Passport scope:** Absence of regex residue is not proof of anonymity, and sampled clinical regex expressions kept does not equal ground-truth `medical_kept`.
* **Name linking on unsupported scripts & multi-row blocks:** While 9 Indic numeral systems and 10 scripts (`Latin` + 9 Indic scripts `\u0900-\u0D7F`: `Devanagari`, `Bengali/Assamese`, `Gurmukhi`, `Gujarati`, `Odia`, `Tamil`, `Telugu`, `Kannada`, `Malayalam`) are normalized/transliterated, unknown scripts abstain safely to avoid false merges; multi-row stacked CSV blocks retain exact row indices relative to `rows[0]`.
* **Coincidental numeric substrings & `A5` risk:** Valid clinical numbers/shifted timestamps can match 4–5 digit MRN substrings locally; preserving diagnoses and LOS keeps unique-condition `A5` non-zero.
* **Environment verification note:** Verified locally on macOS Python 3.14 (and Python 3.9 syntax/smoke check) with offline blocked sockets (`60/60` unit/security/contract/Assurance 3.0/Mutation/torture/UI/Playwright tests pass), `PYTHONHASHSEED=1 vs 2` byte parity, and `check_submission.py --run` (`READY TO SUBMIT`, `CONTRACT OK`); local Docker daemon was inactive.
