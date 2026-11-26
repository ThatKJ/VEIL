# VEIL (`rakshak`): a multilingual, longitudinal privacy firewall for hospital records

**Hide the identity. Preserve the medicine.** VEIL (`rakshak`) sanitises messy multi-hospital exports in English, Hindi (Devanagari), Hinglish, and Nagari/Eastern/Western Indic scripts (CSV/TSV, nested JSON, arrays-of-arrays, JSON Lines, FHIR R4 Bundles, fixed-width `.txt`, free-text notes, broken files). It works **offline, on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, filenames (including CamelCase & hyphenated MRNs), URLs, metadata, base64/hex/HTML-encoded payloads;
* keeps medicines, doses (`1-0-1`, `q8h`), vitals, lab values, diagnoses (ICD-10), doctors (`Dr.`), and exact hospital-stay lengths (LOS) intact;
* links the same patient across scripts, files, and hospitals (`Mohammad` / `Mohd.` / `Md.` / `मोहम्मद`), never merging homonyms (`0` false merges across all benchmarks);
* **measures and reduces patient-level re-identification risk**, escalating generalisation only on rare pooled quasi-identifier profiles.

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

## Measured results (local harness, frozen engine commit `3b4e605` / `known-good-8`, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight. Note: `chaos_holdout20` and `chaos_holdout21` were reclassified from blind to diagnostic/development datasets in Phase XI (`kg5`=`e83ba90`, `kg7`=`70f77c8`/`4f11756`, `kg8`=`3b4e605`).

| Dataset | Role | Truth leak / Canaries | Probes | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---|---:|---:|---:|---:|---:|
| official `dev` | official practice | 0.22% (`check_dev 0.0%`) / 0/4 | 0.9930 | 0.9968 / **0** | 0.9458 / 0.8692 | **92.30** |
| `chaos_dev` | dev synthetic | 0.06% / 0/3 | 0.9939 | 1.0000 / **0** | 0.9379 / 0.8790 | **92.71** |
| `chaos_holdout15` | Bundelkhand (diag) | 0.36% / 0/4 | 0.9996 | 0.9953 / **0** | 0.9123 / 0.9393 | **87.49** |
| `chaos_holdout16` | Punjab/Doaba (diag) | 0.65% / 0/4 | 0.9997 | 0.9970 / **0** | 0.9183 / 0.9412 | **85.25** |
| `chaos_holdout17` | Andhra (diag) | 0.44% / 0/4 | 0.9996 | 0.9951 / **0** | 0.9163 / 0.9539 | **92.94** |
| `chaos_holdout18` | Assam/Odisha+HL7 (diag) | 0.03% / 0/4 | 1.0000 | 0.9815 / **0** | 0.8608 / 0.7348 | **85.78** |
| `chaos_holdout19` | Karnataka+JSONL (diag) | 0.01% / 0/4 | 0.9490 | 0.9873 / **0** | 0.8519 / 0.8418 | **91.95** |
| `chaos_holdout20` | Haryana+EAV/stacked (diag, was 68.38) | **0.00%** / **0/4** | 0.7509 | 0.9536 / **0** | 0.7645 / 0.8278 | **85.98** |
| `chaos_holdout21` | Kerala+South-Indic/JSON (diag, was 42.64) | **0.00%** / **0/4** | 0.9999 | 0.9053 / **0** | 0.8942 / 0.8682 | **85.69** |

* **Fresh independent Phase XI blind suite (`s9_A_awadh`, `s9_B_unfamiliar`, `s9_C_ambiguous`; 1-shot, uninspected):**
  * `s9_A_awadh` (EN/HI/Hinglish): `kg8` **90.03** (`0` FM, `det 0.9727`, `F0.5 0.9968`) vs `kg7` 90.08, `kg5` 89.59.
  * `s9_B_unfamiliar` (super-header TSV, EAV CSV, stringified JSON array, coded JSON columns, CSV JSON payload, `wa.me/`/`tel:`, SQL comments): **`kg8` 89.20 (`det 1.0000`, `F0.5 1.0000`, `0` FM, `0/4` canaries)** vs `kg7` 26.71 (`FM=404`, `2/4` canaries) and `kg5` 26.70 (`FM=404`, `2/4` canaries).
  * `s9_C_ambiguous` (4 South-Indic digit scripts, shared household phones & ration cards, binary quarantine): `kg8` **60.11** (`det 1.0000`, `F0.5 1.0000`, `0` FM, `0` canaries) vs `kg7` 60.11, `kg5` 30.56.
* **7-set (`dev`, `chaos_dev`, `H15..H19`) & `H1..H5` notes:** Zero false merges across `dev`, `chaos_dev`, `H1`, `H3..H5`, `H15..H21`, `S9_A..C`, and `W1..W5` (`11` false-merge pairs observed on `chaos_holdout2` at `est_total 95.08`). `A7 = 0.000` on `dev`.
* **High-cardinality scaling (`scale_cardinality.py`, 2 CPUs):** `100,000 rows x 100,000 unique patients` in **`13.95s`** (`707.5 MB` peak RSS, `0` quarantined); `2,000` small files in **`1.44s`**. Worst-case linkage suite (`linkage_worstcase.py`, `W1..W5`): `0` false merges in `0.015–0.286s`.

## Release Assurance & Clinical Privacy Command Center (Dev/Demo Tools — Not Runtime)

* **One-command interactive dashboard (`launch_veil.sh` / `tools/veil_ui.py`):** Launches the offline **VEIL — Clinical Privacy Command Center** (`127.0.0.1:8765`, pure Python stdlib + zero external web frameworks/CDNs) pre-loaded on the bundled `demo/sample_hospital/` dataset (`SH-25-1001`..`SH-25-1005` across super-aligned TSV, EAV CSV, Devanagari coded JSON, EN/HI clinical note, HL7 v2 `ADT^A04`, clean fever protocol, and fail-closed `scans/corrupt_scan.bin` binary quarantine). Supports synthetic dataset drag-and-drop upload, live execution progress, before-and-after record diffs, cross-hospital SVG patient identity graph & cannot-link veto decisions, 3-policy Privacy Arena, temporal LOS verification, live defect injection/repair via Privacy Passport, and sanitized ZIP export:
  ```bash
  ./launch_veil.sh          # or: python3 tools/veil_ui.py --demo --open
  ```
* **`tools/veil_passport.py`** runs a truth-free audit across four independent checks (`structural` pairing all physical files 1:1 with SHA-256 report entries, independent `privacy` residue including base64, `clinical` sampled expressions/intervals, and `identity` pseudonym placement). On official `dev`, the Passport measured **`200/200`** physical input files accounted (`199` unique SHA-256s), `194` exported, `6` quarantined, **`0` residual pattern hits** across `197` channels, **`100.0%` protected clinical expressions** (`1637/1637`, intervals `24/24`), and **`774/774` pseudonyms placed**.
* **`tools/veil_demo.py`** runs the live engine + local attacker end-to-end on synthetic `chaos_dev` (fragmented patient `PT00005`, `21/21` records linked to `PSN-81FAPE`, homonyms separated `PSN-YRWD2D` vs `PSN-YWXMP4`, `107/109` clinical values kept, `A4` reduced `1.00 -> 0.23` vs direct masking, plus injected defect caught by Passport and repaired to `416/416` placed).

## License & Models

Licensed under the **MIT License** ([LICENSE](LICENSE)). **Models:** None — zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Passport scope:** Absence of regex residue is not proof of anonymity, and sampled clinical regex expressions kept does not equal ground-truth `medical_kept`.
* **Name linking on unsupported scripts & multi-row blocks:** While 8 Indic digit systems are scrubbed cleanly, name transliteration covers Devanagari/Bengali/Gurmukhi/Gujarati natively and abstains safely on unknown scripts to avoid false merges; multi-row stacked CSV blocks retain exact row indices relative to `rows[0]`.
* **Coincidental numeric substrings & `A5` risk:** Valid clinical numbers/shifted timestamps can match 4–5 digit MRN substrings locally; preserving diagnoses and LOS keeps unique-condition `A5` non-zero.
* **Environment verification note:** Verified locally on macOS Python 3.14 with offline blocked sockets (`33/33` unit/security/contract/Passport/UI tests pass); local Docker daemon was inactive.
