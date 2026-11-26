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

## Measured results (local harness, frozen engine commit `70f77c8` / `known-good-7`, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`, full 3-run A/A/B evaluation). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight.

| Dataset | Personal data leaked (`check_dev`) | Canaries | Medical kept (probes) | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---:|---:|---:|---:|---:|---:|
| official `dev` | 0.0% | 0 / 4 | 99.3% | 0.9968 / **0** | 0.9458 / 0.8692 | **92.30** |
| `chaos_dev` | 0.0% | 0 / 3 | 98.7% | 0.9935 / **0** | 0.9327 / 0.9017 | **93.09** |
| `chaos_holdout15` (Bundelkhand) | 0.1% | 0 / 4 | 99.96% | 1.0000 / **0** | 0.9133 / 0.9454 | **87.75** |
| `chaos_holdout16` (Punjab/Doaba) | 0.1% | 0 / 4 | 99.97% | 0.9993 / **0** | 0.9183 / 0.9471 | **85.62** |
| `chaos_holdout17` (Andhra) | 0.3% | 0 / 4 | 99.96% | 0.9953 / **0** | 0.9163 / 0.9585 | **93.06** |
| `chaos_holdout18` (Assam/Odisha + HL7) | 0.0% | 0 / 4 | 100.0% | 0.9897 / **0** | 0.8608 / 0.7614 | **86.82** |
| `chaos_holdout19` (Karnataka + JS literals) | 0.6% | 0 / 4 | 94.9% | 0.9882 / **0** | 0.8529 / 0.8576 | **92.39** |
| `chaos_holdout20` (**BLIND**, uninspected) | 5.9% | 3 / 4 | 66.1% | 0.9450 / **0** | 0.7768 / 0.7171 | **68.38** |
| `chaos_holdout21` (**BLIND**, uninspected) | 17.7% | 2 / 4 | 98.5% | 0.4315 / 1,485 | 0.7806 / 0.5467 | **42.64** |

* **7-set (`dev`, `chaos_dev`, `H15..H19`) summary:** mean **`90.15`**, min `85.62`, **`0` false merges (`PP = 1.0000`)**, **`0/27` canaries**, **`1.0000` pseudonym consistency**, and `0.000` `A7` cross-secret risk on all 7 sets (reclaimed `+9.86` pts on `H18` over `84db8d3` and eliminated `H16`'s `rec_ret=0.63 -> 1.00` collapse).
* **Strictly uninspected `H20/H21` comparison (`kg5` -> `kg6` -> `84db8d3` -> `70f77c8`):** On `H20`, `70f77c8` (`68.38`) matches `kg6` and beats `kg5` (`67.72`); on `H21`, `70f77c8` (`42.64`, `17.7%` leaked) beats `84db8d3` (`38.74`, `28.3%` leaked), `kg6` (`40.73`), and `kg5` (`40.90`).
* **High-cardinality scaling (`scale_cardinality.py`, 2 CPUs):** `100,000 rows x 100,000 unique patients` in **`11.63s`** (`670.9 MB` peak RSS, `0` quarantined); `2,000` small files in **`1.40s`**. Worst-case linkage suite (`linkage_worstcase.py`, `W1..W5`): `0` false merges in `0.01–0.28s`.

## Release Assurance & Demo (Dev/Demo Tools — Not Runtime)

* **`tools/veil_passport.py`** runs a truth-free audit across four independent checks (`structural`, independent `privacy` residue including base64, `clinical` doses/BP/labs/ICD/intervals, and `identity` pseudonym placement). On official `dev`, the Passport measured `199/199` files accounted, **`0` residual pattern hits** across `197` channels, **`100.0%` protected clinical values** (`1637/1637`, intervals `23/24`), and **`774/774` pseudonyms placed**.
* **`tools/veil_demo.py`** runs the live engine + local attacker end-to-end on synthetic `chaos_dev` (fragmented patient `PT00005`, `21/21` records linked to `PSN-81FAPE`, homonyms separated `PSN-YRWD2D` vs `PSN-YWXMP4`, `107/109` clinical values kept, `A4` reduced `1.00 -> 0.23` vs direct masking, plus injected defect caught by Passport and repaired).

## Models

None. Zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Unfamiliar format/script headroom (`chaos_holdout20`, `chaos_holdout21`):** Strictly uninspected blind holdouts `H20/H21` exposed unparsed/non-standard structures (`canaries 3/4` & `2/4`, `H21` `17.7%` leak and `1,485` false merges), left raw/uninspected to preserve blind integrity.
* **Keyed maps with PII keys:** When a JSON map key itself is PII, emitting the input locator leaks PII into `records.jsonl`; VEIL renames those keys safely (`_SAFE_SURROGATE_KEY` + real-record `rec_ids` check) and falls back to the nearest safe ancestor (`patient: null`).
* **Coincidental numeric substrings & `A5` risk:** Valid clinical numbers/shifted timestamps can match 4–5 digit MRN substrings locally; preserving diagnoses and LOS keeps unique-condition `A5` non-zero.
* **Environment verification note:** Verified locally on macOS Python 3.14 with offline blocked sockets (`28/28` unit/security/contract/Passport tests pass); local Docker daemon was inactive.
