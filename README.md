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

## Measured results (local harness, frozen code commit `e83ba90` / `known-good-5`, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`, full 3-run A/A/B evaluation). Because the official evaluator is sealed, numbers below are local estimates excluding the scaled sub-weight.

| Dataset | Personal data leaked (`check_dev`) | Canaries | Medical kept | Link F0.5 / FM | Utility / Privacy | Est. total |
|---|---:|---:|---:|---:|---:|---:|
| official `dev` | 0.0% | 0 / 4 | 99.3% (probes) | 0.9968 / **0** | 0.9457 / 0.8692 | **92.30** |
| `chaos_dev` | 0.0% | 0 / 3 | 99.4% (probes) | 0.9783 / **0** | 0.9278 / 0.9016 | **92.51** |
| 5 validation holdouts (`H1..H5`) | 0.0–0.3% | **0 / 20** | 99.7–100% | 0.971–0.991 / **0** | 0.895–0.913 / 0.834–0.979 | **89.55–94.79** |
| 3 unseen blind sets (`H15..H17`, Phase IX) | 0.4–1.7% | **0 / 12** | 99.96–99.97% | 0.720–0.986 / **0** | 0.822–0.909 / 0.946–0.959 | **78.69–92.62** (mean **86.24**) |

* **Dev + validation 7-set mean:** **`92.33`** (`0` false merges, `PP = 1.0000`, `pseudonym_consistency = 1.0000`, `100.0%` Devanagari recall, `0/27` canaries).
* **Blind head-to-head (`H15..H17`, Bundelkhand/MP, Punjab/Doaba, Andhra/Rayalaseema):** `known-good-5` (`e83ba90`, mean **`86.24`**, min `78.69`, max `92.62`) improved on every dataset over `known-good-4` (`c7300d4`, mean `86.16`), with **`0/12` canaries**, **`0` false merges**, **`1.0000` pseudonym consistency**, and **`0.000` A7 cross-secret risk** on all 3 sets.
* **High-cardinality scaling (`scale_cardinality.py`, 2 CPUs):** `100,000 rows x 100,000 unique patients` in **`11.03s`** (`704.2 MB` peak RSS, `0` quarantined); `2,000` small files in **`1.19s`**. See `docs/brief.pdf` and `research/` for full tables.

## Models

None. Zero LLMs, zero transformers, zero pretrained weights, zero network calls.

## Known limitations

* Resistance to re-identification is verified against the published attacker suite (`ATTACKS.md`); real-world or undisclosed attacks outside that model are not covered, and no finite test proves anonymity.
* **Blind regional variance (`chaos_holdout16`):** On the unseen Punjab/Doaba synthetic corpus (`H16`), `record_retention` (`0.6294`) and `pairwise_recall` (`0.3396`) dropped relative to other sets while `PP = 1.0000` and `0` false merges held — highlighting harder unlabelled/punjabi name-style linkage and locator recovery when unseen regional syntax diverges.
* **Coincidental numeric substrings:** Local `check_dev` / `evaluate.py` flags 1–10 ordinary numeric `leaked_identifiers` per set where shifted ISO dates, valid vitals (`BP 165/98`), or FHIR `urn:uuid` fragments share 4–5 digit substrings with MRNs.
* **Targeted rare-disease + exact LOS (`A5`):** Intentionally preserved clinical truth (`ICD-10` + stay length) leaves unique diagnoses partially matchable (`0.00–0.64` rel. to raw).
* **Environment verification note:** Verified locally on macOS Python 3.14 with offline blocked sockets (`21/21` unit/security/contract tests pass); local Docker daemon was inactive, so Linux container runtime is verified via CLI/contract and offline-socket isolation tests rather than a live Docker daemon.
