# Rakshak: a multilingual, longitudinal privacy firewall for hospital records

Rakshak sanitises messy multi-hospital exports in English, Hindi (Devanagari) and Hinglish
(CSV/TSV, nested JSON, JSON Lines, FHIR R4, free-text notes, broken files). It works **offline,
on CPU only, with no LLMs or ML models**, using only the Python standard library. In one release it:

* removes personal data everywhere: content, JSON keys, CSV headers, file names, metadata, base64 attachments;
* keeps medicines, doses, vitals, lab values, diagnoses, doctors and exact hospital-stay lengths intact;
* links the same patient across scripts, files and hospitals (Mohammad / Mohd. / Md. / मोहम्मद), never merging homonyms;
* **measures and reduces patient-level re-identification risk**, the part that makes the attacker fail.

## Run

```bash
pip install -r requirements.txt          # nothing to install: standard library only
RAKSHA_SECRET=<secret> python3 main.py --input <input dir> --output <empty output dir>
```

Output: `sanitized/` (same tree and formats, UTF-8), `report.json`, `records.jsonl` (contract v1).
`RAKSHA_SECRET` keys every pseudonym, date shift and renamed file/key (HMAC-SHA256). It is never written anywhere.
Same input + same secret gives byte-identical output. A different secret gives different pseudonyms and shifts.

## How it works (two passes)

```
input ─► 1. Ingest: BOM/UTF-16/cp1252 sniffing, content-type sniffing (JSON behind .csv, pipe tables in .txt,
            JSON Lines), depth guard; unreadable or unsupported files are QUARANTINED, never copied
       ─► 2. Structure: per-field kind from header/key lexicon (EN/HI/Marathi/Hinglish) + value shape;
            patient records found at any depth (nested arrays, arrays-of-arrays, header+rows tables)
       ─► 3. Harvest: names, IDs, phones and villages from structured fields + labelled free text
       ─► 4. Identity graph: strong IDs, then name skeleton (script-independent) + second clue
            (DOB / relative / village+age), only when unambiguous; whole-cluster cannot-link checks
            (gender, DOB, age, Aadhaar/ABHA/PAN conflicts) stop transitive over-merging
       ─► 5. Pooled-profile privacy engine (USP, below) -> per-patient rule
       ─► 6. Rewrite: structured rules + free-text scrubber (doctor/clinical spans protected first; dates
            shifted per patient; IDs; labelled/kinship/honorific/contextual names; harvested-name sweep;
            address fragments; truthful age bands)
       ─► 7. Independent verification: exact-substring scan of harvested critical values on the output
       ─► report.json (SHA-256 per input file, honest counts), records.jsonl (pseudonym present IN each record)
```

## USP: pooled-profile, patient-level privacy

A patient who is anonymous in one record is often identifiable once all of their records are
pooled, and pooling is exactly what the attacker does. Rakshak resolves each patient's records first, then
evaluates the **pooled** quasi-identifiers (district, gender, age, birth year, conditions) of that patient
across every file, script and hospital. Generalisation is escalated **only for patients whose pooled profile is rare**:
a small equivalence class in the release, a rare condition (shared by at most 3 patients), or age 80 and over. For those
patients the DOB is removed, a wider truthful band is used, and PIN/tehsil are dropped. Bands are **consistent per patient**,
so intersecting records cannot recover an exact age. Dates move by a secret per-patient shift, so stays and intervals stay exact.

Prior art: risk-driven anonymisation with attacker models exists for structured tables (ARX). Our contribution is applying
it to pooled multilingual free text plus structured records in one offline pipeline. This is a combination, not a "first".

## Measured results (local harness, NOT the official evaluator)

Local re-implementation of the published scorer and attacker (`docs/SCORING.md`, `docs/ATTACKS.md`). The official
evaluator is sealed, so totals below are **estimates**. Dev = organizer practice data. Chaos sets are independently
generated synthetic data with unseen formats.

| Dataset | Personal data leaked (check_dev) | Canaries | Medical values kept | Link F0.5 / false merges | Est. total |
|---|---|---|---|---|---|
| official dev | 0.0% | 0/4 | 100.0% | 0.99 / 0 | 88.2 |
| chaos_dev | 0.0% | 0/3 | n/a | 0.91 / 0 | 86.8 |

Privacy approaches on identical inputs (dev, local attacker): masking only, privacy 0.55; fixed transforms, 0.65;
**adaptive patient-level, 0.80** (profile re-identification 0.90 → 0.40 of raw).
Full logs: see the project brief and the experiment leaderboard.

## Models

None. No LLMs, no transformers, no pretrained models. Only rules, lexicons written for this project, transliteration
tables, and probabilistic-style record linkage.

## Known limitations

* The attacker model is the published one, so resistance to *other* attackers is not guaranteed. No finite test proves anonymity.
* Unseen layouts are handled generically (value shape, nested-record discovery), but entirely novel formats may still leak.
  Files we cannot parse safely are quarantined, which costs record retention but never leaks.
* Escalated (high-risk) patients lose their DOB (age band kept), a deliberate privacy-over-utility choice.
* Names with no structural or contextual cue at all can survive. A final verification pass catches harvested values only.
