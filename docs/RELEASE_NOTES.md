# VEIL release notes — submission freeze

Team **The Aevos** (Ishan Kumar — leader; Kirtan; Aryan Verma; Ukani Het) · Track 3, Secret Wards · Yugaantar DevForge.
All figures below are from local runs on synthetic data with the unmodified organizer toolkit or our local
re-implementation of the published attacker; they are not official competition results.

## Releases

| Tag | Commit | Content |
|---|---|---|
| `known-good-15` / `aegis-release` | `c191fb1` | AEGIS security hardening of the local demo UI and Passport; core engine unchanged |
| `known-good-16` | `4007e66` | SENTINEL: record-aligned birth-date verification in the Passport + regression tests; core engine unchanged |
| `submission-final` | this commit | Documentation only (these notes; no code change) |

The sanitizer (`main.py`, `rakshak/`, `config/`, `raksha.toml`, `requirements.txt`) produces byte-identical output across all three.

## SENTINEL evidence

- **Practice-checker DOB findings.** `check_dev.py` reported 2 of 3230 identifiers for some secrets, both birth dates. Investigation: in every case the patient's own DOB had been shifted; the original date string appeared only because a *different* date (another patient's shifted DOB or shifted registration date) coincided with it. These are coincidental date-string matches, not unchanged original DOB values. Because shifts are keyed by `RAKSHA_SECRET`, the practice-checker count varies with the secret: 2/3230 for 2 of 12 secrets tried, 0/3230 for the other 10 and for the Linux run. We do not claim universal zero leakage, and the release was not tuned to a favourable secret.
- **Record-aligned DOB verification.** The Passport now flags a birth-date table cell that is identical in input and output at the same row and column (a genuinely unshifted DOB); coincidences in other rows cannot trigger it.
- **Regression.** The engine shifted all 60 independently generated birth dates (five date formats, five header labels); the verifier detected the one deliberately restored original DOB.
- **Mutation testing.** 16/16 injected defects detected (identifiers incl. base64, patient name, dose, lab value, stay length, wrong pseudonym, broken locator, missing/duplicate record, broken FHIR reference, unexpected file, wrong report count, malformed output, unshifted DOB); the clean release passes. Eight clean releases produced no DOB false alarms.
- **Linux.** Executed a fresh public clone in a Linux container (Python 3.12, 2 CPUs, 4 GB, network disabled, read-only filesystem and input, private HOME/TMPDIR, 900 s limit): exit 0, all files accounted for, input unchanged, deterministic, identical to macOS output, `validate_output.py` CONTRACT OK; the two-process mode matched single-process output on 100,000 rows. This approximates the organizer environment; it does not reproduce its exact sandbox.
- **Privacy–utility.** Suppressing birth dates for escalated patients reduced local re-identification but cut temporal utility (0.98 → 0.68) and lowered the estimated overall score on all three test sets, so it was rejected.

## Disclosed limitations

- Residual re-identification under the local attacker (about 9–10 of 48 dev patients, vs 47/48 on raw data): shifted birth dates keep the approximate year; rare diagnoses with exact length of stay are kept for clinical truth; small demographic cohorts.
- Two-line CSV records (seen in a Malayalam diagnostic set): the continuation row is linked to the right patient but carries no pseudonym cell.
- Pseudonymisation is not anonymisation; the Privacy Passport is evidence about one release, not a certificate.
- The local demo UI is for synthetic data; real deployments need strong confidential keys and encrypted storage.
- The event-wide AI-assisted development policy has not been confirmed with the organizers.
