# Pre-Submission Checklist — Smart Log Analyzer & Anomaly Detector

Organized by the assessment's own grading categories so nothing graded gets missed.

## Functionality
- [x] App runs from a clean clone/restart without manual DB seeding steps you forgot to script
- [x] Full pipeline works end-to-end: load logs.csv → validate → detect → AI-explain → view in UI
- [x] Empty dataset case tested — shows a clear "no data" state, doesn't crash
- [x] Malformed rows (the 2 in logs.csv) are actually rejected, not silently ingested
- [x] No unhandled exceptions when clicking through list → detail for every flagged entry

## AI (appropriate use, reasoning, reliability)
- [x] AI is called only for explanation/root-cause — confirm nowhere does it influence which entries get flagged
- [x] AI explanations are cached in the DB, not regenerated on every page load (check by reloading a detail view twice and confirming no new API call fires)
- [x] API failure is handled gracefully — temporarily break the API key and confirm the UI shows "unavailable" instead of crashing, then restore the key
- [x] Spot-check 4-5 AI explanations against the actual anomaly — do they make sense, or are they generic/templated-sounding?
- [x] Explanations read as genuinely generated text, not a fill-in-the-blank template (this is explicitly checked against per the brief)

## Engineering (design, code quality, maintainability)
- [x] Code is organized into logical modules (ingestion / detector / AI client / UI), not one giant script
- [x] No hardcoded API keys in source — using env var / config, and it's excluded from anything you'd share publicly
- [x] Detector thresholds/rules are named constants or config, not magic numbers buried inline
- [x] You can explain every function you didn't personally type (Antigravity-generated code included) — re-read anything unfamiliar before submitting

## Data (persistence, sensible handling)
- [x] SQLite file persists between app restarts — flagged entries and AI explanations survive a restart, don't regenerate
- [x] Schema matches what you documented (LogEntry / FlaggedEntry with the fields you specified)
- [x] Rejected/invalid rows are still logged somewhere (not silently dropped with zero trace)

## UX (clarity, usability)
- [x] Flagged entries are visually distinguishable from normal ones at a glance in the list view
- [x] Detail view shows: entry fields, detector_rule + score, AI explanation, AI root cause — all in one place
- [x] Validation summary (rows loaded vs rejected) is visible somewhere, not buried in logs only you can see

## Problem Solving (decisions, trade-offs, originality)
- [x] README explicitly states which detector rules you chose and *why* (not just what)
- [x] README notes any thresholds you picked and the reasoning (e.g. why 25 requests/50s counts as a burst)
- [x] Any optional enhancements you added are mentioned, with brief justification

## Ground-truth verification (your own quality bar, not explicitly graded but strong evidence)
- [x] Cross-checked detector output row IDs against `answer_key.csv` — note the hit rate somewhere (README or your own notes) in case you're asked
- [x] Understand and can explain any false positives/negatives your detector produced relative to the answer key

## README completeness (explicit deliverable)
- [x] Setup instructions: how to install deps, set the Gemini API key, and run the app
- [x] Approach section: detector logic + reasoning, AI integration + reasoning
- [x] Assumptions made about the data explicitly listed
- [x] Known limitations explicitly listed (don't hide gaps — naming them well reads as maturity, not weakness)

## Final pass
- [x] Do a full restart-and-run one more time, timing it, right before submission — confirms nothing broke in last-minute edits
- [x] Remove/rotate any API key you don't want exposed if you're sharing the repo publicly
- [x] Confirm you can talk through every design decision out loud without notes — you're explicitly expected to defend the implementation verbally