# TrustVault: write-up  (DRAFT: rewrite the sections marked YOURS in your own words before submitting)

## What I built
FastAPI + PostgreSQL document platform: server-side sessions, three roles, per-document read/edit grants, encrypted storage, search, versions, soft delete and trash,
an HMAC-chained audit trail that records refusals, owner and admin activity views, and an advisory AI feature. 170+ automated tests on PostgreSQL, a
route-discovering isolation suite, and a mutation script that removes one security check at a time.

## What I deliberately did not build
Folder/group inheritance (it turns "one file" into "forty"), download links or tokens (they would need expiring and revoking), stateless JWTs (cannot be
revoked instantly), content-aware AI (the model never sees file contents), email verification, MFA, per-user quotas, antivirus.

## My permission model, in my own words   <- YOURS
_Explain, in your voice, who can reach a document and why the server answers 404 instead of 403. Use the "permission model in plain words" part of docs/WALKTHROUGH.md as notes only._

## How I used AI and where it was wrong   <- YOURS (must match your PROMPTS.md)
_Real moments only. Examples of true things that happened in this build, to jog your memory (use the ones you remember and add your own):_
- _A design that returned 403 for ungranted documents (an existence oracle) and a transfer-accept rule that did the same._
- _A route-inventory test that passed while checking 1 of 32 routes; a test that could never fail (`or True`)._
- _Audit lock: an in-process lock that could deadlock against the database lock; refusal counters that lived in memory._
- _The first test run passed, but the mutation script found authorisation checks nobody was testing._

## What is unfinished
See README "Decisions and known limits" and THREATS.md "Knowingly accepted". Nothing in the README describes a feature that is not built.
