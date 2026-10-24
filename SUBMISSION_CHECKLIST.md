# Submission checklist (rules copied from the brief; read the "grounds for rejection" part again)

**Deadline: Sunday 25 October 2026, 6:00 PM.** Whatever is on the form then is what is evaluated.

## Rules that can remove you from the process
- [ ] **Do not make the repository public before the deadline.** The brief asks for a public repo AND forbids publishing early: keep it **private** (Render can still deploy
      a private repo) and switch it to public shortly before 6:00 PM on Sunday, then check the link in a private window.
- [ ] **Never back-date commits or rewrite history.** Your history starts when you started committing: say so honestly in the write-up (the earlier design work was done in another tool).
      Commit now, in small honest steps (docs, then code, then tests).
- [ ] **PROMPTS.md is yours.** At least 5 dated entries (what you asked / what it produced / what was wrong / what you did, with a commit link), at least 2 about
      authorisation, access control or the audit trail. Add the context files you reused (AI_CONTEXT.md, the handoff prompt). Write it in your own words.
- [ ] **You must be able to explain and change the code live.** Read `docs/WALKTHROUGH.md` and trace a download through the real files.
- [ ] **Do not claim anything that does not work** (form, video, README). Say "unfinished" instead. See README "known limits".
- [ ] Do not share your repo or code with anyone; do not attack anyone else's system.

## Before you submit
- [ ] Live URL opens in an **incognito window** (open it a minute early: free hosts sleep). Seed accounts log in; README table matches.
- [ ] `python -m pytest -q` green on your machine; run `python -m scripts.mutation_check` once and commit the fresh `MUTATION_REPORT.md`.
- [ ] README top lines have your live URL; DEPLOY.md steps match what you actually did (fix anything that differed).
- [ ] THREATS.md reread: every claim marked BUILT is true; add anything you found yourself.
- [ ] 5-minute demo video recorded from `DEMO.md`, showing only working features; link added.
- [ ] WRITEUP.md rewritten in your own words (permission model and AI sections).
- [ ] Form: title, one-line description, GitHub link, live link, six questions, then tick **"I am done. Submit this for evaluation."**
