# Five-minute demo script

Record only what works on the deployed URL. Use two browser windows (one normal, one private) so two people can be signed in at once.
If you did not set `ANTHROPIC_API_KEY`, skip the AI step and say so out loud (it returns 503 "not configured"): do not show it as working.

| Time | Show | Say |
|---|---|---|
| 0:00 | README + `THREATS.md` open | "A document is reachable only by someone granted it, I can prove who reached it including refused attempts, and revoking works immediately." |
| 0:30 | Window 1: log in as `viewer_demo` | Exactly one document listed. Download it. "Everything else is invisible, not just hidden." |
| 1:00 | Browser dev tools / terminal: request the Contract's id as the viewer | Same `404 Document not found` as a made-up id. "Missing and ungranted look identical, so ids can't be probed." |
| 1:30 | Window 2: `owner_demo` -> open the Salary letter -> **Activity** tab | The viewer's download and the refused attempt are in the record. |
| 2:15 | Owner clicks **Revoke**; Window 1 clicks Download again | Fails immediately. "No links or tokens to expire; the server asks the database every time." |
| 2:45 | Owner: grant `edit`, upload a new version; viewer sees version history | Edit grantees can add versions but cannot delete or relabel. |
| 3:15 | `admin_demo`: activity filters (permission changes, DENIED), **Audit trail -> Verify integrity** -> VALID | "Admins see ids only. No document contents." |
| 3:45 | Terminal: `python -m scripts.mutation_check -k "authorize() call site"` (a few lines) or show `MUTATION_REPORT.md` | "I remove each authorisation check one at a time; the tests fail every time." |
| 4:15 | Open `THREATS.md` "Knowingly accepted" | Read two honest limits (single-user free-tier database; no storage quota). |
| 4:45 | End | "Unfinished: see README 'known limits'." |
