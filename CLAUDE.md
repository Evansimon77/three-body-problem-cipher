# Chaos Cipher

Read `PROGRESS.md` on session start for full project context. The engineering philosophy + the
one-signature **Prime Directive** are global (`~/.claude/`) — read `~/.claude/Architect-Strategy.md`
on demand for any substantial design/build/refactor.

**Trigger words** (load this project when the user says any of): "chaos cipher", "chaos engine",
"the cipher project", "PWLCM", "chaos crypto", "the encryption experiment".

## What this is
A **research** chaos-based stream cipher (integer PWLCM keystream + AEAD shell). Clearly
**UNVETTED** — never used to protect real data. The point is to experiment and learn by trying
to break it. Honest evaluation lives in `REPORT.md`.

## Three-pillar workflow (how we work here)
| Pillar | Role |
|--------|------|
| **GitHub** (`Evansimon77/chaos-cipher`, private) | 🕰️ Time machine — every save is a commit; roll back anytime. Each new idea = a git branch. |
| **Obsidian** (`Chaos Cipher.md`) | 📜 Append-only log — every step recorded, nothing erased, including dead ends. |
| **`PROGRESS.md`** (this folder) | 🧭 Living compass — what's DONE · what's NEXT · the GOAL. Read first on resume. |

## The "save" command
When the user says **"save"** (or "save this" / "checkpoint"), do ALL of these in order:
1. **Test** — run `python3 -m pytest tests/ -q`; only proceed if green (note it if not).
2. **GitHub** — `git add -A && git commit -m "<concise what+why>" && git push`.
3. **Obsidian** — prepend a dated entry to the `## 📜 Build Log` section of
   `~/Documents/Cursor Code/Obsidian Vault/Vault/Chaos Cipher.md` (append-only; never delete).
4. **PROGRESS.md** — update `Last updated` + the `NEXT` / `GOAL` and prepend a `✅ DONE <date>` entry.
Report the commit hash, the branch, and the one-line log entry back to the user.

## Branching idea-exploration
- New idea → `git checkout -b <idea-name>`; experiment, `save` along the way.
- Idea works → merge to `main`. Idea fails → `git checkout main` (or the last good branch) and
  branch off again. The Obsidian log keeps the dead-end lesson even after the branch is deleted.

## Resume
```bash
cd "~/Documents/Cursor Code/Projects/chaos-cipher" && claude
```
On "work on the chaos cipher" → read `PROGRESS.md` (done/next/goal), then resume from NEXT.
