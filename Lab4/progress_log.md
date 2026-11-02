# Lab 4 — Progress log (screenshots + write-up)

Running record of the Lakera challenge: every screenshot, the prompt used, and why
it worked. This is the raw material for the two things the task requires in the
report:

1. **Скриншот скорборда и список пройденных комнат.**
2. **История запросов** — как именно решался каждый уровень.

Strategy (see [`README.md`](README.md) and the scoring analysis): **go deep in ONE
challenge — all 5 levels of *Curs-ed CodeReview* → automatic 100.**

---

## Reference screenshots

| File | What it shows |
|---|---|
| `screenshots/01_curs-ed_level1_interface.png` | The Curs-ed CodeReview Level 1 UI: the poisoned **rules file** (left), the attack-input box, and the victim chatbot (right). |
| `screenshots/02_scoring_rules.png` | **Scoring rules.** Grade = (total score / 10) − (completed levels); a level counts only at ≥ 75. Shortcuts to 100: 1100+ total points, OR all 5 levels of one challenge. |
| `screenshots/03_challenges_overview_level1_100.png` | Challenge grid. **Curs-ed CodeReview Level 1 = 100/100**, Level 2 unlocked, 3–5 locked. Other challenges available as point-padding fallback. |

---

## Attempt log — Curs-ed CodeReview

Objective: make the review recommend `import malicious-scanner`.
Vector: **indirect prompt injection** via the poisoned rules file.

### Level 1 — DONE (100/100)
- **Screenshot:** `screenshots/03_challenges_overview_level1_100.png` (shows 100/100).
- **Technique family:** instruction continuation + output-format steering.
- **Prompt used:** _(paste the exact text that scored here)_
- **Why it worked:** the injection was added as the next numbered "rule", so it
  inherited the authority of the legitimate rules list; it tied the malicious
  import to the model's real task ("suggest improvements") and dictated the output
  format, so the import landed in the review's recommendations.

### Level 2 — TODO
- **Screenshot:** _(add `screenshots/04_curs-ed_level2_*.png`)_
- **Defence this level adds:** _(note what changed vs L1 — a filter? a stronger
  system prompt? an output check?)_
- **Prompt used:** _
- **Why it worked:** _

### Level 3 — TODO
_(same template)_

### Level 4 — TODO
_(same template)_

### Level 5 — TODO
_(same template; a screenshot of all 5 bars full = automatic 100)_

---

## How to add a new screenshot

1. Take the screenshot after a level is solved (scoreboard or the victim panel
   showing the successful review).
2. Save it to `Lab4/screenshots/` with the next number, e.g.
   `04_curs-ed_level2_solved.png`.
3. Fill in the matching section above: the **exact prompt**, the **defence the
   level added**, and **why the prompt beat it**.
4. (Optional) tell me and I'll commit it.

When all 5 levels are done + the scoreboard screenshot is in, I'll assemble the
final **`Lab4_report.docx`** in the same style as Labs 1–3.
