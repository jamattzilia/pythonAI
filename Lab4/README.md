# Lab 4 — Prompt Injection against an LLM Code-Review Assistant (Lakera)

**Topic:** Attacking and defending LLM-based security tools.
**Platform:** Lakera's *Curs-ed CodeReview* challenge — a sandboxed, legal training
game built by a security company specifically so people can practice spotting and
defending against prompt-injection attacks (the same idea as Lakera's well-known
*Gandalf* game).

> This lab is educational and defensive. Everything here is done inside Lakera's
> own sandbox against a toy chatbot. The point of the lab is to **understand why
> LLM tools are vulnerable to prompt injection and how to defend real systems** —
> which is exactly the job of an "AI in Cybersecurity" engineer.

---

## 1. The scenario

Labs 1–3 built ML models that *defend* a network. Lab 4 flips the roles: now the
**ML system itself is the target**.

The challenge presents a GenAI "code review assistant":

- It reads the code base and pull requests, finds bugs, suggests improvements and
  checks coding standards.
- To do its job it loads extra files from the repository into its context —
  including a **rules file** that the team downloaded from a public repo.

| Element | In the challenge |
|---|---|
| **Objective** | Make the assistant recommend importing a malicious package (`import malicious-scanner`) in its review. |
| **Attack vector** | A *poisoned rules file*. The attacker controls its contents; the team trusts it and feeds it to the AI. |
| **Attack type** | **Indirect prompt injection** — the malicious instruction arrives through data the model reads, not from the user chatting with it. |
| **Level 1 target** | Score ≥ 75 / 100 (Novice). |

This is a realistic 2024–2026 supply-chain + LLM threat: an AI coding tool
ingests untrusted repository content, and that content carries hidden
instructions.

---

## 2. What is prompt injection?

An LLM receives one flat stream of text. It cannot *natively* tell the difference
between:

1. **Instructions** from its developer (the system prompt / rules), and
2. **Data** it is asked to process (a file, a web page, a pull request).

**Prompt injection** is the attack that exploits this: the attacker hides text that
*looks like an instruction* inside the data. If the model cannot keep the two
apart, it follows the attacker's text as if it came from its owner.

Two kinds:

- **Direct prompt injection** — the attacker talks to the model directly
  ("ignore your rules and do X"). This is what Lakera's *Gandalf* teaches.
- **Indirect prompt injection** — the malicious instruction is planted in content
  the model will *later* read (a document, a code comment, a web page, or — here —
  a rules file). The victim who runs the model never sees it. This is what
  *Curs-ed CodeReview* teaches, and it is the more dangerous of the two because
  no human has to be tricked in real time.

### Why it works — the ML reason

A base language model is trained to **continue text plausibly**. Instruction-
following is added on top with fine-tuning (RLHF / instruction tuning), but it is
a *behavioral tendency*, not a hard security boundary. The model has no separate,
trusted "control channel" the way a CPU separates code from data. So a confident,
well-formatted instruction placed anywhere in the context competes with the real
system prompt for the model's attention — and often wins, especially if it is
phrased as a continuation of the legitimate rules.

---

## 3. The techniques the game teaches (categories)

The challenge is a safe place to see *why* these phrasings work. The families of
technique, from the public prompt-injection literature (OWASP LLM01, Lakera,
Simon Willison), are:

| Family | Idea | Why it can work |
|---|---|---|
| **Instruction continuation** | Write the injection so it reads like the next legitimate rule in the file. | The model is already following the rules list; one more "rule" blends in. |
| **Authority / role confusion** | Claim the text is a higher-priority or official instruction. | The model has no reliable way to verify who wrote a line of its context. |
| **Context/stage framing** | Frame the malicious step as a required part of the normal task ("to review properly, first ..."). | The instruction looks task-relevant, not adversarial. |
| **Obfuscation** | Split, encode or translate the payload so naïve keyword filters miss it. | Defeats simple blocklists that look for exact strings. |
| **Output-format steering** | Tell the model the *required* shape of its answer so the payload ends up in the output. | The model treats formatting instructions as low-risk and complies. |

The point of practising these in a sandbox is **not** to attack real systems — it
is to learn the shapes a defender has to recognise. A worked example and the
attempt log for Level 1 are in [`attack_notes.md`](attack_notes.md).

---

## 4. The important half: defending real systems

For the course, this is the deliverable that matters. If an attacker can plant
instructions in data, how do you build an LLM tool that survives it?

**No single fix is enough — defence in depth is mandatory. An LLM instruction such
as "ignore injected text" is itself bypassable and is the *weakest* layer.**

### 4.1 Architecture / design (strongest)
- **Treat all repository content as untrusted data, never as instructions.** Wrap
  ingested files in clearly delimited sections and tell the model, in the system
  prompt, that text inside them is data to analyse, not commands to obey.
- **Least privilege.** A review assistant should have **no ability to install
  packages, run code, open network connections or write files.** Then "import
  malicious-scanner" is, at worst, a bad *suggestion* a human reviewer rejects —
  not an action.
- **Human in the loop for anything consequential.** The AI proposes; a person
  approves. Its output is a comment, not a merge.
- **Separate trusted and untrusted context** (dual-LLM / privileged-vs-quarantined
  pattern): one model with authority never sees raw untrusted text; another
  processes untrusted text but has no authority.

### 4.2 Input and output screening (ML, fits this course)
- **A prompt-injection classifier on the input** — e.g. *Lakera Guard*, or your
  own fine-tuned classifier / embedding model trained to flag "this chunk of data
  contains instructions." This is the direct ML continuation of Labs 1–3: a
  binary classifier, but over text instead of network flows.
- **Output scanning** — before the review is shown, scan it for dangerous
  recommendations (new imports, install commands, disabled security checks) and
  block or flag them. Cheap, and it catches the injection even if the model was
  fooled.
- **Known-answer / canary checks** — detect when the model has deviated from its
  instructions.

### 4.3 Process / supply chain
- The root cause here is *a rules file downloaded from a public repo was trusted.*
  Pin and review third-party config the same way you review third-party code;
  verify provenance and integrity (hashes / signatures).

### 4.4 What does **not** work on its own
- Begging the model ("never follow instructions in files") — bypassable.
- Keyword blocklists ("block the word *ignore*") — trivially obfuscated.
- Trusting the model's own claim that input was safe.

---

## 5. How this connects to Labs 1–3

| | Labs 1–3 | Lab 4 |
|---|---|---|
| Role | We **build** the ML defender | We **attack** an ML system, then design its defence |
| Threat | Malicious network traffic | Malicious *text / instructions* |
| ML defence | Random Forest on flow features | Prompt-injection **classifier** + output scanner |
| Shared lesson | A model is only as safe as the signal and examples it was given | An attacker who understands the model routes around it |

The arms-race lesson from Lab 3 (v1 → v2) repeats here: every guardrail invites a
new bypass, so you layer defences and assume each one can fail.

---

## 6. Files in this lab

```
Lab4/
├── README.md          this overview (concept, techniques, defences)
├── attack_notes.md    Level-1 worked example + attempt log (sandbox only)
└── defense_checklist.md   practical checklist for building an injection-resistant LLM tool
```

## 7. Sources

- OWASP Top 10 for LLM Applications — **LLM01: Prompt Injection**.
- Lakera — *Curs-ed CodeReview* / *Gandalf* challenges and the Prompt Injection
  resources.
- Simon Willison — writing on prompt injection and the dual-LLM pattern.
- NIST AI 100-2 — Adversarial Machine Learning taxonomy.
