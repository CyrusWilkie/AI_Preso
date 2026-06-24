# Presentation Outline: Making AI Think

**Duration:** 15–20 minutes
**Audience:** Pen testing team
**Core narrative:** LLMs don't inherently "reason" — but you can write code that makes them behave as if they do. Each technique adds more structure to the AI's thinking process, and the results improve dramatically.

---

## Slide 1: Title Slide

**Title:** Making AI Think — Prompting Techniques for Vulnerability Discovery
**Subtitle:** Same model, same code, dramatically different results
**Visual:** None needed — clean title slide

---

## Slide 2: What We're Doing Today

**Points:**
- We're going to take a small, local LLM and ask it to find vulnerabilities in code
- We'll try four different prompting techniques, each more sophisticated
- The model never changes — only how we talk to it and the code we wrap around it
- Goal: show how much of what we call "AI reasoning" is actually engineering

**Visual:** Simple diagram showing the constant (the LLM) vs. the variable (the prompting technique), with an arrow from "same model" to "better results"

---

## Slide 3: The Setup

**Points:**
- Model: Qwen 2.5 Coder 7B running on Ollama (local, on an old laptop with a 4050)
- Not a frontier model — deliberately chosen to show that technique matters more than model size
- Three benchmark code files:
  - A C banking CLI (20 vulns — buffer overflows, format strings, race conditions)
  - A Python Flask web app (20 vulns — SQLi, XSS, SSRF, deserialization)
  - A PHP file-sharing app (25 vulns — RCE, LFI, file upload bypass, CSRF)
- 65 total vulnerabilities, ranging from obvious to subtle

**Visual:** Screenshot of the three code files open side by side (just the top 20-30 lines of each to give the audience a flavour)

---

## Slide 4: The Vulnerability Spectrum

**Points:**
- Not all vulns are equal in difficulty — some are textbook, others require contextual reasoning
- Easy: `gets()`, `strcpy()`, direct SQL concatenation — pattern matching finds these
- Moderate: format string bugs, insecure deserialization, SSRF — need to understand what the code does
- Hard: TOCTOU race conditions, off-by-one errors, returning stack pointers, mass assignment — need to reason about program behaviour
- The real test is whether a technique can find the hard ones

**Visual:** A table showing 3-4 example vulnerabilities from each difficulty tier with a one-line description (pull from VULNERABILITY_KEY.md)

---

## Slide 5: Technique 1 — Zero-Shot (Concept)

**Title:** Technique 1: Zero-Shot Prompting — "Just Ask"
**Points:**
- The most basic approach: paste the code into a prompt and say "find vulnerabilities"
- No examples, no structure, no reasoning guidance
- This is how most people use LLMs for code review today
- The model has to decide on its own what to look for, how deep to go, and how to report it
- Think of it as handing a junior analyst a file and saying "tell me what's wrong"

**Visual:** Show the actual prompt text from `1_zero_shot.py` — the raw string that gets sent to the model (it's short enough to fit on a slide)

---

## Slide 6: Technique 1 — Zero-Shot (Implementation)

**Title:** Implementation: Just a single API call
**Points:**
- The code is minimal — load the file, send the prompt, print the response
- No parsing, no structure, no iteration
- This is the baseline — the least amount of engineering possible

**Visual:** Screenshot of the key section of `1_zero_shot.py` — the `zero_shot_analysis` function (roughly lines 23–57). Highlight how simple it is.

---

## Slide 7: Technique 1 — Zero-Shot (Results)

**Title:** Zero-Shot Results
**Points:**
- The model finds the obvious stuff: `gets()`, `strcpy()`, hardcoded passwords, basic SQLi
- Misses subtle issues: race conditions, off-by-one, stack pointer return, mass assignment
- Output is inconsistent — sometimes verbose paragraphs, sometimes bullet points
- No severity ratings, no CWE references, hard to action
- This is a good gut-check, but you wouldn't write a report from this

**Visual:** Screenshot of the terminal output from running `python 1_zero_shot.py vulnerable.c`. Annotate with callouts: "found this" / "missed this"

---

## Slide 8: Technique 2 — Few-Shot Structured (Concept)

**Title:** Technique 2: Few-Shot Prompting — "Show, Don't Tell"
**Points:**
- Instead of just asking, we show the model 3 examples of what a good vulnerability report looks like
- Each example is a structured JSON object with fields: vulnerability name, CWE, severity, location, code snippet, explanation, exploitation scenario, remediation
- The examples prime the model to look for specific categories (injection, memory safety, hardcoded creds)
- Structured output means we can parse, count, and compare results programmatically

**Visual:** Show one of the three few-shot examples from `2_few_shot_structured.py` (the JSON block for SQL Injection or Buffer Overflow) — it fits on a slide and the audience can immediately see the structure

---

## Slide 9: Technique 2 — Few-Shot Structured (Implementation)

**Title:** Implementation: Parse, Deduplicate, Rank
**Points:**
- The prompt is richer, but the real addition is the code around it
- JSON extraction: parse the model's free-text response to pull out structured findings
- Deduplication: the model sometimes reports the same vuln twice — code catches this
- Severity sorting: findings are ranked Critical → High → Medium → Low
- Still a single LLM call — the code processes the output, not the reasoning

**Visual:** Screenshot of the `extract_json_findings` and `deduplicate_findings` functions — show the code that processes the model's output. Also show the coloured terminal output with severity tags.

---

## Slide 10: Technique 2 — Few-Shot Structured (Results)

**Title:** Few-Shot Results
**Points:**
- Finds more vulnerabilities than zero-shot — the examples guided the model's attention
- Output is now structured and parseable — we can count and compare
- Severity ratings are present and mostly reasonable
- Still misses the subtle stuff — the model is reasoning in a single pass over the entire file
- One-shot reasoning has a ceiling: the model can't focus on everything at once

**Visual:** Screenshot of the terminal output from running `python 2_few_shot_structured.py vulnerable.c`. Highlight the structured output with severity colours.

---

## Slide 11: The Key Insight

**Title:** The Problem with Single-Pass Reasoning
**Points:**
- So far, both techniques ask the model to do everything at once: find, classify, explain, rate
- Human analysts don't work this way — they first map the attack surface, then probe each area
- What if we made the AI work the same way?
- The next two techniques use Python code to decompose the task and iterate

**Visual:** Side-by-side comparison:
- Left: "Single-pass" — one big prompt → one big response
- Right: "Multi-pass" — recon → per-element analysis → deep dive (a simple flowchart)

---

## Slide 12: Technique 3 — Chain-of-Thought (Concept)

**Title:** Technique 3: Chain-of-Thought — "Think Step by Step"
**Points:**
- Decompose the analysis into distinct phases, each building on the last
- Phase 1 — Reconnaissance: "Map the attack surface, don't look for vulns yet"
- Phase 2 — Per-element analysis: loop over EACH element individually and ask "is this one vulnerable?"
- Phase 3 — Deep analysis: loop over EACH finding and ask "is this exploitable? does it chain?"
- The code orchestrates a reasoning pipeline — it parses the LLM's output, splits it into pieces, and feeds each piece back one at a time
- Each LLM call focuses on ONE thing instead of everything

**Visual:** Flowchart showing the three phases with the iteration loops clearly marked:
```
Phase 1: Recon → [list of N elements]
              ↓
Phase 2: for each element → analyse → [findings]
              ↓
Phase 3: for each finding → deep dive → [enriched findings]
              ↓
         Final Report
```

---

## Slide 13: Technique 3 — Chain-of-Thought (Implementation — Parsing)

**Title:** Implementation: Making the LLM's Output Machine-Readable
**Points:**
- Phase 1 asks the model to produce a NUMBERED LIST of attack surface elements
- The code parses this into individual strings using regex
- This is the critical step: the LLM's output becomes the input for a loop
- Each element gets its own focused LLM call in Phase 2

**Visual:** Two screenshots side by side:
- Left: the raw Phase 1 output from the terminal (the numbered list of elements)
- Right: the `parse_attack_surface_elements` function from the code

---

## Slide 14: Technique 3 — Chain-of-Thought (Implementation — Iteration)

**Title:** Implementation: The Reasoning Loop
**Points:**
- Phase 2 iterates: `for each element → send to LLM → collect findings`
- Each prompt contains ONLY that single element + the code — focused attention
- Phase 3 iterates again: `for each finding → send back to LLM for deep analysis`
- The deep analysis checks exploitability and whether the finding chains to other attacks
- The progress output (`[3/15] Analyzing: ...`) shows the loop in action

**Visual:** Screenshot of the terminal during Phase 2 execution — showing the `[1/N] ... [2/N] ...` progress with FOUND/clean results. This is visually compelling and shows the iteration clearly.

---

## Slide 15: Technique 3 — Chain-of-Thought (Results)

**Title:** Chain-of-Thought Results
**Points:**
- Finds significantly more vulnerabilities than few-shot
- The per-element focus helps the model notice things it glossed over in a single pass
- Deep analysis phase catches some false positives and identifies attack chains
- But the model is still limited to what it "knows" — if it doesn't recall the specifics of a vulnerability class, it can't look for it
- This is where RAG comes in

**Visual:** Screenshot of the final report output from `python 3_chain_of_thought.py vulnerable.c`. Annotate any newly-found vulns that the previous techniques missed.

---

## Slide 16: Technique 4 — CoT + RAG (Concept)

**Title:** Technique 4: Chain-of-Thought + RAG — "Think With Expert Knowledge"
**Points:**
- Same iterative approach as Technique 3, but now each element also gets matched to a knowledge base of vulnerability patterns
- The knowledge base contains 20 CWE entries with:
  - What the vulnerability IS
  - Specific detection patterns to look for in code
  - Code examples of the vulnerability
  - How to fix it
- For each attack surface element, we RETRIEVE the most relevant CWEs and include them in the prompt
- The model isn't relying on vague training memory — it has expert reference material right in front of it

**Visual:** Show a single CWE entry from `cwe_entries.json` (e.g., CWE-362 Race Condition) — the detection patterns and examples are the key part. Highlight "this is what gets injected into the prompt."

---

## Slide 17: Technique 4 — CoT + RAG (Implementation — Retrieval)

**Title:** Implementation: Keyword-Based Retrieval
**Points:**
- The `VulnerabilityKnowledgeBase` class indexes all CWE entries by keyword
- For each attack surface element, it scores CWEs by keyword overlap and returns the top matches
- Example: an element mentioning `system()` and `user input` retrieves CWE-78 (Command Injection)
- Example: an element mentioning `strcpy` retrieves CWE-120 (Buffer Overflow)
- This is targeted retrieval — each element gets different CWEs, not the whole database

**Visual:** Screenshot of Phase 2 terminal output showing the per-element retrieval: `[3/15] system() call... Retrieved CWEs: CWE-78, CWE-22 -> FOUND: Command Injection`. The per-element CWE matching is the visual payoff.

---

## Slide 18: Technique 4 — CoT + RAG (Implementation — Verification & Cross-Reference)

**Title:** Implementation: Verification Loop and Attack Chains
**Points:**
- Phase 3 — Verification: each finding is sent back with its specific CWE definition and checked against the detection patterns. False positives get rejected.
- Phase 4 — Cross-reference: pairs of high-severity findings are checked for chains
  - "Can SQL injection + weak hashing = full database compromise?"
  - "Can SSRF + debug endpoint = internal service access?"
- Uses `itertools.combinations` to generate pairs — the code decides which pairs to check
- The model only answers "do these two combine?" — a focused yes/no question

**Visual:** Screenshot of Phase 3 (verification with CONFIRMED/REJECTED labels) and Phase 4 (pairwise chain checking) terminal output

---

## Slide 19: Technique 4 — CoT + RAG (Results)

**Title:** CoT + RAG Results
**Points:**
- Finds the most vulnerabilities of any technique, including subtle ones
- False positives reduced by the verification loop
- Attack chains identified that no other technique found
- The model performed dramatically better — not because it got smarter, but because the code gave it structure and knowledge

**Visual:** Screenshot of the final report from `python 4_cot_rag.py vulnerable.c`. Annotate the vulns and chains that only this technique found.

---

## Slide 20: The Comparison

**Title:** Same Model, Four Techniques

**Points:**
- Show the scoring table filled in with results from all four techniques
- The progression should be clearly visible — each technique finds more than the last
- The biggest jumps: zero-shot → few-shot (structured output), and CoT → CoT+RAG (knowledge)
- The model didn't get smarter — we just got better at using it

**Visual:** The completed scoring table from VULNERABILITY_KEY.md:

| Technique | vulnerable.c (/20) | vulnerable_app.py (/20) | vulnerable_app.php (/25) | Total (/65) |
|-----------|-------------------|------------------------|-------------------------|-------------|
| 1. Zero-Shot | X | X | X | X |
| 2. Few-Shot | X | X | X | X |
| 3. CoT | X | X | X | X |
| 4. CoT + RAG | X | X | X | X |

Consider a bar chart version of this data as a secondary visual.

---

## Slide 21: What This Means for Us

**Title:** Takeaways
**Points:**
- LLMs don't "think" on their own — but you can build thinking into the system around them
- The four levers you can pull:
  1. **Examples** — show it what good output looks like
  2. **Decomposition** — break big tasks into focused subtasks
  3. **Iteration** — parse output and feed it back one piece at a time
  4. **Knowledge** — retrieve relevant context and put it in the prompt
- These techniques apply to any LLM task, not just vuln finding
- A small local model with good engineering can outperform a large model with a lazy prompt

**Visual:** The four levers as a simple stacked diagram or four-column layout

---

## Slide 22: Questions

**Title:** Questions?
**Points:** None — open floor
**Visual:** Contact details / repo link if you're sharing the code

---

## Screenshots Needed (Checklist)

Run each technique against `vulnerable.c` (or whichever file gives the best contrast) and capture:

- [ ] The three code files open in an editor (Slide 3)
- [ ] `python 1_zero_shot.py vulnerable.c` — full terminal output (Slide 7)
- [ ] The prompt text from `1_zero_shot.py` (Slide 5 — can screenshot the code)
- [ ] The `zero_shot_analysis` function in editor (Slide 6)
- [ ] One of the few-shot JSON examples from `2_few_shot_structured.py` in editor (Slide 8)
- [ ] The `extract_json_findings` and `deduplicate_findings` functions in editor (Slide 9)
- [ ] `python 2_few_shot_structured.py vulnerable.c` — terminal output (Slide 10)
- [ ] `python 3_chain_of_thought.py vulnerable.c` — Phase 1 output showing numbered list (Slide 13)
- [ ] The `parse_attack_surface_elements` function in editor (Slide 13)
- [ ] `python 3_chain_of_thought.py vulnerable.c` — Phase 2 output showing `[1/N]` iteration (Slide 14)
- [ ] `python 3_chain_of_thought.py vulnerable.c` — final report (Slide 15)
- [ ] A single CWE entry from `cwe_entries.json` in editor (Slide 16)
- [ ] `python 4_cot_rag.py vulnerable.c` — Phase 2 output showing per-element CWE retrieval (Slide 17)
- [ ] `python 4_cot_rag.py vulnerable.c` — Phase 3 verification + Phase 4 cross-reference output (Slide 18)
- [ ] `python 4_cot_rag.py vulnerable.c` — final report (Slide 19)
- [ ] Completed scoring table (Slide 20 — fill in after running all techniques)
