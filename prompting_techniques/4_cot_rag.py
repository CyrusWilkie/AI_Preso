"""
Technique 4: Chain-of-Thought + Retrieval-Augmented Generation (RAG)
====================================================================
The most sophisticated approach. Combines function extraction, multi-lens
recon, and a CWE knowledge base for targeted per-function scanning.

How it works:
  1. FUNCTION EXTRACTION — Parse code into individual functions
  2. MULTI-LENS RECON — 4 focused passes to map the attack surface
  3. CWE SELECTION — Match recon output to knowledge base for relevant CWEs
  4. PER-FUNCTION x PER-CWE SCANNING — For each CWE, check each function
     individually with expert detection patterns (small, focused prompts)
  5. VERIFICATION — Each finding is verified against its CWE definition
  6. GAP ANALYSIS — Reflection pass to find missed categories
  7. CROSS-REFERENCE — Pairs of different vuln types checked for chains
"""

import ollama
import json
import os
import sys
import re
import time
from collections import Counter
from itertools import combinations

from code_parser import extract_functions
from results_saver import save_results

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
KNOWLEDGE_BASE_PATH = "../knowledge_base/cwe_entries.json"

RECON_LENSES = [
    {
        "name": "Memory Safety",
        "focus": """Focus ONLY on memory safety concerns. Look for:
- Buffer operations (strcpy, sprintf, gets, read, memcpy, strcat)
- Heap allocations and frees (malloc, free, realloc) — track what happens to pointers AFTER free
- Stack-allocated buffers that might be returned or escape their scope
- Array index operations that might go out of bounds (off-by-one, missing upper/lower checks)
- Pointer arithmetic and casting""",
    },
    {
        "name": "Input Validation & Injection",
        "focus": """Focus ONLY on how external input flows into dangerous operations. Look for:
- User input sources (stdin, file reads, network reads, command-line args, environment)
- Dangerous sinks where input ends up (system/exec calls, SQL, file paths, format strings)
- Whether input is validated, sanitized, or escaped before reaching each sink
- String formatting operations where user data could be interpreted as format specifiers""",
    },
    {
        "name": "Auth, Secrets & Crypto",
        "focus": """Focus ONLY on authentication, authorization, secrets, and cryptography. Look for:
- Hardcoded passwords, API keys, connection strings, encryption keys
- How passwords are stored and compared (plaintext vs hashed, salt usage)
- Token generation — is it predictable or cryptographically random?
- Authorization checks — are there operations that should require permission but don't?
- Sensitive data exposure (debug output, logging of passwords/tokens, info leaks)""",
    },
    {
        "name": "Concurrency, Error Handling & Resources",
        "focus": """Focus ONLY on concurrency, error handling, and resource management. Look for:
- Race conditions: check-then-act patterns without locking, especially with shared state
- Signal handlers calling non-async-signal-safe functions (printf, malloc, fclose, exit)
- Missing NULL checks after operations that can fail (fopen, malloc)
- Resource leaks: opened files never closed, allocated memory never freed
- Integer overflow in arithmetic operations (especially multiplication)
- Off-by-one errors in loop bounds (< vs <=)""",
    },
]


# ─── Knowledge Base (RAG) ───────────────────────────────────────────────

class VulnerabilityKnowledgeBase:
    def __init__(self, kb_path):
        with open(kb_path, "r") as f:
            self.entries = json.load(f)

        self.keyword_index = {}
        for entry in self.entries:
            keywords = set()
            keywords.update(self._extract_keywords(entry["name"]))
            keywords.update(self._extract_keywords(entry["description"]))
            for pattern in entry.get("detection_patterns", []):
                keywords.update(self._extract_keywords(pattern))
            for example in entry.get("examples", []):
                keywords.update(self._extract_keywords(example))
            for kw in keywords:
                self.keyword_index.setdefault(kw, []).append(entry)

    def _extract_keywords(self, text):
        text = text.lower()
        words = re.findall(r'[a-z_]+(?:\(\))?', text)
        important = [
            w for w in words
            if len(w) > 3 or w.endswith("()") or w in ("xss", "sql", "rce", "ssrf", "csrf", "xxe")
        ]
        return set(important)

    def retrieve(self, query_text, max_results=12):
        query_keywords = self._extract_keywords(query_text)
        scores = {}
        for kw in query_keywords:
            for entry in self.keyword_index.get(kw, []):
                cwe_id = entry["id"]
                scores[cwe_id] = scores.get(cwe_id, 0) + 1

        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_ids = [cwe_id for cwe_id, _ in ranked[:max_results]]
        return [e for e in self.entries if e["id"] in top_ids]

    def get_by_id(self, cwe_id):
        for entry in self.entries:
            if entry["id"] == cwe_id:
                return entry
        return None

    def format_entry(self, entry):
        lines = [
            f"### {entry['id']}: {entry['name']} [{entry['severity']}]",
            f"Description: {entry['description']}",
            "Detection patterns:",
        ]
        for p in entry.get("detection_patterns", []):
            lines.append(f"  - {p}")
        lines.append("Code examples of this vulnerability:")
        for ex in entry.get("examples", []):
            lines.append(f"  - {ex}")
        lines.append(f"Remediation: {entry.get('remediation', 'N/A')}")
        return "\n".join(lines)


# ─── LLM Interface ──────────────────────────────────────────────────────

def query_llm(prompt, temperature=0.1):
    client = ollama.Client(host=OLLAMA_HOST)
    response = client.generate(
        model=MODEL,
        prompt=prompt,
        stream=False,
        options={"temperature": temperature, "num_predict": 4096},
    )
    return response.response


def extract_json_findings(text):
    findings = []
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(text[start:i + 1])
                    if "vulnerability" in obj:
                        findings.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None
    return findings


def load_code(filepath):
    with open(filepath, "r") as f:
        return f.read()


def parse_numbered_list(text):
    elements = []
    for line in text.split("\n"):
        line = line.strip()
        match = re.match(r'^\d+[\.\)]\s*(.+)', line)
        if match:
            element = match.group(1).strip()
            if element and len(element) > 10:
                elements.append(element)
    return elements


def deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        vuln = f.get("vulnerability", "").lower()
        loc = f.get("location", "").lower()[:30]
        cwe = f.get("cwe", "").lower()
        key = (vuln, loc)
        alt_key = (cwe, loc)
        if key not in seen and alt_key not in seen:
            seen.add(key)
            seen.add(alt_key)
            unique.append(f)
    return unique


# ─── Phase 2: Multi-Lens Reconnaissance ─────────────────────────────────

def recon_with_lens(code, filename, lens):
    prompt = f"""You are a security analyst performing reconnaissance on source code.
Your task is to MAP THE ATTACK SURFACE through one specific security lens.
Do NOT look for vulnerabilities yet — just identify the relevant code locations.

SECURITY LENS: {lens['name']}
{lens['focus']}

For the code below, produce a NUMBERED LIST of every code location relevant to
this security lens. Each element should be ONE specific point in the code.

Format each element EXACTLY like this:
1. description — function_name (line reference if possible)

Be specific and concrete. Reference actual function names, variable names,
and line numbers from the code.

Filename: {filename}

```
{code}
```

Numbered list of relevant code locations:"""

    return query_llm(prompt)


# ─── Phase 4: Per-Function x Per-CWE Scanning ───────────────────────────

def scan_function_for_cwe(func, globals_code, cwe_entry, kb):
    cwe_context = kb.format_entry(cwe_entry)

    prompt = f"""You are a security analyst checking a SINGLE function for ONE specific
vulnerability type. You have expert knowledge about this vulnerability.

VULNERABILITY TO CHECK FOR:
{cwe_context}

GLOBAL CONTEXT (types, defines, globals):
```
{globals_code}
```

FUNCTION TO CHECK (lines {func['start_line']}-{func['end_line']}):
```
{func['code']}
```

Check this function against the detection patterns above:
  Step 1: Does this function contain any of the DETECTION PATTERNS listed?
  Step 2: Compare the code to the EXAMPLES — is the pattern similar?
  Step 3: If it matches, is the data flow actually exploitable?

If this function DOES contain {cwe_entry['id']} ({cwe_entry['name']}), output:
```json
{{
  "vulnerability": "{cwe_entry['name']}",
  "cwe": "{cwe_entry['id']}",
  "severity": "{cwe_entry['severity']}",
  "location": "{func['name']} function, line X",
  "code_snippet": "the specific vulnerable code",
  "matched_pattern": "which detection pattern matched",
  "reasoning": "step-by-step analysis",
  "remediation": "specific fix from the knowledge base"
}}
```

If this function does NOT contain this vulnerability, output:
```json
{{
  "vulnerability": "None",
  "reasoning": "why this pattern does not apply here"
}}
```

Analyze:"""

    return query_llm(prompt)


# ─── Phase 5: Verification ──────────────────────────────────────────────

def verify_finding(func_code, finding, kb):
    cwe_id = finding.get("cwe", "")
    cwe_entry = kb.get_by_id(cwe_id)

    if not cwe_entry:
        finding["confidence"] = "unverified"
        return finding

    prompt = f"""You are verifying a vulnerability finding against its CWE definition.

FINDING:
{json.dumps(finding, indent=2)}

CWE DEFINITION:
{kb.format_entry(cwe_entry)}

RELEVANT CODE:
```
{func_code}
```

Verify:
  1. Does the code ACTUALLY contain the pattern described?
  2. Does it match at least one DETECTION PATTERN from the CWE?
  3. Is this actually exploitable, or is it a false positive?

Output:
```json
{{
  "vulnerability": "name",
  "cwe": "{cwe_id}",
  "verified": true/false,
  "confidence": "high/medium/low",
  "severity": "adjusted if needed",
  "location": "location",
  "explanation": "verified explanation",
  "exploitation_scenario": "concrete attack steps",
  "remediation": "from CWE knowledge base"
}}
```

Verify:"""

    result = query_llm(prompt)
    verified = extract_json_findings(result)
    if verified:
        return verified[0]

    finding["confidence"] = "unverified"
    return finding


# ─── Phase 6: Gap Analysis ──────────────────────────────────────────────

def gap_analysis(code, filename, findings, kb):
    found_summary = "\n".join(
        f"  - {f.get('vulnerability', '?')} ({f.get('cwe', '?')}) at {f.get('location', '?')}"
        for f in findings
    )
    found_cwes = set(f.get("cwe", "") for f in findings)
    found_cwes_str = ", ".join(sorted(found_cwes)) if found_cwes else "none"

    missed_cwes = [e for e in kb.entries if e["id"] not in found_cwes]
    missed_hints = "\n".join(
        f"  - {e['id']}: {e['name']} — look for: {e['detection_patterns'][0]}"
        for e in missed_cwes[:8]
        if e.get("detection_patterns")
    )

    prompt = f"""You are a senior security auditor performing a GAP ANALYSIS.

The following vulnerabilities have been found so far:
{found_summary}

CWE categories already covered: {found_cwes_str}

The following CWE categories have NOT been checked yet. For each one, a
detection pattern is provided. Check the code specifically for these:
{missed_hints}

Review the code below and find vulnerabilities in the UNCHECKED categories.
Only report vulnerabilities that are NOT already in the found list.

For each NEW vulnerability, output a JSON object:
```json
{{
  "vulnerability": "name",
  "cwe": "CWE-XXX",
  "severity": "Critical/High/Medium/Low",
  "location": "function name and line reference",
  "code_snippet": "the specific vulnerable code",
  "reasoning": "why this was missed and why it matters"
}}
```

Filename: {filename}

```
{code}
```

What vulnerabilities were missed?"""

    return query_llm(prompt, temperature=0.2)


# ─── Phase 7: Cross-Reference ───────────────────────────────────────────

def check_chain(finding_a, finding_b):
    prompt = f"""Can these two DIFFERENT vulnerability types be chained for greater impact?

FINDING A:
  {finding_a.get('vulnerability', '?')} ({finding_a.get('cwe', '?')}) at {finding_a.get('location', '?')}
  {finding_a.get('explanation', finding_a.get('reasoning', ''))[:200]}

FINDING B:
  {finding_b.get('vulnerability', '?')} ({finding_b.get('cwe', '?')}) at {finding_b.get('location', '?')}
  {finding_b.get('explanation', finding_b.get('reasoning', ''))[:200]}

Think step by step:
  Step 1: What does exploiting Finding A give the attacker?
  Step 2: Does that help exploit Finding B?
  Step 3: What is the combined impact?

If there IS a chain, output:
```json
{{
  "vulnerability": "Chain: {finding_a.get('vulnerability', '?')} + {finding_b.get('vulnerability', '?')}",
  "cwe": "CWE of the primary link",
  "severity": "Critical or High",
  "location": "multiple",
  "chain_components": ["{finding_a.get('vulnerability', '?')}", "{finding_b.get('vulnerability', '?')}"],
  "exploitation_scenario": "step-by-step chained attack",
  "explanation": "how these combine",
  "remediation": "how to break the chain"
}}
```

If NO chain, output:
```json
{{
  "vulnerability": "None"
}}
```

Analyze:"""

    return query_llm(prompt, temperature=0.2)


# ─── Main Pipeline ──────────────────────────────────────────────────────

def cot_rag_analysis(code, filename, kb):
    print(f"\n{'='*70}")
    print(f"CHAIN-OF-THOUGHT + RAG ANALYSIS: {filename}")
    print(f"{'='*70}")

    total_start = time.time()
    trace = {"phases": {}}

    # Phase 1: Function extraction
    print(f"\n--- Phase 1: FUNCTION EXTRACTION ---")
    functions = extract_functions(code, filename)
    globals_func = next((f for f in functions if f["name"] in ("__globals__", "__module__")), None)
    globals_code = globals_func["code"] if globals_func else ""
    analysis_funcs = [f for f in functions if f["name"] not in ("__globals__", "__module__")]
    print(f"Extracted {len(analysis_funcs)} functions from {filename}")

    trace["phases"]["function_extraction"] = {
        "function_count": len(analysis_funcs),
        "functions": [{"name": f["name"], "start_line": f["start_line"], "end_line": f["end_line"]}
                      for f in analysis_funcs],
    }

    # Phase 2: Multi-lens reconnaissance
    print(f"\n--- Phase 2: MULTI-LENS RECONNAISSANCE ---\n")

    all_recon_text = []
    trace["phases"]["reconnaissance"] = []
    for lens in RECON_LENSES:
        print(f"  Lens: {lens['name']}...", end=" ", flush=True)
        start = time.time()
        raw = recon_with_lens(code, filename, lens)
        elements = parse_numbered_list(raw)
        elapsed = time.time() - start
        print(f"{len(elements)} elements [{elapsed:.1f}s]")
        all_recon_text.append(raw)

        trace["phases"]["reconnaissance"].append({
            "lens": lens["name"],
            "raw_response": raw,
            "parsed_elements": elements,
            "elapsed_seconds": elapsed,
        })

    # Phase 3: CWE selection
    print(f"\n--- Phase 3: CWE SELECTION (RAG) ---")
    combined_recon = "\n\n".join(all_recon_text)
    relevant_cwes = kb.retrieve(combined_recon + "\n" + code[:2000], max_results=12)
    print(f"  Selected {len(relevant_cwes)} CWEs:")
    for entry in relevant_cwes:
        print(f"    - {entry['id']}: {entry['name']} [{entry['severity']}]")

    trace["phases"]["cwe_selection"] = {
        "selected_cwes": [{"id": e["id"], "name": e["name"]} for e in relevant_cwes],
    }

    # Phase 4: Per-function × per-CWE scanning
    print(f"\n--- Phase 4: PER-FUNCTION × PER-CWE SCANNING ---")
    print(f"Scanning {len(analysis_funcs)} functions × {len(relevant_cwes)} CWEs...\n")

    all_findings = []
    trace["phases"]["cwe_scanning"] = []
    for cwe_entry in relevant_cwes:
        cwe_id = cwe_entry["id"]
        cwe_name = cwe_entry["name"]
        print(f"  {cwe_id} ({cwe_name}):")

        cwe_scan_results = []
        for func in analysis_funcs:
            print(f"    {func['name']}()...", end=" ", flush=True)
            start = time.time()
            result = scan_function_for_cwe(func, globals_code, cwe_entry, kb)
            scan_findings = extract_json_findings(result)
            elapsed = time.time() - start

            vulns = [f for f in scan_findings if f.get("vulnerability", "None") != "None"]

            cwe_scan_results.append({
                "function": func["name"],
                "raw_response": result,
                "findings": vulns,
                "elapsed_seconds": elapsed,
            })

            if vulns:
                new = deduplicate_findings(all_findings + vulns)[len(all_findings):]
                if new:
                    print(f"FOUND [{elapsed:.1f}s]")
                    all_findings.extend(new)
                else:
                    print(f"dup [{elapsed:.1f}s]")
            else:
                print(f"- [{elapsed:.1f}s]")

        trace["phases"]["cwe_scanning"].append({
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "function_results": cwe_scan_results,
        })

    print(f"\n  Phase 4 total: {len(all_findings)} unique findings")

    # Phase 5: Verification
    print(f"\n--- Phase 5: PER-FINDING VERIFICATION ---\n")

    verified_findings = []
    trace["phases"]["verification"] = []
    for i, finding in enumerate(all_findings, 1):
        name = finding.get("vulnerability", "Unknown")
        cwe = finding.get("cwe", "?")
        loc = finding.get("location", "")
        func_name = loc.split(" ")[0].split("(")[0] if loc else ""
        func_obj = next((f for f in analysis_funcs if f["name"] == func_name), None)
        func_code = func_obj["code"] if func_obj else code[:500]

        print(f"  [{i}/{len(all_findings)}] {name} ({cwe})...", end=" ", flush=True)
        start = time.time()
        verified = verify_finding(func_code, finding, kb)
        elapsed = time.time() - start

        is_verified = verified.get("verified", True)
        confidence = verified.get("confidence", "?")

        trace["phases"]["verification"].append({
            "original_finding": finding,
            "verified_result": verified,
            "accepted": bool(is_verified or is_verified == "true"),
            "elapsed_seconds": elapsed,
        })

        if is_verified or is_verified == "true":
            print(f"CONFIRMED [{confidence}] [{elapsed:.1f}s]")
            verified_findings.append(verified)
        else:
            print(f"REJECTED [{elapsed:.1f}s]")

    rejected = len(all_findings) - len(verified_findings)
    print(f"\n  Verified: {len(verified_findings)}, Rejected: {rejected}")

    # Phase 6: Gap analysis
    print(f"\n--- Phase 6: GAP ANALYSIS ---\n")

    start = time.time()
    gap_result = gap_analysis(code, filename, verified_findings, kb)
    gap_findings = extract_json_findings(gap_result)
    gap_vulns = [f for f in gap_findings if f.get("vulnerability", "None") != "None"]
    gap_elapsed = time.time() - start

    gap_new = deduplicate_findings(verified_findings + gap_vulns)[len(verified_findings):]
    if gap_new:
        print(f"  Found {len(gap_new)} missed vulnerabilities [{gap_elapsed:.1f}s]:")
        for f in gap_new:
            print(f"    - {f.get('vulnerability', '?')} ({f.get('cwe', '?')}) at {f.get('location', '?')}")
        verified_findings.extend(gap_new)
    else:
        print(f"  No additional vulnerabilities found [{gap_elapsed:.1f}s]")

    trace["phases"]["gap_analysis"] = {
        "raw_response": gap_result,
        "new_findings": gap_new,
        "elapsed_seconds": gap_elapsed,
    }

    # Phase 7: Cross-reference — one representative per CWE type
    print(f"\n--- Phase 7: CROSS-REFERENCE ---")

    high_sev = [f for f in verified_findings
                if f.get("severity", "").lower() in ("critical", "high")]

    cwe_representatives = {}
    for f in high_sev:
        cwe = f.get("cwe", "")
        if cwe and cwe not in cwe_representatives:
            cwe_representatives[cwe] = f
    reps = list(cwe_representatives.values())

    pairs = list(combinations(reps, 2))
    print(f"  {len(high_sev)} high/critical findings across {len(reps)} distinct CWE types")
    print(f"  Checking {len(pairs)} cross-type pairs...\n")

    chain_findings = []
    trace["phases"]["cross_reference"] = []
    for i, (fa, fb) in enumerate(pairs, 1):
        na = fa.get("vulnerability", "?")[:25]
        nb = fb.get("vulnerability", "?")[:25]
        print(f"  [{i}/{len(pairs)}] {na} + {nb}...", end=" ", flush=True)

        start = time.time()
        result = check_chain(fa, fb)
        chain_vulns = extract_json_findings(result)
        elapsed = time.time() - start

        chains = [c for c in chain_vulns if c.get("vulnerability", "None") != "None"]

        trace["phases"]["cross_reference"].append({
            "finding_a": na, "finding_b": nb,
            "raw_response": result, "chains_found": chains,
            "elapsed_seconds": elapsed,
        })

        if chains:
            print(f"CHAIN [{elapsed:.1f}s]")
            chain_findings.extend(chains)
        else:
            print(f"no [{elapsed:.1f}s]")

    total_elapsed = time.time() - total_start

    # ─── Final Report ────────────────────────────────────────────────────

    final_findings = verified_findings + chain_findings
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    final_findings.sort(
        key=lambda f: severity_order.get(f.get("severity", "low").lower(), 4)
    )

    print(f"\n{'='*70}")
    print(f"FINAL REPORT: {filename}")
    print(f"{'='*70}")

    for i, f in enumerate(final_findings, 1):
        sev = f.get("severity", "Unknown")
        name = f.get("vulnerability", "Unknown")
        cwe = f.get("cwe", "N/A")
        loc = f.get("location", "Unknown")
        expl = f.get("explanation", f.get("reasoning", ""))[:250]
        confidence = f.get("confidence", "")
        chain = f.get("chain_components", [])

        sev_colors = {"Critical": "\033[91m", "High": "\033[93m",
                      "Medium": "\033[33m", "Low": "\033[92m"}
        color = sev_colors.get(sev, "")
        reset = "\033[0m" if color else ""

        label = f"#{i}"
        if chain:
            label += " [CHAIN]"
        if confidence:
            label += f" [{confidence}]"

        print(f"\n  {color}[{sev}]{reset} {label}: {name} ({cwe})")
        print(f"    Location: {loc}")
        print(f"    {expl}")

    print(f"\n[Total: {total_elapsed:.1f}s — {len(analysis_funcs)} functions × "
          f"{len(relevant_cwes)} CWEs, {len(verified_findings)} verified, "
          f"{len(chain_findings)} chains]")

    severity_counts = Counter(f.get("severity", "Unknown") for f in final_findings)
    print(f"Severity breakdown: {dict(severity_counts)}")

    trace["final_findings"] = final_findings
    trace["verified_findings"] = verified_findings
    trace["chain_findings"] = chain_findings
    trace["severity_breakdown"] = dict(severity_counts)
    trace["total_elapsed_seconds"] = total_elapsed
    save_results(MODEL, filename, "CoT + RAG", "4_cot_rag.json", trace)

    return final_findings


def main():
    code_files = {
        "vulnerable.c": "../vulnerable_code/vulnerable.c",
        "vulnerable_app.py": "../vulnerable_code/vulnerable_app.py",
        "vulnerable_app.php": "../vulnerable_code/vulnerable_app.php",
    }

    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target and target in code_files:
        files_to_scan = {target: code_files[target]}
    else:
        files_to_scan = code_files

    print(f"Loading CWE knowledge base from {KNOWLEDGE_BASE_PATH}...")
    kb = VulnerabilityKnowledgeBase(KNOWLEDGE_BASE_PATH)
    print(f"Loaded {len(kb.entries)} CWE entries with "
          f"{len(kb.keyword_index)} index terms")

    total_findings = []
    for filename, filepath in files_to_scan.items():
        code = load_code(filepath)
        findings = cot_rag_analysis(code, filename, kb)
        total_findings.extend(findings)

    print(f"\n{'='*70}")
    print("CHAIN-OF-THOUGHT + RAG SUMMARY")
    print(f"{'='*70}")
    print(f"Total findings: {len(total_findings)}")
    print(f"Approach: Function extraction + multi-lens recon + per-function×per-CWE + gap analysis")
    print(f"  Phase 1: Parse code into individual functions")
    print(f"  Phase 2: 4 focused recon lenses")
    print(f"  Phase 3: CWE selection from knowledge base")
    print(f"  Phase 4: Per-function × per-CWE scanning (focused prompts)")
    print(f"  Phase 5: Per-finding verification against CWE definitions")
    print(f"  Phase 6: Gap analysis — find missed categories")
    print(f"  Phase 7: Cross-reference for attack chains")
    print(f"Model: {MODEL}")
    print(f"Knowledge base: {len(kb.entries)} CWE entries")


if __name__ == "__main__":
    main()
