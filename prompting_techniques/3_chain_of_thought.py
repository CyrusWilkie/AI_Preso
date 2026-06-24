"""
Technique 3: Multi-Pass Chain-of-Thought Analysis
==================================================
Instead of asking the LLM to find everything in one shot, we decompose the
analysis into distinct reasoning phases, each building on the last.

Key improvements over few-shot:
  - FUNCTION EXTRACTION: Code is parsed into individual functions so the LLM
    analyzes small, focused chunks instead of the entire file
  - MULTI-LENS RECONNAISSANCE: 4 focused passes through different security
    lenses to map the attack surface broadly
  - PER-FUNCTION ANALYSIS: Each function is analyzed individually with
    already-found context to prevent duplicates
  - GAP ANALYSIS: A reflection pass identifies missed vulnerability categories
    and scans specifically for those

Phases:
  1. FUNCTION EXTRACTION — Parse the code into individual functions
  2. MULTI-LENS RECON — 4 focused passes to map the attack surface
  3. PER-FUNCTION ANALYSIS — Analyze each function with already-found context
  4. DEEP ANALYSIS — Assess exploitability of each finding
  5. GAP ANALYSIS — Identify and scan for missed vulnerability categories
"""

import ollama
import json
import os
import re
import sys
import time
from collections import Counter

from code_parser import extract_functions
from results_saver import save_results

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

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


def load_code(filepath):
    with open(filepath, "r") as f:
        return f.read()


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


# ─── Phase 3: Per-Function Analysis ─────────────────────────────────────

def analyze_function(func, filename, globals_code, already_found):
    already_found_text = ""
    if already_found:
        found_list = "\n".join(
            f"  - {f.get('vulnerability', '?')} ({f.get('cwe', '?')}) at {f.get('location', '?')}"
            for f in already_found
        )
        already_found_text = f"""
The following vulnerabilities have ALREADY been found — do NOT repeat these.
Look for NEW, DIFFERENT vulnerabilities in this function:
{found_list}
"""

    prompt = f"""You are a security analyst examining a SINGLE function from a larger program.
{already_found_text}
Here is the global context (types, defines, globals):
```
{globals_code}
```

Here is the function to analyze (lines {func['start_line']}-{func['end_line']}):
```
{func['code']}
```

Think step by step:
  Step 1: What does this function do?
  Step 2: What inputs does it receive, and are they validated?
  Step 3: Are there any dangerous operations (buffer writes, system calls, pointer ops)?
  Step 4: Are there memory safety issues (overflow, use-after-free, null deref)?
  Step 5: Are there logic errors (off-by-one, race conditions, missing checks)?

For EACH vulnerability you find, output a JSON object:
```json
{{
  "vulnerability": "name",
  "cwe": "CWE-XXX",
  "severity": "Critical/High/Medium/Low",
  "location": "{func['name']} function, line X",
  "code_snippet": "the specific vulnerable code",
  "reasoning": "your step-by-step analysis"
}}
```

If this function is NOT vulnerable (and findings are not already listed above), output:
```json
{{
  "vulnerability": "None",
  "reasoning": "why this function is safe"
}}
```

Filename: {filename}

Analyze this function for ALL vulnerabilities:"""

    return query_llm(prompt)


# ─── Phase 4: Per-Finding Deep Analysis ─────────────────────────────────

def deep_analysis(func_code, filename, finding):
    finding_json = json.dumps(finding, indent=2)

    prompt = f"""You are a senior penetration tester. A vulnerability has been identified.
Your job is to perform a DEEP ANALYSIS of this single finding.

FINDING:
{finding_json}

RELEVANT CODE:
```
{func_code}
```

Analyze this vulnerability in depth:
  Step 1: Confirm the vulnerability exists by examining the code
  Step 2: Determine if it is actually exploitable (not just theoretically unsafe)
  Step 3: Describe a concrete exploitation scenario — what would an attacker do?
  Step 4: Assess the impact — what does the attacker gain?
  Step 5: Rate the severity considering both likelihood and impact

Output a JSON object:
```json
{{
  "vulnerability": "name",
  "cwe": "CWE-XXX",
  "severity": "Critical/High/Medium/Low",
  "location": "function and line reference",
  "confirmed_exploitable": true/false,
  "exploitation_scenario": "concrete step-by-step attack",
  "impact": "what the attacker gains",
  "remediation": "specific fix"
}}
```

Filename: {filename}

Deep analysis of this finding:"""

    return query_llm(prompt, temperature=0.2)


# ─── Phase 5: Gap Analysis ──────────────────────────────────────────────

def gap_analysis(code, filename, findings):
    found_summary = "\n".join(
        f"  - {f.get('vulnerability', '?')} ({f.get('cwe', '?')}) at {f.get('location', '?')}"
        for f in findings
    )
    found_cwes = set(f.get("cwe", "") for f in findings)
    found_cwes_str = ", ".join(sorted(found_cwes)) if found_cwes else "none"

    prompt = f"""You are a senior security auditor performing a GAP ANALYSIS.

The following vulnerabilities have been found so far in this code:
{found_summary}

CWE categories already covered: {found_cwes_str}

Common vulnerability categories that may be MISSING from the analysis:
- Command injection (CWE-78) — system(), exec(), popen() with user input
- Format string vulnerabilities (CWE-134) — printf/fprintf with user-controlled format
- Use-after-free (CWE-416) — memory used after being freed
- Path traversal (CWE-22) — file paths constructed from user input
- Returning stack pointers (CWE-562) — functions returning addresses of local variables
- NULL pointer dereference (CWE-476) — missing NULL checks after fopen/malloc
- Off-by-one errors (CWE-193) — loop bounds using <= instead of <
- Unsafe signal handlers (CWE-479) — calling non-async-safe functions in handlers

Review the code below and find vulnerabilities that were MISSED in the categories above.
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


# ─── Main Pipeline ──────────────────────────────────────────────────────

def chain_of_thought_analysis(code, filename):
    print(f"\n{'='*70}")
    print(f"CHAIN-OF-THOUGHT ANALYSIS: {filename}")
    print(f"{'='*70}")

    total_start = time.time()
    trace = {"phases": {}}

    # Phase 1: Function extraction
    print(f"\n--- Phase 1: FUNCTION EXTRACTION ---")
    functions = extract_functions(code, filename)
    globals_func = next((f for f in functions if f["name"] in ("__globals__", "__module__")), None)
    globals_code = globals_func["code"] if globals_func else ""
    analysis_funcs = [f for f in functions if f["name"] not in ("__globals__", "__module__")]
    print(f"Extracted {len(analysis_funcs)} functions from {filename}:")
    for f in analysis_funcs:
        lines = f['code'].count('\n') + 1
        print(f"  {f['name']} (lines {f['start_line']}-{f['end_line']}, {lines} lines)")

    trace["phases"]["function_extraction"] = {
        "function_count": len(analysis_funcs),
        "functions": [{"name": f["name"], "start_line": f["start_line"], "end_line": f["end_line"]}
                      for f in analysis_funcs],
    }

    # Phase 2: Multi-lens reconnaissance
    print(f"\n--- Phase 2: MULTI-LENS RECONNAISSANCE ---")
    print(f"Running {len(RECON_LENSES)} focused recon passes...\n")

    trace["phases"]["reconnaissance"] = []
    for lens in RECON_LENSES:
        print(f"  Lens: {lens['name']}...", end=" ", flush=True)
        start = time.time()
        raw = recon_with_lens(code, filename, lens)
        elements = parse_numbered_list(raw)
        elapsed = time.time() - start
        print(f"{len(elements)} elements [{elapsed:.1f}s]")

        trace["phases"]["reconnaissance"].append({
            "lens": lens["name"],
            "raw_response": raw,
            "parsed_elements": elements,
            "elapsed_seconds": elapsed,
        })

    # Phase 3: Per-function analysis
    print(f"\n--- Phase 3: PER-FUNCTION ANALYSIS ---")
    print(f"Analyzing each function individually...\n")

    all_findings = []
    trace["phases"]["function_analysis"] = []
    for i, func in enumerate(analysis_funcs, 1):
        print(f"  [{i}/{len(analysis_funcs)}] {func['name']}()...", end=" ", flush=True)
        start = time.time()
        result = analyze_function(func, filename, globals_code, all_findings)
        func_findings = extract_json_findings(result)
        elapsed = time.time() - start

        vulns = [f for f in func_findings if f.get("vulnerability", "None") != "None"]

        trace["phases"]["function_analysis"].append({
            "function": func["name"],
            "raw_response": result,
            "findings": vulns,
            "already_found_count": len(all_findings),
            "elapsed_seconds": elapsed,
        })

        if vulns:
            new_vulns = deduplicate_findings(all_findings + vulns)[len(all_findings):]
            if new_vulns:
                names = [f.get("vulnerability", "?") for f in new_vulns]
                print(f"FOUND: {', '.join(names)} [{elapsed:.1f}s]")
                all_findings.extend(new_vulns)
            else:
                print(f"duplicate [{elapsed:.1f}s]")
        else:
            print(f"clean [{elapsed:.1f}s]")

    print(f"\n  Phase 3 total: {len(all_findings)} unique vulnerabilities")

    # Phase 4: Deep analysis
    print(f"\n--- Phase 4: PER-FINDING DEEP ANALYSIS ---")
    print(f"Deep-diving into each finding for exploitability...\n")

    deep_findings = []
    trace["phases"]["deep_analysis"] = []
    for i, finding in enumerate(all_findings, 1):
        name = finding.get("vulnerability", "Unknown")
        loc = finding.get("location", "")
        func_name = loc.split(" ")[0].split("(")[0] if loc else ""
        func_obj = next((f for f in analysis_funcs if f["name"] == func_name), None)
        func_code = func_obj["code"] if func_obj else code

        print(f"  [{i}/{len(all_findings)}] Deep analysis: {name}...", end=" ", flush=True)
        start = time.time()
        result = deep_analysis(func_code, filename, finding)
        enriched = extract_json_findings(result)
        elapsed = time.time() - start

        trace["phases"]["deep_analysis"].append({
            "finding": finding,
            "raw_response": result,
            "enriched": enriched[0] if enriched else None,
            "elapsed_seconds": elapsed,
        })

        if enriched:
            f = enriched[0]
            exploitable = f.get("confirmed_exploitable", True)
            sev = f.get("severity", "?")
            print(f"{'EXPLOITABLE' if exploitable else 'theoretical'} [{sev}] [{elapsed:.1f}s]")
            deep_findings.extend(enriched)
        else:
            deep_findings.append(finding)
            print(f"kept original [{elapsed:.1f}s]")

    # Phase 5: Gap analysis
    print(f"\n--- Phase 5: GAP ANALYSIS ---")
    print(f"Looking for missed vulnerability categories...\n")

    start = time.time()
    gap_result = gap_analysis(code, filename, deep_findings)
    gap_findings = extract_json_findings(gap_result)
    gap_vulns = [f for f in gap_findings if f.get("vulnerability", "None") != "None"]
    gap_elapsed = time.time() - start

    gap_new = deduplicate_findings(deep_findings + gap_vulns)[len(deep_findings):]
    if gap_new:
        print(f"  Found {len(gap_new)} missed vulnerabilities [{gap_elapsed:.1f}s]:")
        for f in gap_new:
            print(f"    - {f.get('vulnerability', '?')} ({f.get('cwe', '?')}) at {f.get('location', '?')}")
        deep_findings.extend(gap_new)
    else:
        print(f"  No additional vulnerabilities found [{gap_elapsed:.1f}s]")

    trace["phases"]["gap_analysis"] = {
        "raw_response": gap_result,
        "new_findings": gap_new,
        "elapsed_seconds": gap_elapsed,
    }

    total_elapsed = time.time() - total_start

    # ─── Final Report ────────────────────────────────────────────────────

    deep_findings = deduplicate_findings(deep_findings)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deep_findings.sort(
        key=lambda f: severity_order.get(f.get("severity", "low").lower(), 4)
    )

    print(f"\n{'='*70}")
    print(f"FINAL REPORT: {filename}")
    print(f"{'='*70}")

    for i, f in enumerate(deep_findings, 1):
        sev = f.get("severity", "Unknown")
        name = f.get("vulnerability", "Unknown")
        cwe = f.get("cwe", "N/A")
        loc = f.get("location", "Unknown")
        expl = f.get("exploitation_scenario", f.get("reasoning", ""))[:200]

        sev_colors = {
            "Critical": "\033[91m",
            "High": "\033[93m",
            "Medium": "\033[33m",
            "Low": "\033[92m",
        }
        color = sev_colors.get(sev, "")
        reset = "\033[0m" if color else ""

        print(f"\n  {color}[{sev}]{reset} #{i}: {name} ({cwe})")
        print(f"    Location: {loc}")
        print(f"    {expl}")

    print(f"\n[Total: {total_elapsed:.1f}s — {len(analysis_funcs)} functions, "
          f"{len(RECON_LENSES)} lenses, {len(deep_findings)} findings]")

    severity_counts = Counter(f.get("severity", "Unknown") for f in deep_findings)
    print(f"Severity breakdown: {dict(severity_counts)}")

    trace["final_findings"] = deep_findings
    trace["severity_breakdown"] = dict(severity_counts)
    trace["total_elapsed_seconds"] = total_elapsed
    save_results(MODEL, filename, "Chain-of-Thought", "3_chain_of_thought.json", trace)

    return deep_findings


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

    total_findings = []
    for filename, filepath in files_to_scan.items():
        code = load_code(filepath)
        findings = chain_of_thought_analysis(code, filename)
        total_findings.extend(findings)

    print(f"\n{'='*70}")
    print("CHAIN-OF-THOUGHT SUMMARY")
    print(f"{'='*70}")
    print(f"Total unique vulnerabilities found: {len(total_findings)}")
    print(f"Approach: Function extraction + multi-lens recon + per-function analysis + gap analysis")
    print(f"  Phase 1: Parse code into individual functions")
    print(f"  Phase 2: 4 focused recon lenses (memory, injection, auth, concurrency)")
    print(f"  Phase 3: Per-function analysis with already-found context")
    print(f"  Phase 4: Per-finding deep exploitability analysis")
    print(f"  Phase 5: Gap analysis — find missed vulnerability categories")
    print(f"Model: {MODEL}")


if __name__ == "__main__":
    main()
