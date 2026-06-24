"""
Technique 2: Few-Shot Prompting with Structured Output
======================================================
We give the LLM concrete examples of what a good vulnerability report looks
like, then ask it to produce findings in that same structured format.

Key improvements over zero-shot:
  - Examples teach the model WHAT we're looking for and HOW to report it
  - Structured JSON output lets us parse, count, and compare results
  - The examples prime the model to look for specific vulnerability classes
    it might otherwise skip

This technique demonstrates that you can meaningfully improve LLM output
by shaping the prompt — no code logic needed beyond parsing the response.
But we DO add code logic here: we validate the JSON output, deduplicate
findings, and produce a severity-sorted report.
"""

import ollama
import json
import os
import sys
import time
from collections import Counter

from results_saver import save_results

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

FEW_SHOT_EXAMPLES = """Here are examples of how to report vulnerabilities:

Example 1:
```json
{
  "vulnerability": "SQL Injection",
  "cwe": "CWE-89",
  "severity": "Critical",
  "location": "login() function, line 45",
  "code_snippet": "query = 'SELECT * FROM users WHERE name = \\'' + username + '\\''",
  "explanation": "User-supplied username is concatenated directly into the SQL query without parameterization, allowing an attacker to inject arbitrary SQL commands.",
  "exploitation": "An attacker could input ' OR '1'='1' -- as the username to bypass authentication.",
  "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))"
}
```

Example 2:
```json
{
  "vulnerability": "Buffer Overflow",
  "cwe": "CWE-120",
  "severity": "Critical",
  "location": "process_input() function, line 23",
  "code_snippet": "strcpy(buffer, user_input);",
  "explanation": "strcpy copies data without bounds checking. If user_input exceeds the buffer size, it overwrites adjacent memory on the stack.",
  "exploitation": "An attacker could supply an oversized input to overwrite the return address and gain code execution.",
  "remediation": "Use strncpy(buffer, user_input, sizeof(buffer) - 1) and ensure null termination."
}
```

Example 3:
```json
{
  "vulnerability": "Hardcoded Credentials",
  "cwe": "CWE-798",
  "severity": "High",
  "location": "Line 5, global constant",
  "code_snippet": "API_KEY = 'sk_live_abc123'",
  "explanation": "An API key is hardcoded in source code. Anyone with access to the source can extract this credential.",
  "exploitation": "An attacker who obtains the source code (via repo access, decompilation, or error disclosure) gains API access.",
  "remediation": "Store secrets in environment variables or a secrets manager, never in source code."
}
```"""


def load_code(filepath):
    with open(filepath, "r") as f:
        return f.read()


def query_llm(prompt):
    client = ollama.Client(host=OLLAMA_HOST)
    response = client.generate(
        model=MODEL,
        prompt=prompt,
        stream=False,
        options={"temperature": 0.1, "num_predict": 8192},
    )
    return response.response


def extract_json_findings(raw_response):
    findings = []

    depth = 0
    start = None
    for i, ch in enumerate(raw_response):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(raw_response[start:i + 1])
                    if "vulnerability" in obj:
                        findings.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None

    return findings


def deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("vulnerability", ""), f.get("location", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def severity_rank(severity):
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return ranks.get(severity.lower(), 5)


def few_shot_analysis(code, filename):
    prompt = f"""You are a security auditor. Analyze the following code for ALL security vulnerabilities.

{FEW_SHOT_EXAMPLES}

Now analyze this code and report EVERY vulnerability you find using the same JSON format.
Output each vulnerability as a separate JSON object. Be thorough - check for injection flaws,
authentication issues, cryptographic weaknesses, access control problems, and memory safety issues.

Filename: {filename}

```
{code}
```

Report each vulnerability as a JSON object:"""

    print(f"\n{'='*70}")
    print(f"FEW-SHOT STRUCTURED ANALYSIS: {filename}")
    print(f"{'='*70}")
    print(f"\nApproach: 3 example vulnerability reports + structured JSON output")
    print(f"Waiting for {MODEL} response...\n")

    start = time.time()
    raw = query_llm(prompt)
    elapsed = time.time() - start

    findings = extract_json_findings(raw)
    findings = deduplicate_findings(findings)
    findings.sort(key=lambda f: severity_rank(f.get("severity", "info")))

    print(f"Found {len(findings)} unique vulnerabilities:\n")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "Unknown")
        name = f.get("vulnerability", "Unknown")
        cwe = f.get("cwe", "N/A")
        loc = f.get("location", "Unknown")
        expl = f.get("explanation", "No explanation provided")

        sev_colors = {
            "Critical": "\033[91m",
            "High": "\033[93m",
            "Medium": "\033[33m",
            "Low": "\033[92m",
        }
        color = sev_colors.get(sev, "")
        reset = "\033[0m" if color else ""

        print(f"  {color}[{sev}]{reset} #{i}: {name} ({cwe})")
        print(f"    Location: {loc}")
        print(f"    {expl[:150]}")
        print()

    print(f"[Completed in {elapsed:.1f}s]")

    severity_counts = Counter(f.get("severity", "Unknown") for f in findings)
    print(f"\nSeverity breakdown: {dict(severity_counts)}")

    save_results(MODEL, filename, "Few-Shot Structured", "2_few_shot_structured.json", {
        "prompt": prompt,
        "raw_response": raw,
        "parsed_findings": extract_json_findings(raw),
        "deduplicated_findings": findings,
        "severity_breakdown": dict(severity_counts),
        "elapsed_seconds": elapsed,
    })

    return findings


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
        findings = few_shot_analysis(code, filename)
        total_findings.extend(findings)

    print(f"\n{'='*70}")
    print("FEW-SHOT SUMMARY")
    print(f"{'='*70}")
    print(f"Total unique vulnerabilities found: {len(total_findings)}")
    print(f"Approach: Few-shot examples + structured JSON + deduplication")
    print(f"Model: {MODEL}")
    print(f"\nImprovement over zero-shot:")
    print(f"  - Structured output lets us parse and count findings")
    print(f"  - Examples teach the model what 'good' reporting looks like")
    print(f"  - Deduplication removes repeated findings")
    print(f"  - But the model still reasons in a single pass — no decomposition")


if __name__ == "__main__":
    main()
