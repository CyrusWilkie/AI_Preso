"""
Technique 1: Zero-Shot Prompting
================================
The simplest approach - ask the LLM to find vulnerabilities with no examples,
no structure, and no reasoning guidance. Just a raw prompt.

This establishes the baseline for what the model can find "out of the box."
"""

import ollama
import os
import sys
import time

from results_saver import save_results

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")


def load_code(filepath):
    with open(filepath, "r") as f:
        return f.read()


def zero_shot_analysis(code, filename):
    prompt = f"""Analyze the following code for security vulnerabilities. List each vulnerability you find.

Filename: {filename}

```
{code}
```"""

    print(f"\n{'='*70}")
    print(f"ZERO-SHOT ANALYSIS: {filename}")
    print(f"{'='*70}")
    print(f"\nPrompt sent to model (truncated):")
    print(f"  \"{prompt[:120]}...\"")
    print(f"\nWaiting for {MODEL} response...\n")

    start = time.time()

    client = ollama.Client(host=OLLAMA_HOST)
    response = client.generate(
        model=MODEL,
        prompt=prompt,
        stream=False,
        options={"temperature": 0.1, "num_predict": 4096},
    )

    elapsed = time.time() - start
    result = response.response

    print(result)
    print(f"\n[Completed in {elapsed:.1f}s]")

    save_results(MODEL, filename, "Zero-Shot", "1_zero_shot.json", {
        "prompt": prompt,
        "raw_response": result,
        "elapsed_seconds": elapsed,
    })

    return result


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

    all_results = {}
    for filename, filepath in files_to_scan.items():
        code = load_code(filepath)
        result = zero_shot_analysis(code, filename)
        all_results[filename] = result

    print(f"\n{'='*70}")
    print("ZERO-SHOT SUMMARY")
    print(f"{'='*70}")
    print(f"Files analyzed: {len(all_results)}")
    print(f"Approach: Single prompt, no examples, no reasoning structure")
    print(f"Model: {MODEL}")
    print(f"\nThis is our baseline. The model finds the obvious vulnerabilities")
    print(f"but may miss subtle issues, provide shallow analysis, or")
    print(f"fail to categorize findings consistently.")


if __name__ == "__main__":
    main()
