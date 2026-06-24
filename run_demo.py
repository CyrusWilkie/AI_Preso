"""
Presentation Runner
===================
Run each prompting technique against a single file to compare results side by side.
Usage:
    python run_demo.py                                      # defaults: vulnerable.c, all techniques
    python run_demo.py vulnerable_app.py                    # all techniques on the Python app
    python run_demo.py vulnerable_app.php 2                 # technique 2 on the PHP app
    python run_demo.py --model mistral:7b                   # override the model
    python run_demo.py vulnerable.c 3 --model llama3.1:8b   # technique 3, specific model
"""

import argparse
import subprocess
import sys
import os

TECHNIQUES = {
    "1": ("Zero-Shot Prompting", "prompting_techniques/1_zero_shot.py"),
    "2": ("Few-Shot Structured", "prompting_techniques/2_few_shot_structured.py"),
    "3": ("Chain-of-Thought (Multi-Pass)", "prompting_techniques/3_chain_of_thought.py"),
    "4": ("CoT + RAG (Full Pipeline)", "prompting_techniques/4_cot_rag.py"),
}

DEFAULT_TARGET = "vulnerable.c"


def main():
    parser = argparse.ArgumentParser(description="Run prompting technique demos")
    parser.add_argument("target", nargs="?", default=DEFAULT_TARGET,
                        help="Target file to analyze (default: vulnerable.c)")
    parser.add_argument("technique", nargs="?", default=None,
                        help="Technique number to run (1-4, default: all)")
    parser.add_argument("--model", "-m", default=None,
                        help="Override the Ollama model (e.g. --model mistral:7b)")
    args = parser.parse_args()

    if args.technique and args.technique in TECHNIQUES:
        techniques_to_run = {args.technique: TECHNIQUES[args.technique]}
    else:
        techniques_to_run = TECHNIQUES

    root = os.path.dirname(os.path.abspath(__file__))

    env = os.environ.copy()
    if args.model:
        env["OLLAMA_MODEL"] = args.model

    model_display = args.model or "qwen2.5-coder:7b (default)"

    print(f"\n{'#'*70}")
    print(f"# LLM VULNERABILITY ANALYSIS — PROMPTING TECHNIQUES COMPARISON")
    print(f"# Target: {args.target}")
    print(f"# Model:  {model_display}")
    print(f"# Techniques: {', '.join(techniques_to_run.keys())}")
    print(f"{'#'*70}")

    for num, (name, script) in techniques_to_run.items():
        print(f"\n\n{'#'*70}")
        print(f"# TECHNIQUE {num}: {name}")
        print(f"{'#'*70}\n")

        script_path = os.path.join(root, script)
        result = subprocess.run(
            [sys.executable, script_path, args.target],
            cwd=os.path.join(root, "prompting_techniques"),
            env=env,
        )

        if result.returncode != 0:
            print(f"\n[ERROR] Technique {num} exited with code {result.returncode}")


if __name__ == "__main__":
    main()
