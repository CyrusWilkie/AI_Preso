"""
Shared utility for saving analysis results to disk.
Results are saved as JSON with full reasoning traces and parsed findings.
"""

import json
import os
from datetime import datetime, timezone


def get_results_dir(model, target_filename):
    model_slug = model.replace(":", "_").replace("/", "_")
    results_dir = os.path.join(
        os.path.dirname(__file__), "..", "results", model_slug, target_filename
    )
    os.makedirs(results_dir, exist_ok=True)
    return results_dir


def save_results(model, target_filename, technique_name, output_filename, data):
    results_dir = get_results_dir(model, target_filename)
    filepath = os.path.join(results_dir, output_filename)

    data["metadata"] = {
        "model": model,
        "target": target_filename,
        "technique": technique_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"\n[Results saved to {os.path.relpath(filepath)}]")
