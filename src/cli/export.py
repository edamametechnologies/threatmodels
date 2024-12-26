#!/usr/bin/env python3

import json
import os
import sys
import re

def expand_command(command: str, system: str) -> str:
    """
    Expand a one-liner command into a multi-line script for readability.
    This is a simplistic approach, inserting line breaks after logical separators.
    """
    if system.lower() == "windows":
        # For PowerShell, split at semicolons
        lines = command.split(';')
    else:
        # For Unix shells, split at logical separators
        # This includes &&, ||, ;, and { }
        # Be careful with curly braces to not break blocks
        # A more sophisticated parser might be needed for complex commands
        separators = ['&&', '||', ';']
        pattern = '|'.join(map(re.escape, separators))
        parts = re.split(f'({pattern})', command)
        lines = []
        current_line = ""
        for part in parts:
            if part in separators:
                current_line += part + ' '
                lines.append(current_line.strip())
                current_line = ""
            else:
                current_line += part
        if current_line:
            lines.append(current_line.strip())
    # Join with newlines and proper indentation
    return "\n".join(line.strip() for line in lines if line.strip())

def main(json_file_path):
    """
    Example usage:
      python extract_cli.py threat_model_Windows.json

    It will create a folder named after the top-level "name" in your JSON
    (e.g. "threatmodel-Windows") and then for each metric, a subfolder
    named e.g. "no-EPP". Inside that subfolder, you will have up to three files:

      - implementation.ps or .sh
      - remediation.ps or .sh
      - rollback.ps or .sh

    depending on which blocks have class="cli" and system="Windows" or not.
    """
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    model_name = data.get("name", "unknown-model")

    # Make sure the top-level folder exists
    os.makedirs(model_name, exist_ok=True)

    metrics = data.get("metrics", [])

    for metric in metrics:
        metric_name = metric.get("name", "unnamed-metric")
        # Create subfolder for this metric inside the model folder
        subfolder_path = os.path.join(model_name, metric_name)
        os.makedirs(subfolder_path, exist_ok=True)

        # We'll check each of the blocks we care about
        for block_name in ["implementation", "remediation", "rollback"]:
            block_data = metric.get(block_name, {})
            # We only care if "class" == "cli"
            if block_data.get("class") == "cli":
                # Decide file extension: .ps if Windows, else .sh
                sys_val = block_data.get("system", "").lower()
                if "windows" in sys_val:
                    ext = ".ps"
                else:
                    ext = ".sh"

                # The "target" is the CLI command
                target_str = block_data.get("target", "").strip()
                if not target_str:
                    continue  # no command to write

                # Build final file path, e.g. "threatmodel-Windows/no-EPP/implementation.ps"
                out_file_name = f"{block_name}{ext}"
                out_file_path = os.path.join(subfolder_path, out_file_name)

                # Write the command
                with open(out_file_path, 'w', encoding='utf-8') as out_f:
                    if ext == ".sh":
                        out_f.write("#!/bin/bash\n\n")

                    out_f.write(expand_command(target_str, sys_val) + "\n")

                print(f"Created: {out_file_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_cli.py <threat_model.json>")
        sys.exit(1)

    main(sys.argv[1])
