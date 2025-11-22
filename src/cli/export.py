#!/usr/bin/env python3

import json
import os
import sys


def _split_outside_quotes(command: str, separators):
    """
    Split a command string on the provided separators, ignoring any separators
    that appear inside single- or double-quoted strings.
    """
    if not command:
        return []

    # Longer separators should be matched first (e.g. "&&" before ";")
    sorted_separators = sorted(separators, key=len, reverse=True)
    parts = []
    last_index = 0
    i = 0
    in_single = False
    in_double = False
    escape_next = False

    while i < len(command):
        char = command[i]

        if escape_next:
            escape_next = False
        elif not in_single and char == '\\':
            # Outside of single quotes, a backslash escapes the next character.
            escape_next = True
        elif char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            matched_sep = next(
                (sep for sep in sorted_separators if command.startswith(sep, i)),
                None,
            )
            if matched_sep:
                parts.append(command[last_index:i])
                parts.append(matched_sep)
                i += len(matched_sep)
                last_index = i
                continue

        i += 1

    parts.append(command[last_index:])
    return [part for part in parts if part]

def _normalize_newlines(value: str) -> str:
    """Normalize CRLF/CR line endings to LF."""
    return value.replace('\r\n', '\n').replace('\r', '\n')


def expand_command(command: str, system: str) -> str:
    """
    Expand a one-liner command into a multi-line script for readability.
    This is a simplistic approach, inserting line breaks after logical separators.
    """
    separators = [';'] if system.lower() == "windows" else ['&&', '||', ';']
    parts = _split_outside_quotes(command, separators) if command else []

    lines = []
    current_line = ""
    attach_separator = system.lower() != "windows"

    for part in parts or [command]:
        if part in separators:
            if attach_separator:
                current_line += part + ' '
                lines.append(current_line.strip())
                current_line = ""
            else:
                if current_line.strip():
                    lines.append(current_line.strip())
                current_line = ""
        else:
            current_line += part

    if current_line.strip():
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

                # The "target" is the CLI command (possibly multi-line)
                raw_target = block_data.get("target", "")
                if not isinstance(raw_target, str):
                    raw_target = str(raw_target)

                if not raw_target.strip():
                    continue  # no command to write

                target_str = _normalize_newlines(raw_target)
                has_explicit_formatting = "\n" in target_str

                if has_explicit_formatting:
                    script_body = target_str
                else:
                    # Single-line command: expand for readability
                    script_body = expand_command(target_str.strip(), sys_val)

                script_body = _normalize_newlines(script_body)
                if script_body and not script_body.endswith("\n"):
                    script_body += "\n"

                # Build final file path, e.g. "threatmodel-Windows/no-EPP/implementation.ps"
                out_file_name = f"{block_name}{ext}"
                out_file_path = os.path.join(subfolder_path, out_file_name)

                # Write the command
                with open(out_file_path, 'w', encoding='utf-8') as out_f:
                    if ext == ".sh" and not script_body.startswith("#!"):
                        out_f.write("#!/bin/bash\n\n")

                    out_f.write(script_body)

                print(f"Created: {out_file_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_cli.py <threat_model.json>")
        sys.exit(1)

    main(sys.argv[1])
