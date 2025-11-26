#!/usr/bin/env python3

import json
import os
import sys

from typing import List

VALID_BLOCKS = ["implementation", "remediation", "rollback"]


def _normalize_newlines(value: str) -> str:
    """Normalize CRLF/CR line endings to LF for consistent storage."""
    return value.replace('\r\n', '\n').replace('\r', '\n')


def _read_script_file(path: str) -> str:
    """
    Read a CLI script file preserving indentation, comments, and blank lines.
    """
    with open(path, 'r', encoding='utf-8') as f_in:
        return f_in.read()


def _escape_sh_line(line: str) -> str:
    """Escape single quotes for safe embedding inside a shell '...'
    argument."""
    return line.replace("'", "'\"'\"'")


def _strip_comments(lines: List[str], comment_prefix: str) -> List[str]:
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(comment_prefix):
            continue
        cleaned.append(stripped)
    return cleaned


def _encode_shell_script(lines: List[str], shell: str = "/bin/bash") -> str:
    """
    Encode a shell script as a portable one-liner that reconstructs the
    original content via printf piped into the target shell. This preserves comments,
    heredocs, arrays, etc. while keeping JSON targets single-line for legacy
    clients.
    """
    if not lines:
        return ""

    escaped = ["'{}'".format(_escape_sh_line(line)) for line in lines]
    args = " ".join(escaped) if escaped else "''"
    return f"printf '%s\\n' {args} | {shell}"


def _encode_powershell_script(lines: List[str]) -> str:
    """
    Encode a PowerShell script as a one-liner by building an array of lines,
    joining with `n newlines, and piping into Invoke-Expression.
    """
    if not lines:
        return ""

    escaped = ["'{}'".format(line.replace("'", "''")) for line in lines]
    joined = ", ".join(escaped)
    return (
        "$__EDAMAME_LINES = @(" + joined + "); "
        "$__EDAMAME_SCRIPT = $__EDAMAME_LINES -join \"`n\"; "
        "Invoke-Expression $__EDAMAME_SCRIPT"
    )


def _prepare_target_content(content: str, extension: str, shell: str = "/bin/bash") -> str:
    """
    Prepare script content for JSON storage:
      * normalize newlines
      * remove shebang/header for shell scripts
      * trim trailing newlines
      * encode the script as a backwards-compatible one-liner that rebuilds
        the original multiline body right before execution.
    """
    normalized = _normalize_newlines(content)

    if extension.lower() == ".sh" and normalized.startswith("#!"):
        # Drop the shebang line and any immediate blank line after it
        _, _, remainder = normalized.partition("\n")
        normalized = remainder.lstrip("\n")

    normalized = normalized.rstrip("\n")
    lines = normalized.split("\n") if normalized else []

    if extension.lower() == ".sh":
        return _encode_shell_script(lines, shell=shell)

    if extension.lower() == ".ps":
        return _encode_powershell_script(lines)

    # Fallback: simple whitespace-collapsed command
    return " ".join(line.strip() for line in lines if line.strip())

def import_cli_scripts(json_file_path):
    """
    Reads the original JSON (e.g. threat_model_Windows.json),
    scans the folder named after data["name"] (the model),
    then for each <metric_name> subfolder, picks up .ps or .sh files
    named implementation.{ps,sh}, remediation.{ps,sh}, rollback.{ps,sh},
    and merges them back into the JSON's 'target' with proper escaping.
    """
    # 1) Load the original JSON
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    model_name = data.get("name", "unknown-model")

    # The top-level directory where scripts are stored
    # must match the model's "name" exactly
    if not os.path.isdir(model_name):
        print(f"[ERROR] The folder '{model_name}' does not exist.")
        print("Make sure your script folder matches data['name'] in the JSON.")
        sys.exit(1)

    metrics = data.get("metrics", [])

    # Create a dictionary so we can quickly look up each metric by its name
    # Key = metric_name (exact match), Value = the metric dict
    metric_lookup = {m.get("name"): m for m in metrics}

    # Determine target shell based on model name
    target_shell = "/bin/bash"
    if "linux" in model_name.lower():
        target_shell = "/bin/sh"

    # 2) For each subfolder in model_name/
    model_subfolders = os.listdir(model_name)
    for metric_folder in model_subfolders:
        metric_path = os.path.join(model_name, metric_folder)
        if not os.path.isdir(metric_path):
            continue  # skip files at top level, if any

        # 3) Find the matching metric in the JSON
        metric_data = metric_lookup.get(metric_folder)
        if not metric_data:
            print(f"[WARNING] No matching metric found in JSON for folder '{metric_folder}'. Skipping.")
            continue

        # 4) For each valid block name, check .ps or .sh
        for block_name in VALID_BLOCKS:
            ps_file = os.path.join(metric_path, f"{block_name}.ps")
            sh_file = os.path.join(metric_path, f"{block_name}.sh")

            script_path = None
            if os.path.isfile(ps_file):
                script_path = ps_file
            elif os.path.isfile(sh_file):
                script_path = sh_file

            if not script_path:
                continue

            raw_script = _read_script_file(script_path)
            ext = os.path.splitext(script_path)[1]
            script_content = _prepare_target_content(raw_script, ext, shell=target_shell)

            if not script_content.strip():
                print(f"[WARNING] Script '{script_path}' is empty. Skipping.")
                continue

            block_data = metric_data.get(block_name, {})
            block_data["class"] = "cli"
            block_data["target"] = script_content

            metric_data[block_name] = block_data
            print(f"[INFO] Imported {script_path} into metric '{metric_folder}' -> {block_name}")

    # 5) Write updated JSON to the same file
    updated_json_path = json_file_path
    with open(updated_json_path, 'w', encoding='utf-8') as f_out:
        json.dump(data, f_out, indent=2, ensure_ascii=False)

    print(f"[INFO] Updated JSON written to '{updated_json_path}'.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python import_cli_scripts.py <threat_model.json>")
        sys.exit(1)

    json_file_path = sys.argv[1]
    if not os.path.isfile(json_file_path):
        print(f"[ERROR] JSON file not found: {json_file_path}")
        sys.exit(1)

    import_cli_scripts(json_file_path)


if __name__ == "__main__":
    main()
