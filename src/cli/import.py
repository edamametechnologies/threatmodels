#!/usr/bin/env python3

import json
import os
import sys

VALID_BLOCKS = ["implementation", "remediation", "rollback"]

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

            if os.path.isfile(ps_file):
                # read content
                with open(ps_file, 'r', encoding='utf-8') as f_in:
                    content = f_in.read().rstrip("\n")

                # Join lines back into one-liner, use ";" on Windows
                one_liner = content.replace("\n", "; ")

                # store into metric_data[block_name]
                block_data = metric_data.get(block_name, {})
                block_data["class"] = "cli"
                block_data["target"] = one_liner

                metric_data[block_name] = block_data
                print(f"[INFO] Imported {ps_file} into metric '{metric_folder}' -> {block_name}")

            elif os.path.isfile(sh_file):
                # read content
                with open(sh_file, 'r', encoding='utf-8') as f_in:
                    lines = f_in.readlines()

                # Remove shebang and comments
                content = []
                for line in lines:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    if line:
                        content.append(line)

                # Join lines back into one-liner
                one_liner = " ".join(content)

                block_data = metric_data.get(block_name, {})
                block_data["class"] = "cli"
                block_data["target"] = one_liner

                metric_data[block_name] = block_data
                print(f"[INFO] Imported {sh_file} into metric '{metric_folder}' -> {block_name}")
            else:
                # no script file for this block, do nothing
                pass

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
