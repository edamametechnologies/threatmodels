#!/usr/bin/env python3

import json
import sys
import os

def merge_tags_from_files(input_json_paths):
    """
    Reads one or more threat-model JSON files, merges them into a dictionary:
        merged = {
          metric_name: {
            threat_model_name: set_of_tags,
            ...
          },
          ...
        }
    """
    merged = {}
    # Keep track of which threat_model_name came from which file.
    # We assume each file is a distinct "threat model."
    all_threat_models = set()

    for json_path in input_json_paths:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Use top-level "name" as the threat_model_name
        threat_model_name = data.get("name", os.path.basename(json_path))
        all_threat_models.add(threat_model_name)

        metrics = data.get("metrics", [])
        for metric in metrics:
            metric_name = metric.get("name", "")
            tags = metric.get("tags", [])

            if metric_name not in merged:
                merged[metric_name] = {}
            if threat_model_name not in merged[metric_name]:
                merged[metric_name][threat_model_name] = set()

            merged[metric_name][threat_model_name].update(tags)

    return merged, all_threat_models


def finalize_generic_tags(merged_data, all_threat_models):
    """
    For each metric, if it appears in *all* threat models,
    compute the intersection of tags across all threat-model-specific sets.
    Whatever is common to all becomes "generic".
    Then remove those tags from each threat-model-specific set.
    """
    # Convert to a list to avoid modifying dict keys during iteration
    metric_names = list(merged_data.keys())
    total_tm_count = len(all_threat_models)

    for metric_name in metric_names:
        # The sub-dict for this metric might appear in fewer than all threat models
        # If it's not in all, we skip computing "generic" because the user wants
        # "generic" only if it's truly shared by all provided models.
        metric_tms = merged_data[metric_name]  # {threat_model: set_of_tags, ...}

        if len(metric_tms) < total_tm_count:
            # Not in all threat models => skip
            continue

        # Check if this metric_name is indeed in *every* threat_model_name
        # Because some threat_model_name might be missing the metric entirely.
        # We'll see if we truly have an entry for each threat_model_name:
        missing_any = any(tm not in metric_tms for tm in all_threat_models)
        if missing_any:
            continue

        # Compute intersection across all threat_model_name sets
        all_sets = list(metric_tms.values())  # a list of set_of_tags
        common_tags = set.intersection(*all_sets) if all_sets else set()

        # If there's any common tag, move it to "generic"
        if common_tags:
            # Create or reset the "generic" set
            metric_tms["generic"] = common_tags

            # Remove those common tags from each threat_model_name’s set
            for tm in list(metric_tms.keys()):
                if tm == "generic":
                    continue
                metric_tms[tm] = metric_tms[tm] - common_tags


def write_merged_tags(merged_data, output_path="tags.json"):
    """
    Converts sets to sorted lists, writes to tags.json with structure:
      {
        "metric_name": {
          "ThreatModelA": [...],
          "ThreatModelB": [...],
          "generic": [...]
        },
        ...
      }
    """
    final_dict = {}
    for metric_name in sorted(merged_data.keys()):
        final_dict[metric_name] = {}
        for tm_name in sorted(merged_data[metric_name].keys()):
            sorted_tags = sorted(merged_data[metric_name][tm_name])
            final_dict[metric_name][tm_name] = sorted_tags

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_dict, f, indent=2, ensure_ascii=False)
    
    print(f"[INFO] Merged tags with 'generic' written to '{output_path}'.")


def read_tags(input_json_list):
    """
    Orchestrates reading from multiple JSON files,
    placing truly shared tags into "generic",
    then writing everything to tags.json.
    """
    merged_data, all_threat_models = merge_tags_from_files(input_json_list)
    # Move common tags into "generic" if they appear in all threat models
    finalize_generic_tags(merged_data, all_threat_models)
    write_merged_tags(merged_data, "tags.json")


def write_tags(output_json_list):
    """
    Reads from tags.json (always), updates each JSON in output_json_list.
    For each metric, final tags are the union of:
      threat_model-specific tags + "generic" tags (if present).
    Writes updated JSON (in-place).
    """

    with open("tags.json", 'r', encoding='utf-8') as f:
        tags_data = json.load(f)

    for output_json_path in output_json_list:
        with open(output_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # The top-level "name" identifies which threat-model-specific key we use
        threat_model_name = data.get("name", os.path.basename(output_json_path))

        metrics = data.get("metrics", [])
        for metric in metrics:
            metric_name = metric.get("name", "")
            if metric_name not in tags_data:
                # No entry at all for this metric
                continue

            # The final set of tags is a union of any threat_model-specific tags
            # plus any "generic" tags, if present
            final_tags = set()

            # If there's a block for this threat_model_name, add it
            tm_tags = tags_data[metric_name].get(threat_model_name, [])
            final_tags.update(tm_tags)

            # If there's "generic" for this metric, also add that
            if "generic" in tags_data[metric_name]:
                final_tags.update(tags_data[metric_name]["generic"])

            metric["tags"] = sorted(final_tags)

        # Overwrite the JSON with updated tags
        with open(output_json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[INFO] Updated metric tags and wrote to '{output_json_path}'.")


def main():
    """
    Usage:
      python tags_script.py read  <input1.json> [<input2.json> ...]
      python tags_script.py write <json_in> [<json_in2.json> ...]
    
    read  => merges tags from multiple JSONs; places truly shared tags under "generic".
    write => updates one or more JSON files by applying threat-model-specific plus "generic" tags.
    """
    if len(sys.argv) < 2:
        print("[ERROR] Missing mode argument (read or write).")
        print(main.__doc__)
        sys.exit(1)
    
    mode = sys.argv[1].lower()

    if mode == "read":
        if len(sys.argv) < 3:
            print("[ERROR] Provide at least one JSON file to read.")
            print(main.__doc__)
            sys.exit(1)
        
        input_json_list = sys.argv[2:]
        read_tags(input_json_list)

    elif mode == "write":
        if len(sys.argv) < 3:
            print("[ERROR] Provide at least one JSON file to update.")
            print(main.__doc__)
            sys.exit(1)

        output_json_list = sys.argv[2:]
        write_tags(output_json_list)

    else:
        print("[ERROR] Unknown mode. Use 'read' or 'write'.")
        print(main.__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
