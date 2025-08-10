'''Validate models'''

import sys
import json
import requests
import ipaddress
import hashlib
import re
import os
from urllib.parse import urlparse

# Validate validate_lanscan-port-vulns against this VulnerabilityInfoList Rust structure
# #[derive(Serialize, Deserialize, Debug, Clone, Ord, Eq, PartialEq, PartialOrd)]
# pub struct VulnerabilityInfo {
#     pub name: String,
#     pub description: String,
# }
#
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct VulnerabilityPortInfo {
#     pub port: u16,
#     pub name: String,
#     pub description: String,
#     pub vulnerabilities: Vec<VulnerabilityInfo>,
#     pub count: u32,
#     pub protocol: String,
# }
#
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct VulnerabilityInfoListJSON {
#     pub date: String,
#     pub signature: String,
#     pub vulnerabilities: Vec<VulnerabilityPortInfo>,
# }
#
# pub struct VulnerabilityInfoList {
#     pub date: String,
#     pub signature: String,
#     pub port_vulns: HashMap<u16, VulnerabilityPortInfo>,
#     pub http_ports: HashMap<u16, VulnerabilityPortInfo>,
#     pub https_ports: HashMap<u16, VulnerabilityPortInfo>,
# }
def validate_lanscan_port_vulns(filename: str) -> None:
    allowed_keys_vulnerability_info = {'name', 'description'}
    allowed_keys_vulnerability_port_info = {'port', 'name', 'description', 'vulnerabilities', 'count', 'protocol'}
    allowed_keys_vulnerability_info_list = {'date', 'signature', 'vulnerabilities'}

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    if set(data.keys()) != allowed_keys_vulnerability_info_list:
        raise ValueError(f"Unexpected keys [{data.keys()}] in JSON data at root")

    for i, vuln in enumerate(data['vulnerabilities']):
        if not isinstance(vuln, dict) or set(vuln.keys()) != allowed_keys_vulnerability_port_info:
            raise ValueError(f"Unexpected keys [{vuln.keys()}] in VulnerabilityPortInfo at 'vulnerabilities[{i}]'")

        for j, v in enumerate(vuln['vulnerabilities']):
            if not isinstance(v, dict) or set(v.keys()) != allowed_keys_vulnerability_info:
                raise ValueError(f"Unexpected keys [{v.keys()}] in VulnerabilityInfo at 'vulnerabilities[{i}] -> vulnerabilities[{j}]'")

    print("Validation successful")

# Validate validate_lanscan_profiles against this DeviceTypeListJSON Rust structure
# [derive(Debug, Deserialize, Serialize, Clone)]
# struct Attributes {
#     open_ports: Option<Vec<u16>>,
#     mdns_services: Option<Vec<String>>,
#     vendors: Option<Vec<String>>,
#     hostnames: Option<Vec<String>>,
#     banners: Option<Vec<String>>,
#     negate: Option<bool>, // New field to indicate negation
# }
#
# #[derive(Debug, Deserialize, Serialize, Clone)]
# enum Condition {
#     Leaf(Attributes),
#     Node {
#         #[serde(rename = "type")]
#         condition_type: String,
#         sub_conditions: Vec<Condition>,
#     },
# }
#
# #[derive(Debug, Deserialize, Serialize, Clone)]
# struct DeviceTypeRule {
#     device_type: String,
#     conditions: Vec<Condition>,
# }
#
# #[derive(Serialize, Deserialize, Debug, Clone)]
# struct DeviceTypeListJSON {
#     date: String,
#     signature: String,
#     profiles: Vec<DeviceTypeRule>,
# }
def validate_lanscan_profiles(filename: str) -> None:
    allowed_keys_device_type_rule = {'device_type', 'conditions'}
    allowed_keys_device_type_list = {'date', 'signature', 'profiles'}

    def validate_attributes(attributes, path):
        allowed_keys = {'open_ports', 'mdns_services', 'vendors', 'hostnames', 'banners', 'negate'}
        actual_keys = set(attributes.keys())

        # Check for the presence of exactly one of the required keys
        required_keys = allowed_keys - {'negate'}
        present_keys = actual_keys & required_keys
        if len(present_keys) != 1:
            raise ValueError(f"Exactly one of {required_keys} must be present in Attributes at {path}")
        if 'negate' in actual_keys and not isinstance(attributes['negate'], bool):
            raise ValueError(f"'negate' must be a boolean in Attributes at {path}")

        # Type check for the present key
        present_key = present_keys.pop()
        if present_key == 'open_ports' and not all(isinstance(item, int) for item in attributes[present_key]):
            raise ValueError(f"Invalid type for attribute 'open_ports' at {path}")
        elif present_key in ['mdns_services', 'vendors', 'hostnames', 'banners'] and not all(isinstance(item, str) for item in attributes[present_key]):
            raise ValueError(f"Invalid type for attribute '{present_key}' at {path}")

    def validate_condition(condition, path):
        if not isinstance(condition, dict):
            raise ValueError(f"Condition must be a dictionary at {path}")

        if 'Leaf' in condition:
            validate_attributes(condition['Leaf'], path + " -> 'Leaf'")
        elif 'Node' in condition:
            node = condition['Node']
            if 'sub_conditions' not in node or not isinstance(node['sub_conditions'], list):
                raise ValueError(f"Node type Condition must have 'sub_conditions' as a list at {path}")
            if 'type' not in node:
                raise ValueError(f"Node type Condition must have 'type' field at {path}")

            for i, sub_condition in enumerate(node['sub_conditions']):
                validate_condition(sub_condition, f"{path} -> 'Node' -> sub_conditions[{i}]")
        else:
            raise ValueError(f"Condition must be either a Leaf or a Node at {path}")

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")
    actual_keys = set(data.keys())
    if actual_keys != allowed_keys_device_type_list:
        unexpected_keys = actual_keys - allowed_keys_device_type_list
        missing_keys = allowed_keys_device_type_list - actual_keys
        raise ValueError(f"Unexpected keys [{unexpected_keys}] or missing keys [{missing_keys}] in JSON data")

    for i, profile in enumerate(data['profiles']):
        if not isinstance(profile, dict):
            raise ValueError(f"Each profile must be a dictionary at profiles[{i}]")
        actual_keys = set(profile.keys())
        if actual_keys != allowed_keys_device_type_rule:
            unexpected_keys = actual_keys - allowed_keys_device_type_rule
            missing_keys = allowed_keys_device_type_rule - actual_keys
            raise ValueError(f"Unexpected keys [{unexpected_keys}] or missing keys [{missing_keys}] in DeviceTypeRule at profiles[{i}]")

        for j, condition in enumerate(profile['conditions']):
            validate_condition(condition, f"profiles[{i}] -> conditions[{j}]")

    print("Validation successful")

# Validate threatmodel against this ThreatMetrics Rust structure
# // Only Strings in order to easily read the JSON array
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct ThreatMetricEducationJSON {
#     pub locale: String,
#     pub class: String,
#     pub target: String,
# }
#
# // Only Strings in order to easily read the JSON array
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct ThreatMetricImplementationJSON {
#     pub system: String,
#     pub minversion: i32,
#     pub maxversion: i32,
#     pub class: String,
#     pub elevation: String,
#     pub target: String,
#     pub education: Vec<ThreatMetricEducationJSON>
# }
#
# // Only Strings in order to easily read the JSON array
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct ThreatMetricDescriptionJSON {
#     pub locale: String,
#     pub title: String,
#     pub summary: String
# }
#
# // Only Strings in order to easily read the JSON array
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct ThreatMetricJSON {
#     pub name: String,
#     pub metrictype: String,
#     pub dimension: String,
#     pub severity: i32,
#     pub scope: String,
#     pub tags: Vec<String>,
#     pub description: Vec<ThreatMetricDescriptionJSON>,
#     pub implementation: ThreatMetricImplementationJSON,
#     pub remediation: ThreatMetricImplementationJSON,
#     pub rollback: ThreatMetricImplementationJSON,
# }
#
# #[derive(Serialize, Deserialize, Debug, Clone)]
# pub struct ThreatMetricsJSON {
#     pub name: String,
#     pub extends: String,
#     pub date: String,
#     pub signature: String,
#     pub metrics: Vec<ThreatMetricJSON>,
# }
#
# #[derive(Debug, Clone, Serialize, Deserialize)]
# pub enum ThreatStatus {
#     Active,
#     Inactive,
#     Unknown
# }
#
# #[derive(Debug, Clone, Serialize, Deserialize)]
# pub struct ThreatMetric {
#     pub metric: ThreatMetricJSON,
#     // Can be empty
#     pub timestamp: String,
#     pub status: ThreatStatus,
# }
#
# #[derive(Debug, Clone, Serialize, Deserialize)]
# pub struct ThreatMetrics {
#     pub metrics: Vec<ThreatMetric>,
#     // Copied field from the JSON threat model
#     pub name: String,
#     pub extends: String,
#     pub date: String,
#     pub signature: String,
#     pub timestamp: String,
# }
def validate_threat_model(filename: str) -> None:
    allowed_keys_threat_metric_json = {
        'name', 'metrictype', 'dimension', 'severity', 'scope',
        'tags', 'description', 'implementation', 'remediation', 'rollback'
    }
    allowed_keys_threat_metrics_json = {'name', 'extends', 'date', 'signature', 'metrics'}
    allowed_keys_description = {'locale', 'title', 'summary'}
    allowed_keys_implementation = {
        'system', 'minversion', 'maxversion', 'class', 'elevation',
        'target', 'education'
    }
    allowed_keys_education = {'locale', 'class', 'target'}

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    if set(data.keys()) != allowed_keys_threat_metrics_json:
        raise ValueError(f"Unexpected keys [{data.keys()}] in JSON data at root")

    for i, metric in enumerate(data['metrics']):
        if set(metric.keys()) != allowed_keys_threat_metric_json:
            raise ValueError(f"Unexpected keys [{metric.keys()}] in ThreatMetricJSON at '{metric['name']}'")

        # Validate description
        for j, description in enumerate(metric['description']):
            if set(description.keys()) != allowed_keys_description:
                raise ValueError(f"Unexpected keys [{description.keys()}] in description at '{metric['name']} -> description[{j}]'")

        # Validate implementation, remediation, and rollback
        for key in ['implementation', 'remediation', 'rollback']:
            impl = metric[key]
            if set(impl.keys()) != allowed_keys_implementation:
                raise ValueError(f"Unexpected keys [{impl.keys()}] in {key} at '{metric['name']} -> {key}'")

            # If we have a class "link" or "youtube" or "installer" check the url is valid and try to access it to check if we have a 404
            if impl['class'] in ['link', 'youtube']:
                # Only check http(s) links
                if impl['target'].startswith("http"):
                    response = requests.head(impl['target'])
                    if not response.ok:
                        # Sometime head request is not allowed, try with get
                        response = requests.get(impl['target'])
                        if not response.ok:
                            error_msg = f"Invalid URL '{impl['target']}' in target field at '{metric['name']} -> {key}'. Reason: {response.status_code} {response.reason}"
                            print(error_msg)
                            raise ValueError(error_msg)

            # If we have a youtube class, check the URL is a valid youtube video
            if impl['class'] == 'youtube':
                if not impl['target'].startswith("https://www.youtube.com/watch?v="):
                    raise ValueError(f"Invalid URL '{impl['target']}' in target field at '{metric['name']} -> {key} -> impl[{k}]'. "
                                     f"URL must start with 'https://www.youtube.com/watch?v='")

            # If we have a youtube URL, check if the class is 'youtube'
            if impl['target'].startswith("https://www.youtube.com/watch?v=") and impl['class'] != 'youtube':
                raise ValueError(f"Invalid class '{impl['class']}' in class field at '{metric['name']} -> {key} -> impl[{k}]'. "
                                 f"Class must be 'youtube'")

            # Validate 'education' in 'implementation'
            for k, education in enumerate(impl['education']):
                if set(education.keys()) != allowed_keys_education:
                    raise ValueError(f"Unexpected keys in education at '{metric['name']} -> {key} -> education[{k}]'")

                # Type checks for fields in 'education'
                if not all(isinstance(education[field], str) for field in allowed_keys_education):
                    raise ValueError(f"Invalid data type in education fields at '{metric['name']} -> {key} -> education[{k}]'")

                # If we have a class "link" or "youtube" check the url is valid and try to access it to check if we have a 404
                if education['class'] in ['link', 'youtube']:
                    # Only check http(s) links
                    if education['target'].startswith("http"):
                        response = requests.head(education['target'])
                        if not response.ok:
                            # Sometime head request is not allowed, try with get
                            response = requests.get(education['target'])
                            if not response.ok:
                                error_msg = f"Invalid URL '{education['target']}' in target field at '{metric['name']} -> {key} -> education[{k}]'. Reason: {response.status_code} {response.reason}"
                                print(error_msg)
                                raise ValueError(error_msg)

                    # If we have a youtube class, check the URL is a valid youtube video
                    if education['class'] == 'youtube':
                        if not education['target'].startswith("https://www.youtube.com/watch?v="):
                            raise ValueError(f"Invalid URL '{education['target']}' in target field at '{metric['name']} -> {key} -> impl[{k}]'. "
                                             f"URL must start with 'https://www.youtube.com/watch?v='")

                    # If we have a youtube URL, check if the class is 'youtube'
                    if education['target'].startswith("https://www.youtube.com/watch?v=") and education['class'] != 'youtube':
                        raise ValueError(f"Invalid class '{impl['class']}' in class field at '{metric['name']} -> {key} -> impl[{k}]'. "
                                         f"Class must be 'youtube'")

            # Type checks for other fields in implementation/remediation/rollback
            if not isinstance(impl['system'], str) or \
                    not isinstance(impl['minversion'], int) or \
                    not isinstance(impl['maxversion'], int) or \
                    not isinstance(impl['class'], str) or \
                    not isinstance(impl['elevation'], str) or \
                    not isinstance(impl['target'], str):
                raise ValueError(f"Invalid data type in {key} fields at '{metric['name']} -> {key}'")

    print("Validation successful")


# Validate whitelist against WhitelistsJSON Rust structure
# pub struct WhitelistEndpoint {
#     pub domain: Option<String>,
#     pub ip: Option<String>,
#     pub port: Option<u16>,
#     pub protocol: Option<String>,
#     pub as_number: Option<u32>,
#     pub as_country: Option<String>,
#     pub as_owner: Option<String>,
#     pub process: Option<String>,
#     pub description: Option<String>,
# }
# pub struct WhitelistInfo {
#     pub name: String,
#     pub extends: Option<Vec<String>>,
#     pub endpoints: Vec<WhitelistEndpoint>,
# }
# pub struct WhitelistsJSON {
#     pub date: String,
#     pub signature: Option<String>,
#     pub whitelists: Vec<WhitelistInfo>,
# }
def validate_whitelist(filename: str) -> None:
    allowed_top_keys = {'date', 'signature', 'whitelists'}
    required_top_keys = {'date', 'whitelists'}
    allowed_info_keys = {'name', 'extends', 'endpoints'}
    required_info_keys = {'name', 'endpoints'}
    allowed_endpoint_keys = {
        'domain', 'ip', 'port', 'protocol', 'as_number', 'as_country',
        'as_owner', 'process', 'description'
    }

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    actual_top_keys = set(data.keys())
    if not required_top_keys.issubset(actual_top_keys):
        missing = required_top_keys - actual_top_keys
        raise ValueError(f"Missing required top-level keys: {missing}")
    if not actual_top_keys.issubset(allowed_top_keys):
        extra = actual_top_keys - allowed_top_keys
        raise ValueError(f"Unexpected top-level keys: {extra}")

    if not isinstance(data['whitelists'], list):
        raise ValueError("Top-level 'whitelists' must be a list")

    for i, info in enumerate(data['whitelists']):
        if not isinstance(info, dict):
            raise ValueError(f"Item at whitelists[{i}] is not a valid object")

        actual_info_keys = set(info.keys())
        if not required_info_keys.issubset(actual_info_keys):
            missing = required_info_keys - actual_info_keys
            raise ValueError(f"Missing required keys in whitelists[{i}]: {missing}")
        if not actual_info_keys.issubset(allowed_info_keys):
            extra = actual_info_keys - allowed_info_keys
            raise ValueError(f"Unexpected keys in whitelists[{i}]: {extra}")

        if not isinstance(info['name'], str):
            raise ValueError(f"'name' in whitelists[{i}] must be a string")
        if 'extends' in info and info['extends'] is not None:
             if not isinstance(info['extends'], list) or not all(isinstance(item, str) for item in info['extends']):
                 raise ValueError(f"'extends' in whitelists[{i}] must be a list of strings or null")
        if not isinstance(info['endpoints'], list):
            raise ValueError(f"'endpoints' in whitelists[{i}] must be a list")

        whitelist_name = info.get('name', f'index {i}') # For error messages

        for j, endpoint in enumerate(info['endpoints']):
            path = f"whitelists['{whitelist_name}'] -> endpoints[{j}]"
            if not isinstance(endpoint, dict):
                 raise ValueError(f"Item at {path} is not a valid object")

            actual_endpoint_keys = set(endpoint.keys())
            if not actual_endpoint_keys.issubset(allowed_endpoint_keys):
                extra = actual_endpoint_keys - allowed_endpoint_keys
                raise ValueError(f"Unexpected keys in {path}: {extra}")

            # Type checks for optional fields
            if 'domain' in endpoint and endpoint['domain'] is not None and not isinstance(endpoint['domain'], str):
                raise ValueError(f"'domain' in {path} must be a string or null")
            if 'ip' in endpoint and endpoint['ip'] is not None:
                 if not isinstance(endpoint['ip'], str):
                     raise ValueError(f"'ip' in {path} must be a string or null")
                 try:
                     # Check if it's a valid IP or CIDR
                     if '/' in endpoint['ip']:
                         ipaddress.ip_network(endpoint['ip'], strict=False)
                     else:
                         ipaddress.ip_address(endpoint['ip'])
                 except ValueError as ip_err:
                     raise ValueError(f"Invalid 'ip' format in {path}: {endpoint['ip']} ({ip_err})")
            if 'port' in endpoint and endpoint['port'] is not None:
                 if not isinstance(endpoint['port'], int):
                     raise ValueError(f"'port' in {path} must be an integer or null")
                 if not (0 <= endpoint['port'] <= 65535):
                     raise ValueError(f"'port' in {path} must be between 0 and 65535")
            if 'protocol' in endpoint and endpoint['protocol'] is not None and not isinstance(endpoint['protocol'], str):
                raise ValueError(f"'protocol' in {path} must be a string or null")
            if 'as_number' in endpoint and endpoint['as_number'] is not None and not isinstance(endpoint['as_number'], int):
                 raise ValueError(f"'as_number' in {path} must be an integer or null")
            if 'as_country' in endpoint and endpoint['as_country'] is not None and not isinstance(endpoint['as_country'], str):
                raise ValueError(f"'as_country' in {path} must be a string or null")
            if 'as_owner' in endpoint and endpoint['as_owner'] is not None and not isinstance(endpoint['as_owner'], str):
                 raise ValueError(f"'as_owner' in {path} must be a string or null")
            if 'process' in endpoint and endpoint['process'] is not None and not isinstance(endpoint['process'], str):
                 raise ValueError(f"'process' in {path} must be a string or null")
            if 'description' in endpoint and endpoint['description'] is not None and not isinstance(endpoint['description'], str):
                raise ValueError(f"'description' in {path} must be a string or null")

    print("Whitelist validation successful")


# Validate blacklist against BlacklistsJSON Rust structure
# pub struct BlacklistInfo {
#     pub name: String,
#     pub description: Option<String>,
#     pub last_updated: Option<String>,
#     pub source_url: Option<String>,
#     pub ip_ranges: Vec<String>,
# }
# pub struct BlacklistsJSON {
#     pub date: String,
#     pub signature: String,
#     pub blacklists: Vec<BlacklistInfo>,
# }
def validate_blacklist(filename: str) -> None:
    allowed_top_keys = {'date', 'signature', 'blacklists'}
    required_top_keys = {'date', 'signature', 'blacklists'}
    allowed_info_keys = {'name', 'description', 'last_updated', 'source_url', 'ip_ranges'}
    required_info_keys = {'name', 'ip_ranges'}

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    actual_top_keys = set(data.keys())
    if not required_top_keys.issubset(actual_top_keys):
        missing = required_top_keys - actual_top_keys
        raise ValueError(f"Missing required top-level keys: {missing}")
    if not actual_top_keys.issubset(allowed_top_keys):
        extra = actual_top_keys - allowed_top_keys
        raise ValueError(f"Unexpected top-level keys: {extra}")

    if not isinstance(data['blacklists'], list):
        raise ValueError("Top-level 'blacklists' must be a list")

    for i, info in enumerate(data['blacklists']):
        if not isinstance(info, dict):
            raise ValueError(f"Item at blacklists[{i}] is not a valid object")

        actual_info_keys = set(info.keys())
        if not required_info_keys.issubset(actual_info_keys):
            missing = required_info_keys - actual_info_keys
            raise ValueError(f"Missing required keys in blacklists[{i}]: {missing}")
        if not actual_info_keys.issubset(allowed_info_keys):
            extra = actual_info_keys - allowed_info_keys
            raise ValueError(f"Unexpected keys in blacklists[{i}]: {extra}")

        if not isinstance(info['name'], str):
            raise ValueError(f"'name' in blacklists[{i}] must be a string")
        if 'description' in info and info['description'] is not None and not isinstance(info['description'], str):
            raise ValueError(f"'description' in blacklists[{i}] must be a string or null")
        if 'last_updated' in info and info['last_updated'] is not None and not isinstance(info['last_updated'], str):
             raise ValueError(f"'last_updated' in blacklists[{i}] must be a string or null")
        if 'source_url' in info and info['source_url'] is not None:
            if not isinstance(info['source_url'], str):
                 raise ValueError(f"'source_url' in blacklists[{i}] must be a string or null")
            # Basic URL format validation
            try:
                parsed = urlparse(info['source_url'])
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError(f"Invalid URL format for 'source_url' in blacklists[{i}]: {info['source_url']}")
            except ValueError as url_err:
                 raise ValueError(f"Invalid URL format for 'source_url' in blacklists[{i}]: {info['source_url']} ({url_err})")

        if not isinstance(info['ip_ranges'], list):
            raise ValueError(f"'ip_ranges' in blacklists[{i}] must be a list")

        blacklist_name = info.get('name', f'index {i}') # For error messages

        for j, ip_range in enumerate(info['ip_ranges']):
            path = f"blacklists['{blacklist_name}'] -> ip_ranges[{j}]"
            if not isinstance(ip_range, str):
                 raise ValueError(f"Item at {path} must be a string")
            try:
                # Check if it's a valid IP or CIDR
                if '/' in ip_range:
                    ipaddress.ip_network(ip_range, strict=False)
                else:
                    ipaddress.ip_address(ip_range)
            except ValueError as ip_err:
                raise ValueError(f"Invalid IP/CIDR format in {path}: {ip_range} ({ip_err})")

    print("Blacklist validation successful")


# Validate vendor vulnerabilities against the structure used in build-vendor-vulns-db.py
def validate_vendor_vulns(filename: str) -> None:
    """Validate vendor vulnerabilities database"""
    allowed_keys_root = {'date', 'signature', 'vulnerabilities'}
    allowed_keys_vendor = {'vendor', 'vulnerabilities', 'count'}
    allowed_keys_vulnerability = {'name', 'description'}

    with open(filename, 'r', encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    actual_keys = set(data.keys())
    if not actual_keys == allowed_keys_root:
        raise ValueError(f"Unexpected keys [{actual_keys}] in JSON data at root")

    if not isinstance(data['vulnerabilities'], list):
        raise ValueError("'vulnerabilities' must be a list")

    for i, vendor_entry in enumerate(data['vulnerabilities']):
        if not isinstance(vendor_entry, dict):
            raise ValueError(f"Each vendor entry must be a dictionary at vulnerabilities[{i}]")
        
        actual_keys = set(vendor_entry.keys())
        if not actual_keys.issubset(allowed_keys_vendor):
            unexpected_keys = actual_keys - allowed_keys_vendor
            raise ValueError(f"Unexpected keys [{unexpected_keys}] in vendor at vulnerabilities[{i}]")
        
        if 'vendor' not in vendor_entry:
            raise ValueError(f"Missing 'vendor' key in vulnerabilities[{i}]")
            
        if 'vulnerabilities' not in vendor_entry:
            raise ValueError(f"Missing 'vulnerabilities' key in vulnerabilities[{i}]")
        
        if not isinstance(vendor_entry['vulnerabilities'], list):
            raise ValueError(f"'vulnerabilities' must be a list in vulnerabilities[{i}]")
            
        for j, vuln in enumerate(vendor_entry['vulnerabilities']):
            if not isinstance(vuln, dict):
                raise ValueError(f"Each vulnerability must be a dictionary at vulnerabilities[{i}].vulnerabilities[{j}]")
                
            actual_keys = set(vuln.keys())
            if not actual_keys == allowed_keys_vulnerability:
                raise ValueError(f"Unexpected keys [{actual_keys}] in vulnerability at vulnerabilities[{i}].vulnerabilities[{j}]")

    print("Vendor vulnerabilities validation successful")

if __name__ == "__main__":
    validation_errors = []
    for arg in sys.argv[1:]: # Skip the script name itself
        try:
            print(f"Validating {arg}...")
            if arg.startswith("lanscan-port-vulns"):
                validate_lanscan_port_vulns(arg)
            elif arg.startswith("lanscan-profiles") or arg.startswith("lanscan_profiles"): # Match both patterns
                validate_lanscan_profiles(arg)
            elif arg.startswith("threatmodel"):
                validate_threat_model(arg)
            elif arg.startswith("whitelist"):
                 validate_whitelist(arg)
            elif arg.startswith("blacklist"):
                 validate_blacklist(arg)
            elif arg.startswith("lanscan-vendor-vulns"):
                 validate_vendor_vulns(arg)
            else:
                print(f"Warning: No specific validation logic found for prefix of file '{arg}'. Skipping.")
            print(f"Validation successful for {arg}")
        except Exception as e:
            error_msg = f"Validation failed for {arg}: {e}"
            print(error_msg)
            validation_errors.append(error_msg)

    if validation_errors:
        print("\n--- Validation Summary: FAILURES --- GITHUB_ACTION_ERRORS --- START") # Marker for GH Action error parsing
        for error in validation_errors:
            print(error)
        print("--- Validation Summary: FAILURES --- GITHUB_ACTION_ERRORS --- END") # Marker for GH Action error parsing
        sys.exit(1) # Exit with non-zero code if any validation failed
    else:
        print("\n--- Validation Summary: All files validated successfully! ---")
