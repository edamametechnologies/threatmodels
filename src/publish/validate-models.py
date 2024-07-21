'''Validate models'''

import sys
import json
import requests

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
                            raise ValueError(f"Invalid URL '{impl['target']}' in target field at '{metric['name']} -> {key} -> impl[{k}]'. "
                                             f"Reason: {response.status_code} {response.reason}")

            # Validate 'education' in 'implementation'
            for k, education in enumerate(impl['education']):
                if set(education.keys()) != allowed_keys_education:
                    raise ValueError(f"Unexpected keys in education at '{metric['name']} -> {key} -> education[{k}]'")

                # Type checks for fields in 'education'
                if not all(isinstance(education[field], str) for field in allowed_keys_education):
                    raise ValueError(f"Invalid data type in education fields at '{metric['name']} -> {key} -> education[{k}]'")

                # If we have a class "link" or "youtube" or "installer" check the url is valid and try to access it to check if we have a 404
                if education['class'] in ['link', 'youtube', 'installer']:
                    # Only check http(s) links
                    if education['target'].startswith("http"):
                        response = requests.head(education['target'])
                        if not response.ok:
                            # Sometime head request is not allowed, try with get
                            response = requests.get(education['target'])
                            if not response.ok:
                                raise ValueError(f"Invalid URL '{education['target']}' in target field at '{metric['name']} -> {key} -> education[{k}]'. "
                                             f"Reason: {response.status_code} {response.reason}")

            # Type checks for other fields in implementation/remediation/rollback
            if not isinstance(impl['system'], str) or \
                    not isinstance(impl['minversion'], int) or \
                    not isinstance(impl['maxversion'], int) or \
                    not isinstance(impl['class'], str) or \
                    not isinstance(impl['elevation'], str) or \
                    not isinstance(impl['target'], str):
                raise ValueError(f"Invalid data type in {key} fields at '{metric['name']} -> {key}'")

    print("Validation successful")


if __name__ == "__main__":
    for arg in sys.argv:
        if arg.startswith("lanscan-port-vulns"):
            print(f"Validating {arg}")
            validate_lanscan_port_vulns(arg)
        elif arg.startswith("lanscan_profiles"):
            print(f"Validating {arg}")
            validate_lanscan_profiles(arg)
        elif arg.startswith("threatmodel"):
            print(f"Validating {arg}")
            validate_threat_model(arg)
