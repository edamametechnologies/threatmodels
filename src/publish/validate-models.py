'''Validate models'''

import sys
import json
import requests
import ipaddress
import hashlib
import re
import os
from urllib.parse import urlparse


# --- Common header validation (date/signature) ---------------------------------
def _compute_signature(data: dict) -> str:
    """Compute sha256 over JSON where signature field is blanked.

    Sorting keys is critical to ensure deterministic signature.
    """
    data_copy = data.copy()
    # Some models allow signature to be null/missing; normalize to empty string
    data_copy["signature"] = ""
    json_str = json.dumps(data_copy, sort_keys=True)
    return hashlib.sha256(json_str.encode()).hexdigest()


_DATE_REGEX = re.compile(r"^[A-Za-z]+\s+\d{1,2}(st|nd|rd|th)\s+\d{4}$")


def _validate_date_string(date_value: str, ctx: str) -> None:
    if not isinstance(date_value, str):
        raise ValueError(f"Top-level 'date' must be a string ({ctx})")
    if not _DATE_REGEX.match(date_value.strip()):
        raise ValueError(
            f"Top-level 'date' must match 'Month DDth YYYY' format (e.g., 'August 08th 2025') ({ctx})"
        )


def _validate_signature_and_sidecar(filename: str, data: dict, *, signature_required: bool, allow_null_signature: bool = False) -> None:
    """Validate signature presence and correctness, and that sidecar .sig matches.

    - signature_required: when True, 'signature' must be a non-empty string
    - allow_null_signature: when True, 'signature' may be None; if None, skip verification
    """
    if "signature" not in data:
        if signature_required:
            raise ValueError("Missing top-level 'signature'")
        # If not required and missing, nothing to verify
        return

    sig = data.get("signature")
    if sig is None:
        if signature_required and not allow_null_signature:
            raise ValueError("Top-level 'signature' must be a string")
        # Optional and absent → skip content verification
        return

    if not isinstance(sig, str) or sig.strip() == "":
        raise ValueError("Top-level 'signature' must be a non-empty string or null")

    calculated = _compute_signature(data)
    if calculated != sig:
        raise ValueError("Top-level 'signature' does not match content (recompute required)")

    # Validate sidecar .sig content if file exists
    sidecar_path = filename.removesuffix('.json') + '.sig'
    if os.path.exists(sidecar_path):
        with open(sidecar_path, 'r', encoding='utf-8') as f:
            sidecar = f.read().strip()
        if sidecar != sig:
            raise ValueError(f"Signature sidecar {os.path.basename(sidecar_path)} does not match top-level signature")


# --- URL reachability check (soft-fail on transient external failures) -------
#
# Per-request timeout. HEAD->GET fallback x 2 attempt cycles = up to 4 requests
# per URL in the worst case, capped at ~40s of wall time per URL.
_URL_TIMEOUT_S = 10
# Total HEAD->GET cycles attempted before a transient failure is reported as a
# warning. Each cycle tries HEAD first (cheap), then GET (some servers reject
# HEAD). 2 cycles = best-effort dedup of one-off network blips without making
# every URL check expensive.
_URL_ATTEMPTS = 2


# Vendor documentation sites that are known to anti-scrape automated probes:
# they return 4xx for unrecognized HTTP clients (or specific IP ranges, e.g.
# datacenter or CI runner IPs) while serving real content to browsers.
# Treating a 4xx from these hosts as a warning rather than a hard failure
# avoids blocking PRs on github-hosted runners that share IPs with the
# scraper allow-deny tables of these vendors. Genuine URL deprecation will
# still be visible in the validation log as a warning so the developer can
# verify manually in a browser.
_KNOWN_ANTI_SCRAPING_URL_FRAGMENTS = (
    "wikipedia.org/wiki/",
    "support.google.com/",
    "support.microsoft.com/",
    "support.apple.com/",
    "learn.microsoft.com/",
    "docs.microsoft.com/",
)


def _classify_response(status: int, reason_text: str, url: str):
    """Return ``("ok"|"warn"|"fail", reason)`` for a single HTTP response.

    - 2xx/3xx -> ``ok``
    - 5xx -> ``warn`` (transient server-side problem)
    - 4xx on a known anti-scraping vendor doc host -> ``warn`` (likely
      bot-detection on the CI runner's IP; the URL itself may be fine)
    - other 4xx -> ``fail`` (genuine URL invalidity)
    """
    if 200 <= status < 400:
        return ("ok", None)
    reason = f"{status} {reason_text}"
    if 500 <= status < 600:
        return ("warn", reason)
    if 400 <= status < 500:
        for fragment in _KNOWN_ANTI_SCRAPING_URL_FRAGMENTS:
            if fragment in url:
                return ("warn", f"{reason} (likely anti-scraping on {fragment})")
    return ("fail", reason)


def _probe_once(url: str):
    """Single HEAD->GET probe cycle.

    Returns a tuple ``(classification, reason)``:
      - ``("ok", None)``                  -- request reached the server and
                                             returned an acceptable status
      - ``("warn", reason)``              -- request reached the server and
                                             returned a soft-fail status
                                             (5xx / Wikipedia 403)
      - ``("fail", reason)``              -- request reached the server and
                                             returned a hard-fail status
                                             (other 4xx)
      - ``("transient", reason)``         -- the request itself failed
                                             (timeout, connection error,
                                             DNS, SSL, ...)

    HEAD is tried first because it's cheap. If HEAD does not yield ``ok``
    *for any reason at all* (network exception, 4xx, 5xx, ...) we ALWAYS
    fall through to GET. Many servers (e.g. ``support.google.com``)
    answer HEAD with 404/405 but answer GET with 200. The final
    classification therefore comes from GET when HEAD is non-ok.
    """
    last_transient_reason = None
    last_class = None
    last_reason = None
    for method in (requests.head, requests.get):
        try:
            response = method(url, timeout=_URL_TIMEOUT_S, allow_redirects=True)
        except requests.exceptions.RequestException as exc:
            last_transient_reason = f"transient request error ({type(exc).__name__}): {exc}"
            last_class = "transient"
            last_reason = last_transient_reason
            continue
        cls, reason = _classify_response(response.status_code, response.reason or "", url)
        if cls == "ok":
            return ("ok", None)
        last_class = cls
        last_reason = reason
    return (last_class or "transient", last_reason or "unknown error")


def _check_url_reachable(url: str):
    """Probe a URL for validation purposes.

    Returns ``("ok", None)`` for 2xx/3xx, ``("warn", reason)`` for soft
    failures that should NOT block validation, and ``("fail", reason)``
    for hard failures that should block validation.

    Soft (warn) failures include:
      - 5xx server-side responses (transient external infrastructure)
      - request timeout / connection error / DNS failure (transient network)
      - 403 from ``wikipedia.org/wiki/`` (Wikipedia anti-scraping; URL is real)

    Hard (fail) failures: any 4xx response other than the Wikipedia 403
    carve-out, AND only when GET (the fallback method) also returns it.
    Many servers reject HEAD with 4xx but accept GET with 2xx; the helper
    falls through HEAD->GET unconditionally before declaring failure.

    Retries the whole HEAD->GET cycle on transient outcomes (network
    exception or 5xx) up to ``_URL_ATTEMPTS`` times before reporting a
    transient failure as a warning.
    """
    last_transient_reason = None
    for _attempt in range(_URL_ATTEMPTS):
        cls, reason = _probe_once(url)
        if cls == "ok":
            return ("ok", None)
        if cls in ("warn", "fail"):
            return (cls, reason)
        # cls == "transient" -- record and retry the whole HEAD->GET cycle.
        last_transient_reason = reason
    return ("warn", last_transient_reason or "exhausted transient retries")


def _check_target_url(url: str, ctx: str) -> None:
    """Apply ``_check_url_reachable`` policy for a JSON ``target`` field.

    Raises ``ValueError`` on hard failures; prints a warning on soft
    failures; silent on success.
    """
    if not url.startswith("http"):
        return
    status, reason = _check_url_reachable(url)
    if status == "ok":
        return
    if status == "warn":
        print(f"Warning: {reason} for URL '{url}' in target field at '{ctx}'.")
        return
    # Hard fail
    error_msg = f"Invalid URL '{url}' in target field at '{ctx}'. Reason: {reason}"
    print(error_msg)
    raise ValueError(error_msg)

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

    # Header checks
    _validate_date_string(data.get('date'), 'lanscan-port-vulns')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

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

    # Header checks
    _validate_date_string(data.get('date'), 'lanscan-profiles')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

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

    # Header checks
    _validate_date_string(data.get('date'), 'threatmodel')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

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
                _check_target_url(impl['target'], f"{metric['name']} -> {key}")

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
                    _check_target_url(
                        education['target'],
                        f"{metric['name']} -> {key} -> education[{k}]",
                    )

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

    _validate_date_string(data.get('date'), 'whitelist')
    # Optional signature: if present, verify; if None/missing, skip
    _validate_signature_and_sidecar(filename, data, signature_required=False, allow_null_signature=True)
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

    _validate_date_string(data.get('date'), 'blacklist')
    _validate_signature_and_sidecar(filename, data, signature_required=True)
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

    _validate_date_string(data.get('date'), 'lanscan-vendor-vulns')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

    print("Vendor vulnerabilities validation successful")

def validate_sensitive_paths(filename: str) -> None:
    """Validate sensitive-paths-db.json structure."""
    allowed_top_keys = {
        'date', 'signature', 'common_patterns', 'platform_patterns', 'labels',
        'watch_roots', 'fim_excluded_path_patterns',
    }

    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    actual_keys = set(data.keys())
    if actual_keys != allowed_top_keys:
        unexpected = actual_keys - allowed_top_keys
        missing = allowed_top_keys - actual_keys
        raise ValueError(f"Unexpected keys {unexpected}, missing keys {missing}")

    _validate_date_string(data.get('date'), 'sensitive-paths')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

    if not isinstance(data['common_patterns'], list):
        raise ValueError("'common_patterns' must be a list")
    for i, pat in enumerate(data['common_patterns']):
        if not isinstance(pat, str):
            raise ValueError(f"common_patterns[{i}] must be a string")

    if not isinstance(data['platform_patterns'], dict):
        raise ValueError("'platform_patterns' must be a dict")
    allowed_platforms = {'macos', 'windows', 'linux', 'ios', 'android'}
    for platform, patterns in data['platform_patterns'].items():
        if platform not in allowed_platforms:
            raise ValueError(f"Unknown platform '{platform}' in platform_patterns")
        if not isinstance(patterns, list):
            raise ValueError(f"platform_patterns['{platform}'] must be a list")
        for i, pat in enumerate(patterns):
            if not isinstance(pat, str):
                raise ValueError(f"platform_patterns['{platform}'][{i}] must be a string")

    if not isinstance(data['labels'], dict):
        raise ValueError("'labels' must be a dict")
    for label, patterns in data['labels'].items():
        if not isinstance(label, str):
            raise ValueError(f"Label key must be a string, got {type(label)}")
        if not isinstance(patterns, list):
            raise ValueError(f"labels['{label}'] must be a list")
        for i, pat in enumerate(patterns):
            if not isinstance(pat, str):
                raise ValueError(f"labels['{label}'][{i}] must be a string")

    # watch_roots: per-platform home-relative directory list consumed by the
    # FIM watcher to bootstrap recursive watches without hardcoding paths
    # in Rust. Keys are explicit so shape stays inspectable from the JSON.
    allowed_watch_root_keys = {
        'common_home_relative',
        'linux_home_relative',
        'macos_home_relative',
        'windows_home_relative',
    }
    if not isinstance(data['watch_roots'], dict):
        raise ValueError("'watch_roots' must be a dict")
    actual_watch_keys = set(data['watch_roots'].keys())
    if actual_watch_keys != allowed_watch_root_keys:
        unexpected = actual_watch_keys - allowed_watch_root_keys
        missing = allowed_watch_root_keys - actual_watch_keys
        raise ValueError(
            f"Unexpected keys {unexpected}, missing keys {missing} in 'watch_roots'"
        )
    for key, paths in data['watch_roots'].items():
        if not isinstance(paths, list):
            raise ValueError(f"watch_roots['{key}'] must be a list")
        for i, p in enumerate(paths):
            if not isinstance(p, str):
                raise ValueError(f"watch_roots['{key}'][{i}] must be a string")
            if p.startswith('/') or '\\' in p:
                raise ValueError(
                    f"watch_roots['{key}'][{i}] must be a HOME-relative POSIX path "
                    f"(no leading '/' and no backslashes); got '{p}'"
                )

    # fim_excluded_path_patterns: substring patterns used by the FIM watcher to
    # short-circuit hashing/store-insert for known build-tool churn (cargo
    # target trees, gradle caches, node_modules, browser content caches, ...).
    # Patterns are matched case-insensitively against forward-slash-normalized
    # paths in flodbadd::fim, so they MUST be lowercase and use '/' separators.
    if not isinstance(data['fim_excluded_path_patterns'], list):
        raise ValueError("'fim_excluded_path_patterns' must be a list")
    for i, pat in enumerate(data['fim_excluded_path_patterns']):
        if not isinstance(pat, str):
            raise ValueError(f"fim_excluded_path_patterns[{i}] must be a string")
        if pat != pat.lower():
            raise ValueError(
                f"fim_excluded_path_patterns[{i}] must be lowercase (matched on lower(path)); got '{pat}'"
            )
        if '\\' in pat:
            raise ValueError(
                f"fim_excluded_path_patterns[{i}] must use '/' separators; got '{pat}'"
            )

    print("Sensitive paths validation successful")


def validate_cve_detection_params(filename: str) -> None:
    """Validate cve-detection-params-db.json structure."""
    allowed_top_keys = {
        'date', 'signature', 'checks',
        'credential_harvest_min_labels',
        'secret_content_scan_max_bytes',
        'secret_content_scan_excluded_path_patterns',
        'secret_content_min_hits',
        'secret_content_network_command_tokens',
        'secret_content_script_extensions',
        'recent_sensitive_open_file_ttl_secs',
        'ci_runner_process_name_prefixes',
        'ci_runner_workspace_path_patterns',
        'ci_workspace_path_patterns',
        'keychain_transactional_filename_patterns',
        'benign_temp_artifact_suffixes',
        'application_storage_patterns',
        'credential_store_patterns',
        'trusted_credential_helpers',
        'generic_reuse_tokens', 'generic_application_tokens',
        'init_process_names', 'suspicious_parent_path_patterns',
        'non_sensitive_browser_data_subtrees',
        'browser_appdata_unknown_writer',
        'build_output_tree_self_spawn_patterns',
        'packaged_application_contains_patterns',
        'packaged_application_starts_with_patterns',
        'packaged_application_ends_with_patterns',
        'managed_temp_staging_patterns',
        'trusted_build_temp_staging',
        'app_self_temp_staging',
        'package_manager_temp_path_patterns',
        'package_manager_temp_writers',
        'edamame_daemon_self_telemetry_writers',
        'edamame_daemon_self_telemetry_install_prefixes',
        'platform_credential_helper_routine_destinations',
        'cloud_provider_sdk_destinations',
        'platform_metadata_endpoints',
        'platform_runtime_probe_filename_patterns',
        'platform_self_state_directories',
        'platform_self_state_processes',
        'runtime_perfdata_paths',
        'fim_hash_size_threshold', 'fim_temp_executable_patterns',
        'known_system_daemon_credential_maintenance_hints',
        'trusted_self_extracting_installers',
    }
    allowed_check_keys = {'severity', 'description', 'reference'}
    required_checks = {
        'credential_harvest',
        'token_exfiltration',
        'skill_supply_chain',
        'sandbox_exploitation',
        'file_system_tampering',
        'sensitive_material_egress',
    }
    allowed_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}

    def validate_string_list(value, key_name: str) -> None:
        if not isinstance(value, list):
            raise ValueError(f"'{key_name}' must be a list")
        for i, item in enumerate(value):
            if not isinstance(item, str):
                raise ValueError(f"{key_name}[{i}] must be a string")

    def validate_platform_string_lists(value, key_name: str) -> None:
        expected_keys = {'macos', 'linux', 'windows'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for platform in sorted(expected_keys):
            validate_string_list(value[platform], f"{key_name}['{platform}']")

    def validate_managed_temp_staging_patterns(value, key_name: str) -> None:
        expected_keys = {'suppress_path_patterns', 'demote_path_patterns'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for subkey in sorted(expected_keys):
            validate_platform_string_lists(value[subkey], f"{key_name}['{subkey}']")

    def validate_trusted_build_temp_staging(value, key_name: str) -> None:
        expected_keys = {'writer_path_patterns', 'artifact_path_patterns'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for subkey in sorted(expected_keys):
            validate_platform_string_lists(value[subkey], f"{key_name}['{subkey}']")

    def validate_app_self_temp_staging(value, key_name: str) -> None:
        # Per-platform list of pair-wise writer/target allowlist entries for
        # trusted-app self-temp-staging suppression (FP-WIN-7c). Each entry
        # documents a single vendor's self-update / self-extract pattern as
        # a (writer_path_patterns, target_path_patterns) pair so the
        # deterministic suppression hook does not collapse two unrelated
        # legitimate writers and trusted targets into a cross-match.
        expected_platform_keys = {'macos', 'linux', 'windows'}
        expected_entry_keys = {
            'name', 'writer_path_patterns', 'target_path_patterns',
        }
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_platform_keys:
            missing = expected_platform_keys - set(value.keys())
            extra = set(value.keys()) - expected_platform_keys
            raise ValueError(
                f"{key_name} has missing keys {missing} and unexpected keys {extra}"
            )
        for platform in sorted(expected_platform_keys):
            entries = value[platform]
            if not isinstance(entries, list):
                raise ValueError(f"{key_name}['{platform}'] must be a list")
            seen_names = set()
            for i, entry in enumerate(entries):
                ekey = f"{key_name}['{platform}'][{i}]"
                if not isinstance(entry, dict):
                    raise ValueError(f"{ekey} must be a dict")
                if set(entry.keys()) != expected_entry_keys:
                    missing = expected_entry_keys - set(entry.keys())
                    extra = set(entry.keys()) - expected_entry_keys
                    raise ValueError(
                        f"{ekey} has missing keys {missing} and unexpected keys {extra}"
                    )
                if not isinstance(entry['name'], str) or not entry['name']:
                    raise ValueError(f"{ekey}['name'] must be a non-empty string")
                if entry['name'] in seen_names:
                    raise ValueError(
                        f"{ekey}['name'] '{entry['name']}' duplicates a previous entry on '{platform}'"
                    )
                seen_names.add(entry['name'])
                validate_string_list(
                    entry['writer_path_patterns'],
                    f"{ekey}['writer_path_patterns']",
                )
                if not entry['writer_path_patterns']:
                    raise ValueError(
                        f"{ekey}['writer_path_patterns'] must contain at least one pattern"
                    )
                validate_string_list(
                    entry['target_path_patterns'],
                    f"{ekey}['target_path_patterns']",
                )
                if not entry['target_path_patterns']:
                    raise ValueError(
                        f"{ekey}['target_path_patterns'] must contain at least one pattern"
                    )

    def validate_helper_matcher_config(value, key_name: str) -> None:
        expected_keys = {
            'exact_paths',
            'path_contains',
            'path_starts_with',
            'path_ends_with',
            'compact_names',
            'compact_leaf_names',
            'leaf_trusted_dir_prefixes',
        }
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for matcher_key in sorted(expected_keys):
            validate_string_list(value[matcher_key], f"{key_name}['{matcher_key}']")

    def validate_platform_helper_matchers(value, key_name: str) -> None:
        expected_keys = {'generic_git', 'macos', 'linux', 'windows'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for platform in sorted(expected_keys):
            validate_helper_matcher_config(value[platform], f"{key_name}['{platform}']")

    def validate_browser_data_subtrees(value, key_name: str) -> None:
        # Lists of case-insensitive substring patterns that the
        # vulnerability detector matches against FIM `path` to suppress
        # browser-cache / browser-state findings (see
        # ../edamame_core/FALSEPOSITIVES.md FP-WIN-1/2/5).
        expected_keys = {
            'chromium_family',
            'chromium_state_files_routine',
            'chromium_profile_state_volatile',
            'chromium_user_data_root_markers',
            'firefox_family_subtrees',
            'firefox_profile_state_volatile',
            'firefox_user_data_root_markers',
        }
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for subkey in sorted(expected_keys):
            validate_string_list(value[subkey], f"{key_name}['{subkey}']")

    def validate_browser_appdata_unknown_writer(value, key_name: str) -> None:
        expected_keys = {
            'chromium_user_data_root_markers',
            'firefox_user_data_root_markers',
            'chromium_process_names',
            'firefox_process_names',
            'directory_target_names',
        }
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for subkey in sorted(expected_keys):
            validate_string_list(value[subkey], f"{key_name}['{subkey}']")

    def validate_ci_runner_workspace_paths(value, key_name: str) -> None:
        # Path substrings are matched against a forward-slash-normalized,
        # lowercased version of the FIM event path, so a single canonical
        # forward-slash form covers Linux, macOS and Windows runners across
        # every CI provider (GitHub Actions, GitLab CI, Jenkins, CircleCI,
        # Buildkite, Travis, TeamCity, Azure DevOps, Bitbucket Pipelines,
        # Drone, Woodpecker, Cirrus, AppVeyor, ...).
        expected_keys = {'path_substrings', 'suppressible_basenames'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_keys:
            missing = expected_keys - set(value.keys())
            extra = set(value.keys()) - expected_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        validate_string_list(value['path_substrings'], f"{key_name}['path_substrings']")
        validate_string_list(value['suppressible_basenames'], f"{key_name}['suppressible_basenames']")

    def validate_credential_helper_destinations(value, key_name: str) -> None:
        # Per-platform { asn_owners: [...], domain_patterns: [...], ip_prefixes: [...] }
        expected_platform_keys = {'macos', 'linux', 'windows'}
        expected_subkeys = {'asn_owners', 'domain_patterns', 'ip_prefixes'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_platform_keys:
            missing = expected_platform_keys - set(value.keys())
            extra = set(value.keys()) - expected_platform_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for platform in sorted(expected_platform_keys):
            sub = value[platform]
            if not isinstance(sub, dict):
                raise ValueError(f"{key_name}['{platform}'] must be a dict")
            if set(sub.keys()) != expected_subkeys:
                missing = expected_subkeys - set(sub.keys())
                extra = set(sub.keys()) - expected_subkeys
                raise ValueError(
                    f"{key_name}['{platform}'] has missing keys {missing} and unexpected keys {extra}"
                )
            validate_string_list(sub['asn_owners'], f"{key_name}['{platform}']['asn_owners']")
            validate_string_list(sub['domain_patterns'], f"{key_name}['{platform}']['domain_patterns']")
            validate_string_list(sub['ip_prefixes'], f"{key_name}['{platform}']['ip_prefixes']")

    def validate_cloud_provider_sdk_destinations(value, key_name: str) -> None:
        # Provider-keyed { asn_owners: [...], domain_suffixes: [...], ip_prefixes: [...] }.
        # Unlike the credential-helper destinations this is keyed by cloud
        # provider (matching the sensitive-path label strings) rather than by
        # platform, and uses domain_suffixes (strict suffix semantics) instead
        # of domain_patterns (substring semantics).
        expected_provider_keys = {'aws', 'azure', 'gcp'}
        expected_subkeys = {'asn_owners', 'domain_suffixes', 'ip_prefixes'}
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_provider_keys:
            missing = expected_provider_keys - set(value.keys())
            extra = set(value.keys()) - expected_provider_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for provider in sorted(expected_provider_keys):
            sub = value[provider]
            if not isinstance(sub, dict):
                raise ValueError(f"{key_name}['{provider}'] must be a dict")
            if set(sub.keys()) != expected_subkeys:
                missing = expected_subkeys - set(sub.keys())
                extra = set(sub.keys()) - expected_subkeys
                raise ValueError(
                    f"{key_name}['{provider}'] has missing keys {missing} and unexpected keys {extra}"
                )
            validate_string_list(sub['asn_owners'], f"{key_name}['{provider}']['asn_owners']")
            validate_string_list(sub['domain_suffixes'], f"{key_name}['{provider}']['domain_suffixes']")
            validate_string_list(sub['ip_prefixes'], f"{key_name}['{provider}']['ip_prefixes']")

    def validate_runtime_perfdata_paths(value, key_name: str) -> None:
        # Per-platform list of {artifact_path_substring, writer_basenames, writer_path_prefixes}
        expected_platform_keys = {'macos', 'linux', 'windows'}
        expected_entry_keys = {
            'artifact_path_substring',
            'writer_basenames',
            'writer_path_prefixes',
        }
        if not isinstance(value, dict):
            raise ValueError(f"'{key_name}' must be a dict")
        if set(value.keys()) != expected_platform_keys:
            missing = expected_platform_keys - set(value.keys())
            extra = set(value.keys()) - expected_platform_keys
            raise ValueError(f"{key_name} has missing keys {missing} and unexpected keys {extra}")
        for platform in sorted(expected_platform_keys):
            entries = value[platform]
            if not isinstance(entries, list):
                raise ValueError(f"{key_name}['{platform}'] must be a list")
            for i, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"{key_name}['{platform}'][{i}] must be a dict")
                if set(entry.keys()) != expected_entry_keys:
                    missing = expected_entry_keys - set(entry.keys())
                    extra = set(entry.keys()) - expected_entry_keys
                    raise ValueError(
                        f"{key_name}['{platform}'][{i}] has missing keys {missing} and unexpected keys {extra}"
                    )
                if not isinstance(entry['artifact_path_substring'], str):
                    raise ValueError(
                        f"{key_name}['{platform}'][{i}]['artifact_path_substring'] must be a string"
                    )
                validate_string_list(
                    entry['writer_basenames'],
                    f"{key_name}['{platform}'][{i}]['writer_basenames']",
                )
                validate_string_list(
                    entry['writer_path_prefixes'],
                    f"{key_name}['{platform}'][{i}]['writer_path_prefixes']",
                )

    with open(filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Data is not a valid JSON object")

    actual_keys = set(data.keys())
    if actual_keys != allowed_top_keys:
        unexpected = actual_keys - allowed_top_keys
        missing = allowed_top_keys - actual_keys
        raise ValueError(f"Unexpected keys {unexpected}, missing keys {missing}")

    _validate_date_string(data.get('date'), 'cve-detection-params')
    _validate_signature_and_sidecar(filename, data, signature_required=True)

    if not isinstance(data['checks'], dict):
        raise ValueError("'checks' must be a dict")
    if set(data['checks'].keys()) != required_checks:
        missing = required_checks - set(data['checks'].keys())
        extra = set(data['checks'].keys()) - required_checks
        raise ValueError(f"Missing checks {missing}, unexpected checks {extra}")
    for check_name, check_data in data['checks'].items():
        if set(check_data.keys()) != allowed_check_keys:
            raise ValueError(f"check '{check_name}' has unexpected keys: {set(check_data.keys()) - allowed_check_keys}")
        if check_data['severity'] not in allowed_severities:
            raise ValueError(f"check '{check_name}' has invalid severity: {check_data['severity']}")
        if not isinstance(check_data['description'], str):
            raise ValueError(f"check '{check_name}' description must be a string")
        if not isinstance(check_data['reference'], str):
            raise ValueError(f"check '{check_name}' reference must be a string")

    if not isinstance(data['credential_harvest_min_labels'], int) or data['credential_harvest_min_labels'] < 1:
        raise ValueError("'credential_harvest_min_labels' must be a positive integer")
    if not isinstance(data['secret_content_scan_max_bytes'], int) or data['secret_content_scan_max_bytes'] < 0:
        raise ValueError("'secret_content_scan_max_bytes' must be a non-negative integer")
    if not isinstance(data['secret_content_min_hits'], int) or data['secret_content_min_hits'] < 1:
        raise ValueError("'secret_content_min_hits' must be a positive integer")
    if not isinstance(data['recent_sensitive_open_file_ttl_secs'], int) or data['recent_sensitive_open_file_ttl_secs'] < 0:
        raise ValueError("'recent_sensitive_open_file_ttl_secs' must be a non-negative integer")
    if not isinstance(data['fim_hash_size_threshold'], int) or data['fim_hash_size_threshold'] < 0:
        raise ValueError("'fim_hash_size_threshold' must be a non-negative integer")

    for list_key in (
        'ci_runner_process_name_prefixes',
        'ci_workspace_path_patterns',
        'keychain_transactional_filename_patterns',
        'benign_temp_artifact_suffixes',
        'application_storage_patterns',
        'generic_reuse_tokens',
        'generic_application_tokens',
        'init_process_names',
        'suspicious_parent_path_patterns',
        'packaged_application_contains_patterns',
        'packaged_application_starts_with_patterns',
        'packaged_application_ends_with_patterns',
        'fim_temp_executable_patterns',
        'secret_content_network_command_tokens',
        'secret_content_scan_excluded_path_patterns',
        'secret_content_script_extensions',
    ):
        validate_string_list(data[list_key], list_key)

    validate_platform_string_lists(data['credential_store_patterns'], 'credential_store_patterns')
    validate_platform_string_lists(
        data['trusted_self_extracting_installers'],
        'trusted_self_extracting_installers',
    )
    validate_platform_helper_matchers(data['trusted_credential_helpers'], 'trusted_credential_helpers')
    validate_platform_string_lists(
        data['known_system_daemon_credential_maintenance_hints'],
        'known_system_daemon_credential_maintenance_hints',
    )
    validate_browser_data_subtrees(
        data['non_sensitive_browser_data_subtrees'],
        'non_sensitive_browser_data_subtrees',
    )
    validate_browser_appdata_unknown_writer(
        data['browser_appdata_unknown_writer'],
        'browser_appdata_unknown_writer',
    )
    validate_managed_temp_staging_patterns(
        data['managed_temp_staging_patterns'],
        'managed_temp_staging_patterns',
    )
    validate_trusted_build_temp_staging(
        data['trusted_build_temp_staging'],
        'trusted_build_temp_staging',
    )
    validate_app_self_temp_staging(
        data['app_self_temp_staging'],
        'app_self_temp_staging',
    )
    validate_platform_string_lists(
        data['package_manager_temp_path_patterns'],
        'package_manager_temp_path_patterns',
    )
    validate_platform_string_lists(
        data['package_manager_temp_writers'],
        'package_manager_temp_writers',
    )
    validate_platform_string_lists(
        data['edamame_daemon_self_telemetry_writers'],
        'edamame_daemon_self_telemetry_writers',
    )
    validate_platform_string_lists(
        data['edamame_daemon_self_telemetry_install_prefixes'],
        'edamame_daemon_self_telemetry_install_prefixes',
    )
    validate_platform_string_lists(
        data['platform_metadata_endpoints'],
        'platform_metadata_endpoints',
    )
    validate_platform_string_lists(
        data['platform_runtime_probe_filename_patterns'],
        'platform_runtime_probe_filename_patterns',
    )
    validate_platform_string_lists(
        data['platform_self_state_directories'],
        'platform_self_state_directories',
    )
    validate_platform_string_lists(
        data['platform_self_state_processes'],
        'platform_self_state_processes',
    )
    validate_platform_string_lists(
        data['build_output_tree_self_spawn_patterns'],
        'build_output_tree_self_spawn_patterns',
    )
    validate_ci_runner_workspace_paths(
        data['ci_runner_workspace_path_patterns'],
        'ci_runner_workspace_path_patterns',
    )
    validate_credential_helper_destinations(
        data['platform_credential_helper_routine_destinations'],
        'platform_credential_helper_routine_destinations',
    )
    validate_cloud_provider_sdk_destinations(
        data['cloud_provider_sdk_destinations'],
        'cloud_provider_sdk_destinations',
    )
    validate_runtime_perfdata_paths(
        data['runtime_perfdata_paths'],
        'runtime_perfdata_paths',
    )

    print("CVE detection params validation successful")


if __name__ == "__main__":
    validation_errors = []
    for arg in sys.argv[1:]: # Skip the script name itself
        filename = os.path.basename(arg)
        try:
            print(f"Validating {arg}...")
            if filename.startswith("lanscan-port-vulns"):
                validate_lanscan_port_vulns(arg)
            elif filename.startswith("lanscan-profiles") or filename.startswith("lanscan_profiles"): # Match both patterns
                validate_lanscan_profiles(arg)
            elif filename.startswith("threatmodel"):
                validate_threat_model(arg)
            elif filename.startswith("whitelist"):
                 validate_whitelist(arg)
            elif filename.startswith("blacklist"):
                 validate_blacklist(arg)
            elif filename.startswith("lanscan-vendor-vulns"):
                 validate_vendor_vulns(arg)
            elif filename.startswith("sensitive-paths"):
                 validate_sensitive_paths(arg)
            elif filename.startswith("cve-detection-params"):
                 validate_cve_detection_params(arg)
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
