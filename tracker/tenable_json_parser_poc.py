import json
import os
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

# --- Configuration ---
SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

NUMERIC_SEVERITY_MAP = {
    4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'
}
AV_PLUGIN_IDS = {
    16193: "Antivirus Software Check", 131023: "Windows Defender Installed"
}
CE_PLUS_PATCH_WINDOW_DAYS = 14
CE_PLUS_CVSS_THRESHOLD = 7.0
CE_PLUS_AV_SIGNATURE_AGE_DAYS = 7


# --- Helper Functions ---
def parse_datetime_flexible(date_string):
    if not date_string or not isinstance(date_string, str):
        return None
    if 'T' in date_string and date_string.endswith('Z'):
        try:
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except ValueError:
            logging.warning(f"Could not parse ISO Z-terminated date string: {date_string}")
            return None
    if "GMT" in date_string:
        date_part = date_string.upper().replace(" GMT", "").strip()
        formats_to_try = ['%b. %d, %Y AT %H:%M:%S', '%b %d, %Y AT %H:%M:%S']
        for fmt in formats_to_try:
            try:
                dt_naive = datetime.strptime(date_part, fmt)
                return dt_naive.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        logging.warning(f"Could not parse GMT date string: {date_string} with tried formats.")
        return None
    try:
        dt_obj = datetime.fromisoformat(date_string)
        if dt_obj.tzinfo is None:
            logging.debug(f"Parsed date string '{date_string}' as naive datetime.")
        return dt_obj
    except ValueError:
        pass
    # Fallback for "YYYYMMDDHHMMSS.ffffff+xxx" format from BIOS (plugin 34096/34097)
    match = re.match(r"(\d{14})\.\d{6}([+-]\d{3})", date_string)
    if match:
        try:
            date_part_str = match.group(1)
            offset_str = match.group(2)
            dt_naive = datetime.strptime(date_part_str, "%Y%m%d%H%M%S")
            offset_minutes = int(offset_str)
            tz = timezone(timedelta(minutes=offset_minutes))
            return dt_naive.replace(tzinfo=tz)
        except ValueError:
            logging.warning(f"Could not parse BIOS date string: {date_string}")
            return None

    logging.warning(f"Could not parse date string with any known format: {date_string}")
    return None


def safe_get(data, keys, default=None):
    """Safely get a nested value from a dictionary."""
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data


def add_if_not_present(target_list, item, key_to_check='name'):
    """Adds item to list if an item with the same key_to_check value isn't already present."""
    # For lists of strings (like ce_plus_assessment_failures after processing)
    if isinstance(item, str) and key_to_check is None:
        if item not in target_list:
            target_list.append(item)
        return

    # For lists of dictionaries
    if not any(existing_item.get(key_to_check) == item.get(key_to_check) for existing_item in target_list):
        target_list.append(item)


# --- Main Parsing Function ---
def parse_tenable_scan_file(file_path):
    logging.info(f"--- Starting to parse file: {file_path} ---")
    if not os.path.exists(file_path):
        logging.error(f"File not found at {file_path}")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            scan_data = json.load(f)
        logging.info(f"Successfully loaded JSON data. Found {len(scan_data)} finding entries.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

    assets_summary = defaultdict(lambda: {
        'operating_system': "Unknown OS",
        'outputs': [],
        'cves_by_severity': {sev: {} for sev in SEVERITY_LEVELS},
        'antivirus_details': [],
        'ce_plus_assessment_failures': [],
        'installed_software': [],
        'network_config': {'mac_addresses': set(), 'dns_servers': set(), 'gateways': set(),
                           'ip_assignment_methods': []},
        'listening_services': [],
        'user_accounts_summary': {'password_policy': {}, 'admin_group_members': [], 'local_users': []},
        'system_hardening': [],
        'hardware_info': {},
        'smb_shares': [],
        'last_reboot_time': "N/A"
    })

    if not isinstance(scan_data, list):
        logging.error("Expected JSON data to be a list of findings.")
        return None

    for i, finding in enumerate(scan_data):
        logging.debug(f"\n--- [PROCESSING] Finding {i + 1} of {len(scan_data)} ---")
        if not isinstance(finding, dict):
            logging.warning(f"Finding entry {i + 1} is not a dictionary. Skipping.")
            continue

        asset_info = finding.get('asset', {})
        asset_identifier = "Unknown_Asset"
        if isinstance(asset_info, dict):
            asset_hostname_from_json = asset_info.get('hostname')
            if asset_hostname_from_json and isinstance(asset_hostname_from_json, str):
                asset_identifier = asset_hostname_from_json
            else:
                asset_identifier = str(safe_get(asset_info, ['uuid']) or \
                                       f"unidentified_asset_in_finding_{i + 1}")
            if assets_summary[asset_identifier]['operating_system'] == "Unknown OS":
                os_list = safe_get(asset_info, ['operating_system'], [])
                if isinstance(os_list, list) and os_list and isinstance(os_list[0], str):
                    assets_summary[asset_identifier]['operating_system'] = os_list[0]

        finding_output = finding.get('output', "")
        if finding_output:
            assets_summary[asset_identifier]['outputs'].append(finding_output)

        plugin_info = finding.get('plugin', {})
        current_plugin_id = safe_get(plugin_info, ['id'])

        # --- Plugin-Specific Parsers ---
        if current_plugin_id in [20811, 178102, 200493]:
            if finding_output:
                for line in finding_output.strip().split('\n'):
                    line = line.strip()
                    if not line or line.startswith(
                        "The following software information is available") or line.startswith(
                        "Nessus detected"): continue  # Skip headers/empty

                    name_part = line.split(' [version')[0].split(' [installed on')[0].strip()
                    if name_part.startswith("- "): name_part = name_part[2:].strip()  # From plugin 178102
                    if not name_part: continue

                    version_match = re.search(r'\[version\s+([^\]]+)\]', line)
                    version = version_match.group(1).strip() if version_match else "N/A"

                    # More robust name extraction if version is at the end
                    if version != "N/A" and name_part.endswith(version):
                        name_part = name_part[:-len(version)].strip()

                    publisher = "N/A"  # Default
                    # Try to get publisher for plugin 20811 format
                    if current_plugin_id == 20811:
                        # Example: "7-Zip 23.01 (x64)  [version 23.01]" - no explicit publisher here
                        # Example: "Microsoft Edge  [version 136.0.3240.76]  [installed on 2025/05/17]" - no explicit publisher
                        # For 20811, publisher is often implied or part of a longer name. We'll keep it simple.
                        pass
                    # Try to get publisher for plugin 178102 (more structured)
                    elif current_plugin_id == 178102:
                        publisher_match = re.search(r"\[Publisher\]\s*:\s*Raw Value\s*:\s*([^\n]+)", finding_output,
                                                    re.IGNORECASE)  # Search in the whole finding_output for this plugin
                        if publisher_match:
                            publisher = publisher_match.group(1).strip()

                    software_item = {'name': name_part, 'version': version, 'publisher': publisher, 'path': 'N/A',
                                     'plugin_id_source': current_plugin_id}
                    add_if_not_present(assets_summary[asset_identifier]['installed_software'], software_item, 'name')

        if current_plugin_id == 24272 and finding_output:
            mac_addresses = assets_summary[asset_identifier]['network_config']['mac_addresses']
            current_interface_macs = re.findall(r"MAC Address\s*=\s*([0-9A-Fa-f:]{17})", finding_output)
            for mac in current_interface_macs:
                mac_addresses.add(mac.upper())

        if current_plugin_id == 34252 and finding_output:
            try:
                service_data = json.loads(finding_output)
                listening_ports = safe_get(service_data, ['listening'], [])
                for port_info in listening_ports:
                    port = safe_get(port_info, ['port'])
                    protocol = safe_get(port_info, ['protocol'])
                    plugin_output_detail = safe_get(port_info, ['plugin_output'], "")
                    process_name_match = re.search(r"The Win32 process '([^']+)' is listening", plugin_output_detail)
                    process_name = process_name_match.group(1) if process_name_match else "N/A"
                    pid_match = re.search(r"\(pid (\d+)\)", plugin_output_detail)
                    pid = pid_match.group(1) if pid_match else "N/A"
                    service_name_match = re.search(r"hosting the following Windows services :\\n(.*?)\\n",
                                                   plugin_output_detail, re.DOTALL)
                    service_display_name = service_name_match.group(1).strip().split('(')[
                        0].strip() if service_name_match else "N/A"
                    service_item = {'port': port, 'protocol': protocol, 'process_name': process_name, 'pid': pid,
                                    'service_display_name': service_display_name, 'plugin_id_source': current_plugin_id}
                    add_if_not_present(assets_summary[asset_identifier]['listening_services'], service_item, 'port')
            except json.JSONDecodeError:
                logging.warning(f"Could not parse JSON output for plugin {current_plugin_id}")

        if current_plugin_id == 17651 and finding_output:
            for line in finding_output.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    assets_summary[asset_identifier]['user_accounts_summary']['password_policy'][
                        key.strip()] = value.strip()

        if current_plugin_id == 10902 and finding_output:
            members = re.findall(r"-\s*(.*?)\s*\((User|Group)\)", finding_output)
            for member_name, member_type in members:
                member_item = {'name': member_name.strip(), 'type': member_type.strip()}
                add_if_not_present(assets_summary[asset_identifier]['user_accounts_summary']['admin_group_members'],
                                   member_item)

        hardening_checks_map = {
            48763: "CWDIllegalInDllSearch", 159817: "Credential Guard Status",
            159929: "LSA Protection Status", 160486: "SMB Protocol Version",
            161691: "MSDT RCE Workaround", 162174: "AlwaysInstallElevated Status",
            92367: "PowerShell Execution Policy", 11457: "Cached Logons Count",
            160301: "LLMNR Status", 166555: "WinVerifyTrust Signature Validation"
        }
        if current_plugin_id in hardening_checks_map and finding_output:
            status_detail = finding_output.strip().replace('\n', ' | ')
            check_item = {'check_name': hardening_checks_map[current_plugin_id], 'status_detail': status_detail,
                          'plugin_id_source': current_plugin_id}
            add_if_not_present(assets_summary[asset_identifier]['system_hardening'], check_item)
            if current_plugin_id == 160486 and "SMB1 : Key not found" not in status_detail and "SMB1 : 0" not in status_detail:  # SMB1 might be enabled if not explicitly disabled or key not found
                # A more precise check would be if "SMB1 : 1" or "SMB1 : Enabled" is found.
                # For CE+, absence of explicit disable is often taken as potentially enabled.
                if "SMB1 : Key not found" in status_detail or "SMB1 : 0" in status_detail:  # Explicitly disabled or not configured (which is good)
                    pass
                else:  # Potentially enabled or ambiguously configured
                    add_if_not_present(assets_summary[asset_identifier]['ce_plus_assessment_failures'],
                                       {'message': "SMBv1 status is not explicitly disabled; further review required."},
                                       'message')

        hw_info = assets_summary[asset_identifier]['hardware_info']
        if current_plugin_id == 24270 and finding_output:
            mfr_match = re.search(r"Computer Manufacturer\s*:\s*(.+)", finding_output)
            model_match = re.search(r"Computer Model\s*:\s*(.+)", finding_output)
            if mfr_match: hw_info['manufacturer'] = mfr_match.group(1).strip()
            if model_match: hw_info['model'] = model_match.group(1).strip()
        if current_plugin_id in [34096, 34097] and finding_output:
            version_match = re.search(r"Version\s*:\s*([^\n]+)", finding_output)
            release_date_match = re.search(r"Release date\s*:\s*([^\n]+)", finding_output)
            if version_match: hw_info['bios_version'] = version_match.group(1).strip()
            if release_date_match:
                parsed_bios_date = parse_datetime_flexible(release_date_match.group(1).strip())
                hw_info['bios_release_date'] = parsed_bios_date.strftime(
                    '%Y-%m-%d') if parsed_bios_date else release_date_match.group(1).strip()
        if current_plugin_id == 51186 and finding_output:
            if 'tpm_info' not in hw_info: hw_info['tpm_info'] = []
            tpm_details = {}
            for line in finding_output.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    tpm_details[key.strip().lower().replace(' ', '_')] = value.strip()
            if tpm_details:
                add_if_not_present(hw_info['tpm_info'], tpm_details, 'manufacturerid')

        if current_plugin_id == 10395 and finding_output:
            shares = re.findall(r"-\s*([A-Za-z0-9\$_-]+)", finding_output)
            for share_name in shares:
                share_item = {'share_name': share_name, 'access_details': 'Enumerated'}
                add_if_not_present(assets_summary[asset_identifier]['smb_shares'], share_item)

        if current_plugin_id == 92366 and finding_output:
            reboot_match = re.search(r"Last reboot\s*:\s*(.+)", finding_output)
            if reboot_match:
                parsed_reboot_time = parse_datetime_flexible(reboot_match.group(1).strip().split('(')[0].strip())
                assets_summary[asset_identifier]['last_reboot_time'] = parsed_reboot_time.strftime(
                    '%Y-%m-%d %H:%M:%S %Z') if parsed_reboot_time else reboot_match.group(1).strip()

        if current_plugin_id in AV_PLUGIN_IDS:
            av_data = {}
            if finding_output:
                lines = finding_output.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower().replace(' ', '_').replace('.', '')
                        value = value.strip()
                        if key == "product_name":
                            av_data['product_name'] = value
                        elif key == "version":
                            av_data['product_version'] = value
                        elif key == "engine_version":
                            av_data['engine_version'] = value
                        elif key == "antivirus_signature_version" or key == "malware_signature_version":
                            av_data['signature_version'] = value
                        elif key == "antispyware_signature_version":
                            av_data['antispyware_signature_version'] = value
                        elif key == "path":
                            av_data['install_path'] = value
                        elif key == "signatures_last_updated" or key == "malware_signature_timestamp":
                            av_data['signatures_last_updated'] = value
                        elif key not in ['forefront_endpoint_protection',
                                         'a_microsoft_anti-malware_product_is_installed_on_the_remote_host_',
                                         'the_following_is_a_consolidated_list_of_detected_mac_addresses']:
                            av_data[key] = value
                if av_data:
                    av_data['plugin_source_id'] = current_plugin_id
                    av_data['plugin_source_name'] = AV_PLUGIN_IDS.get(current_plugin_id, "Unknown AV Plugin")
                    add_if_not_present(assets_summary[asset_identifier]['antivirus_details'], av_data, 'product_name')

        if isinstance(plugin_info, dict):
            raw_severity_finding = finding.get('severity')
            normalized_severity_key = 'info'
            if isinstance(raw_severity_finding, int):
                normalized_severity_key = NUMERIC_SEVERITY_MAP.get(raw_severity_finding, 'info').lower()
            elif isinstance(raw_severity_finding, str):
                normalized_severity_key = raw_severity_finding.lower()
                if normalized_severity_key not in SEVERITY_LEVELS: normalized_severity_key = 'info'

            cvss_base_score_str = "N/A"
            cvss_version = None
            plugin_attributes = plugin_info.get('attributes', [])
            if isinstance(plugin_attributes, list):
                for attr in plugin_attributes:
                    if isinstance(attr, dict) and str(
                            attr.get('attribute_name', '')).lower() == 'cvss3_base_score' and attr.get(
                            'attribute_value'):
                        cvss_base_score_str = str(attr.get('attribute_value'))
                        cvss_version = "3.x"
                        break
                if cvss_version != "3.x":
                    for attr in plugin_attributes:
                        if isinstance(attr, dict) and str(
                                attr.get('attribute_name', '')).lower() == 'cvss_base_score' and attr.get(
                                'attribute_value'):
                            cvss_base_score_str = str(attr.get('attribute_value'))
                            cvss_version = "2.0"
                            break
            if cvss_version is None:
                if plugin_info.get('cvss3_base_score') is not None:
                    cvss_base_score_str = str(plugin_info.get('cvss3_base_score'))
                    cvss_version = "3.x"
                elif plugin_info.get('cvss_base_score') is not None:
                    cvss_base_score_str = str(plugin_info.get('cvss_base_score'))
                    cvss_version = "2.0"
            cvss_base_score_float = -1.0
            try:
                cvss_base_score_float = float(cvss_base_score_str)
            except ValueError:
                pass

            cve_ids_in_plugin = set()
            plugin_cve_list = plugin_info.get('cve', [])
            if isinstance(plugin_cve_list, list):
                for cve_id_str_loop in plugin_cve_list:
                    if isinstance(cve_id_str_loop, str) and cve_id_str_loop.upper().startswith("CVE-"):
                        cve_ids_in_plugin.add(cve_id_str_loop.upper())
            plugin_xrefs_list = plugin_info.get('xrefs', [])
            if isinstance(plugin_xrefs_list, list):
                for xref in plugin_xrefs_list:
                    if isinstance(xref, dict) and str(xref.get('type', '')).upper() == 'CVE':
                        cve_id_str_loop = xref.get('id')
                        if isinstance(cve_id_str_loop, str) and cve_id_str_loop.upper().startswith("CVE-"):
                            cve_ids_in_plugin.add(cve_id_str_loop.upper())

            if cve_ids_in_plugin:
                patch_publication_date_str = plugin_info.get('patch_publication_date') or plugin_info.get(
                    'vuln_publication_date')
                patch_publication_date = parse_datetime_flexible(patch_publication_date_str)
                finding_last_found_str = finding.get('last_found')
                scan_date_for_finding = parse_datetime_flexible(finding_last_found_str)
                is_critical_or_high_vuln = (normalized_severity_key in ['critical', 'high']) or \
                                           (cvss_version and cvss_base_score_float >= CE_PLUS_CVSS_THRESHOLD)
                is_unsupported = plugin_info.get('unsupported_by_vendor', False)

                if is_unsupported and is_critical_or_high_vuln:
                    for cve_id_str_item in cve_ids_in_plugin:
                        failure_msg = (
                            f"Unsupported software (Plugin: {current_plugin_id} - {plugin_info.get('name', 'N/A')}) "
                            f"has associated CVE {cve_id_str_item} rated {normalized_severity_key} / CVSS {cvss_base_score_str}.")
                        add_if_not_present(assets_summary[asset_identifier]['ce_plus_assessment_failures'],
                                           {'message': failure_msg}, 'message')

                if patch_publication_date and scan_date_for_finding:
                    days_since_patch_published = (scan_date_for_finding - patch_publication_date).days
                    if is_critical_or_high_vuln and days_since_patch_published > CE_PLUS_PATCH_WINDOW_DAYS:
                        for cve_id_str_item in cve_ids_in_plugin:
                            patch_date_display = patch_publication_date.strftime('%Y-%m-%d')
                            failure_msg = (
                                f"CVE {cve_id_str_item} (Plugin: {current_plugin_id} - {plugin_info.get('name', 'N/A')}), "
                                f"rated {normalized_severity_key} / CVSS {cvss_base_score_str}, "
                                f"has a patch published on {patch_date_display} ({days_since_patch_published} days ago), "
                                f"exceeding the {CE_PLUS_PATCH_WINDOW_DAYS}-day remediation window.")
                            add_if_not_present(assets_summary[asset_identifier]['ce_plus_assessment_failures'],
                                               {'message': failure_msg}, 'message')

                plugin_id_val = plugin_info.get('id', "N/A")
                plugin_name_val = plugin_info.get('name', "N/A")
                plugin_description_val = plugin_info.get('description', "N/A")
                cvss_vector_val = "N/A"
                if cvss_version == "3.x":
                    for v_attr in plugin_attributes:
                        if isinstance(v_attr, dict) and str(v_attr.get('attribute_name', '')).lower() == 'cvss3_vector':
                            cvss_vector_val = str(v_attr.get('attribute_value', 'N/A'))
                            break
                    if cvss_vector_val == "N/A": cvss_vector_val = plugin_info.get('cvss3_vector', "N/A")
                elif cvss_version == "2.0":
                    for v_attr in plugin_attributes:
                        if isinstance(v_attr, dict) and str(v_attr.get('attribute_name', '')).lower() == 'cvss_vector':
                            cvss_vector_val = str(v_attr.get('attribute_value', 'N/A'))
                            break
                    if cvss_vector_val == "N/A": cvss_vector_val = plugin_info.get('cvss_vector', "N/A")

                for cve_id_str_item in cve_ids_in_plugin:
                    if cve_id_str_item not in assets_summary[asset_identifier]['cves_by_severity'][
                        normalized_severity_key]:
                        cve_detail = {
                            'id': cve_id_str_item,
                            'plugin_id': plugin_id_val,
                            'plugin_name': plugin_name_val,
                            'description': plugin_description_val,
                            'cvss_version': cvss_version if cvss_version else "N/A",
                            'cvss_base_score': cvss_base_score_str,
                            'cvss_vector': cvss_vector_val
                        }
                        assets_summary[asset_identifier]['cves_by_severity'][normalized_severity_key][
                            cve_id_str_item] = cve_detail

    # --- CE+ Antivirus Checks (Post-Loop) ---
    for asset_id, data in assets_summary.items():
        if not data['antivirus_details']:
            failure_msg = f"Antivirus: No Antivirus software detected by plugins {', '.join(map(str, AV_PLUGIN_IDS.keys()))} or key information missing."
            add_if_not_present(data['ce_plus_assessment_failures'], {'message': failure_msg},
                               'message')  # Pass dict for consistency
        else:
            for av_instance in data['antivirus_details']:
                product_name = av_instance.get('product_name', 'Unknown AV')
                if not av_instance.get('product_version') or not av_instance.get('signature_version'):
                    failure_msg = f"Antivirus: '{product_name}' (Plugin: {av_instance.get('plugin_source_id')}) reported with missing critical details (e.g., product version or signature version)."
                    add_if_not_present(data['ce_plus_assessment_failures'], {'message': failure_msg}, 'message')
                last_updated_str = av_instance.get('signatures_last_updated')
                if last_updated_str:
                    last_updated_date = parse_datetime_flexible(last_updated_str)
                    most_recent_finding_date_for_asset = None
                    for finding_item in scan_data:
                        current_asset_info = finding_item.get('asset', {})
                        is_current_asset = (current_asset_info.get('hostname') == asset_id or \
                                            str(current_asset_info.get('uuid')) == asset_id)
                        if is_current_asset:
                            current_finding_date = parse_datetime_flexible(finding_item.get('last_found'))
                            if current_finding_date and (
                                    most_recent_finding_date_for_asset is None or current_finding_date > most_recent_finding_date_for_asset):
                                most_recent_finding_date_for_asset = current_finding_date
                    if last_updated_date and most_recent_finding_date_for_asset and \
                            (
                                    most_recent_finding_date_for_asset - last_updated_date).days > CE_PLUS_AV_SIGNATURE_AGE_DAYS:
                        concern_msg = (
                            f"Antivirus Concern: '{product_name}' signatures last updated on {last_updated_date.strftime('%Y-%m-%d')} "
                            f"({(most_recent_finding_date_for_asset - last_updated_date).days} days ago), "
                            f"may not meet 'up-to-date' criteria (older than {CE_PLUS_AV_SIGNATURE_AGE_DAYS} days).")
                        add_if_not_present(data['ce_plus_assessment_failures'], {'message': concern_msg}, 'message')

    # Finalize data structure
    final_structured_summary = {}
    for asset_id, data in assets_summary.items():
        # Ensure ce_plus_assessment_failures contains only unique strings
        unique_failures = []
        for item in data['ce_plus_assessment_failures']:
            msg = item.get('message') if isinstance(item, dict) else item
            if msg not in unique_failures:
                unique_failures.append(msg)

        final_structured_summary[asset_id] = {
            'operating_system': data['operating_system'],
            'cves_by_severity': {},
            'antivirus_details': data['antivirus_details'],
            'ce_plus_assessment_failures': unique_failures,
            'installed_software': data['installed_software'],
            'network_config': {
                'mac_addresses': sorted(list(data['network_config']['mac_addresses'])),
                'dns_servers': sorted(list(data['network_config']['dns_servers'])),
                'gateways': sorted(list(data['network_config']['gateways'])),
                'ip_assignment_methods': data['network_config']['ip_assignment_methods']
            },
            'listening_services': data['listening_services'],
            'user_accounts_summary': data['user_accounts_summary'],
            'system_hardening': data['system_hardening'],
            'hardware_info': data['hardware_info'],
            'smb_shares': data['smb_shares'],
            'last_reboot_time': data['last_reboot_time']
        }
        for sev, cve_dict in data['cves_by_severity'].items():
            def sort_key(cve_item):
                try:
                    score = float(cve_item['cvss_base_score'])
                except ValueError:
                    score = -1.0
                return (-score, cve_item['id'])

            final_structured_summary[asset_id]['cves_by_severity'][sev] = sorted(list(cve_dict.values()), key=sort_key)

    logging.info("--- Parsing Complete ---")
    return final_structured_summary


# --- Main execution block ---
if __name__ == "__main__":
    import sys

    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_json_file_name = "202505192107_6b88595fefa24e71b01945f045e54b63.json"
    default_json_file_path = os.path.join(script_dir, default_json_file_name)

    if len(sys.argv) > 1:
        json_file_path_arg = sys.argv[1]
    else:
        json_file_path_arg = default_json_file_path
        logging.info(f"[MAIN] No file path provided. Attempting to use default: '{json_file_path_arg}'")

    if not os.path.exists(json_file_path_arg):
        original_hardcoded_path = r"C:\Users\ed311\PycharmProjects\cyber_ask_assessment_tracker\media\scan_reports\202505192107_6b88595fefa24e71b01945f045e54b63.json"
        if os.path.exists(original_hardcoded_path):
            json_file_path_arg = original_hardcoded_path
            logging.info(
                f"[MAIN] Default relative path not found. Using original hardcoded path: '{json_file_path_arg}'")
        else:
            logging.critical(
                f"FATAL ERROR: Input JSON file not found at either '{json_file_path_arg}' or '{original_hardcoded_path}'.")
            sys.exit(1)

    parsed_asset_data = parse_tenable_scan_file(json_file_path_arg)

    if parsed_asset_data:
        logging.info("\n--- [DETAILED ASSET ASSESSMENT (Printed from __main__)] ---")
        for asset_id, data in parsed_asset_data.items():
            print(f"\n\n======================================================================")
            print(f"Asset Identifier: {asset_id}")
            print(f"======================================================================")
            print(f"  OS: {data.get('operating_system', 'N/A')}")
            print(f"  Last Reboot: {data.get('last_reboot_time', 'N/A')}")

            if data.get('hardware_info'):
                print(f"\n  --- Hardware Information ---")
                hi = data['hardware_info']
                print(f"    Manufacturer: {hi.get('manufacturer', 'N/A')}, Model: {hi.get('model', 'N/A')}")
                print(
                    f"    BIOS Version: {hi.get('bios_version', 'N/A')}, Release Date: {hi.get('bios_release_date', 'N/A')}")
                if hi.get('tpm_info'):
                    print(f"    TPM Info:")
                    for tpm in hi['tpm_info']:  # Iterate over all TPM entries
                        print(
                            f"      Manufacturer ID: {tpm.get('manufacturerid', 'N/A')}, Version: {tpm.get('manufacturerversion', 'N/A')}, Spec: {tpm.get('specversion', 'N/A')}")
                        print(
                            f"      Activated: {tpm.get('isactivated_initialvalue', 'N/A')}, Enabled: {tpm.get('isenabled_initialvalue', 'N/A')}, Owned: {tpm.get('isowned_initialvalue', 'N/A')}")

            if data.get('antivirus_details'):
                print(f"\n  --- Antivirus Details ---")
                for av_info in data['antivirus_details']:
                    print(f"    Product Name   : {av_info.get('product_name', 'N/A')}")
                    print(f"    Version        : {av_info.get('product_version', 'N/A')}")
                    print(f"    Engine Version : {av_info.get('engine_version', 'N/A')}")
                    print(f"    Signature Ver. : {av_info.get('signature_version', 'N/A')}")
                    if 'antispyware_signature_version' in av_info:
                        print(f"    Antispyware Ver: {av_info.get('antispyware_signature_version', 'N/A')}")
                    if 'signatures_last_updated' in av_info:
                        print(f"    Signatures Last Updated: {av_info.get('signatures_last_updated', 'N/A')}")
                    print(
                        f"    Reported by    : Plugin {av_info.get('plugin_source_id')} ({av_info.get('plugin_source_name')})")
                    print(f"  ----------------------------------")

            if data.get('installed_software'):
                print(f"\n  --- Installed Software ---")
                for sw in data['installed_software']:  # Print all software
                    print(
                        f"    - {sw.get('name', 'N/A')} (Version: {sw.get('version', 'N/A')}, Publisher: {sw.get('publisher', 'N/A')})")

            if data.get('network_config'):
                nc = data['network_config']
                print(f"\n  --- Network Configuration ---")
                if nc.get('mac_addresses'): print(f"    MAC Addresses: {', '.join(nc['mac_addresses'])}")

            if data.get('listening_services'):
                print(f"\n  --- Listening Services ---")
                for srv in data['listening_services']:  # Print all services
                    print(
                        f"    - Port: {srv.get('port')}/{srv.get('protocol')}, Process: {srv.get('process_name', 'N/A')} (PID: {srv.get('pid', 'N/A')}), Service: {srv.get('service_display_name', 'N/A')}")

            if data.get('user_accounts_summary'):
                uas = data['user_accounts_summary']
                print(f"\n  --- User Accounts & Policy ---")
                if uas.get('password_policy'):
                    print(f"    Password Policy:")
                    for key, val in uas['password_policy'].items(): print(f"      {key}: {val}")
                if uas.get('admin_group_members'):
                    print(f"    Admin Group Members: {', '.join([m['name'] for m in uas['admin_group_members']])}")

            if data.get('system_hardening'):
                print(f"\n  --- System Hardening Checks ---")
                for check in data['system_hardening']:  # Print all checks
                    print(
                        f"    - {check.get('check_name')}: {check.get('status_detail')} (Plugin: {check.get('plugin_id_source')})")

            if data.get('smb_shares'):
                print(f"\n  --- SMB Shares ---")
                print(f"    {', '.join([s.get('share_name') for s in data['smb_shares']])}")

            print(f"\n  --- CVEs by Severity ---")
            any_cves_for_host = False
            for severity_level in SEVERITY_LEVELS:
                cves_list = data['cves_by_severity'].get(severity_level, [])
                if cves_list:
                    any_cves_for_host = True
                    print(f"\n  [{severity_level.upper()} CVEs: {len(cves_list)}]")
                    for cve_info in cves_list:
                        print(f"    ----------------------------------")
                        print(f"      CVE ID         : {cve_info['id']}")
                        print(f"      Plugin ID      : {cve_info['plugin_id']}")
                        print(f"      Plugin Name    : {cve_info['plugin_name']}")  # Full name
                        print(f"      CVSS Version   : {cve_info['cvss_version']}")
                        print(f"      CVSS Base Score: {cve_info['cvss_base_score']}")
                        print(
                            f"      Description    : {cve_info['description'].replace('\n', ' ')}")  # Full description
            if not any_cves_for_host:
                print("\n     No CVEs found for this host in the scan data.")

            print(f"\n  --- Cyber Essentials Plus Automated Assessment Summary ---")
            if data.get('ce_plus_assessment_failures'):
                print(f"    Status: POTENTIAL FAILURES IDENTIFIED")
                print(f"    Reasons:")
                for failure in data['ce_plus_assessment_failures']:
                    print(f"      - {failure}")
            else:
                print(f"    Status: PASS (based on automated checks for patching and AV presence/details)")
            print(f"======================================================================")
    else:
        logging.info("[MAIN] No data was parsed or an error occurred during parsing.")

