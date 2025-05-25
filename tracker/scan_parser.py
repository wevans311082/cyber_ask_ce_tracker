# CHANGES BEGIN — GGGGGGGGGGGG-2025-05-18 19:45:00
# File: tracker/scan_parser.py
# Description: Parses Tenable.io JSON scan data and populates Django models.
# Previous change: GGGGGGGGGGGG-2025-05-18 19:30:00

import json
import os
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone as pytimezone
import uuid

from django.conf import settings
from django.utils import timezone as django_timezone
from django.db import transaction, IntegrityError

from .models import (
    ScopedItem,
    Assessment,
    TenableScanLog,
    OperatingSystem,
    AssetScanDataSnapshot,
    AssetInstalledSoftware,
    AssetAntivirusDetail,
    AssetListeningService
)

# --- Configuration from your POC ---
SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']
NUMERIC_SEVERITY_MAP = {
    4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info'
}
AV_PLUGIN_IDS = {
    16193: "Antivirus Software Check", 131023: "Windows Defender Installed",
    26917: "Symantec AntiVirus Corporate Edition Detection",
    25716: "McAfee VirusScan Enterprise Detection"
}
CE_PLUS_PATCH_WINDOW_DAYS = 14
CE_PLUS_CVSS_THRESHOLD = 7.0
CE_PLUS_AV_SIGNATURE_AGE_DAYS = 7

# Plugin ID Mappings for refactored functions
PLUGIN_LAST_REBOOT = 92366
PLUGIN_SYSINFO_MFR_MODEL = 24270
PLUGINS_BIOS = [34096, 34097]
PLUGIN_TPM = 51186
PLUGIN_MAC_ADDRESS = 24272
PLUGINS_SOFTWARE = [20811, 178102, 200493]
# AV_PLUGIN_IDS is already defined above
PLUGIN_LISTENING_PORTS = 34252
PLUGIN_PASSWORD_POLICY = 17651
PLUGIN_ADMIN_GROUP_MEMBERS = 10902
PLUGIN_SMB_SHARES = 10395
HARDENING_CHECKS_MAP = {
    48763: "CWDIllegalInDllSearch", 159817: "Credential Guard Status", 159929: "LSA Protection Status",
    160486: "SMB Protocol Version", 161691: "MSDT RCE Workaround", 162174: "AlwaysInstallElevated Status",
    92367: "PowerShell Execution Policy", 11457: "Cached Logons Count", 160301: "LLMNR Status",
    166555: "WinVerifyTrust Signature Validation"
}

logger = logging.getLogger(__name__)
print("[PARSER PRINT] scan_parser.py module loaded.")


# --- Helper Functions (parse_datetime_flexible, safe_get, add_if_not_present) ---
# (These remain the same as the version in id="scan_parser_py" with timestamp GGGGGGGGGGGG-2025-05-18 19:30:00)
# For brevity, I'll omit them here but assume they are present and correct.
def parse_datetime_flexible(date_string):
    # print(f"[PARSER PRINT HELPER] parse_datetime_flexible called with: '{date_string}'")
    if not date_string or not isinstance(date_string, str): return None
    if 'T' in date_string and date_string.endswith('Z'):
        try:
            return datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        except ValueError:
            logger.debug(f"Could not parse ISO Z: {date_string}")
    if "GMT" in date_string.upper():
        date_part = date_string.upper().replace(" GMT", "").strip()
        formats_to_try = ['%b %d, %Y AT %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%Y/%m/%d %H:%M:%S']
        for fmt in formats_to_try:
            try:
                return datetime.strptime(date_part, fmt).replace(tzinfo=pytimezone.utc)
            except ValueError:
                continue
        logger.debug(f"Could not parse GMT: {date_string}")
    try:
        dt_obj = datetime.fromisoformat(date_string)
        if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
            return dt_obj.replace(tzinfo=pytimezone.utc)
        return dt_obj
    except ValueError:
        logger.debug(f"Could not parse ISO: {date_string}")
    match = re.match(r"(\d{14})\.\d{6}([+-]\d{3,4})", date_string)
    if match:
        try:
            dt_naive = datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
            offset_str = match.group(2)
            offset_minutes_total = 0
            if len(offset_str) >= 4 and offset_str[1:3].isdigit():
                offset_hours = int(offset_str[1:3])
                offset_minutes_total = offset_hours * 60
                if len(offset_str) == 5 and offset_str[3:5].isdigit():
                    offset_mins_part = int(offset_str[3:5])
                    offset_minutes_total += offset_mins_part
            elif len(offset_str) == 3 and offset_str[1:].isdigit():
                offset_minutes_total = int(offset_str[1:])
                if offset_str[0] == '-':
                    offset_minutes_total = -offset_minutes_total
            if offset_str.startswith('-') and not (len(offset_str) == 3 and offset_str[1:].isdigit()):
                offset_minutes_total = -offset_minutes_total

            return dt_naive.replace(tzinfo=pytimezone(timedelta(minutes=offset_minutes_total)))
        except ValueError as e:
            logger.warning(f"Could not parse BIOS-like date '{date_string}': {e}")
    return None


def safe_get(data, keys, default=None):
    for key in keys:
        if isinstance(data, dict) and key in data:
            data = data[key]
        else:
            return default
    return data


def add_if_not_present(target_list, item_to_add, key_to_check='name'):
    if isinstance(item_to_add, str) and key_to_check is None:
        if item_to_add not in target_list: target_list.append(item_to_add)
        return
    if not isinstance(item_to_add, dict) or (
            key_to_check and key_to_check not in item_to_add and item_to_add.get(key_to_check) is not None):
        if isinstance(item_to_add, dict) and key_to_check is None:
            if item_to_add not in target_list: target_list.append(item_to_add)
        return

    is_present = False
    if key_to_check:
        for existing_item in target_list:
            if isinstance(existing_item, dict) and \
                    existing_item.get(key_to_check) == item_to_add.get(key_to_check) and \
                    item_to_add.get(key_to_check) is not None:
                is_present = True;
                break
    elif isinstance(item_to_add, dict):
        if item_to_add in target_list: is_present = True

    if not is_present: target_list.append(item_to_add)


# --- Refactored Parsing Sub-functions ---

def _parse_last_reboot(finding_output, asset_snapshot):
    print(f"    [PARSER SUB] _parse_last_reboot for snapshot {asset_snapshot.id}")
    reboot_match = re.search(r"Last reboot\s*:\s*(.+)", finding_output)
    if reboot_match:
        parsed_reboot_time_dt = parse_datetime_flexible(reboot_match.group(1).strip().split('(')[0].strip())
        if parsed_reboot_time_dt:
            asset_snapshot.last_reboot_time = parsed_reboot_time_dt
            print(f"      Set last_reboot_time: {asset_snapshot.last_reboot_time}")


def _parse_hardware_info(finding_output, current_plugin_id, hw_info_agg_dict):
    print(f"    [PARSER SUB] _parse_hardware_info for plugin {current_plugin_id}")
    if current_plugin_id == PLUGIN_SYSINFO_MFR_MODEL:
        mfr_match = re.search(r"Computer Manufacturer\s*:\s*(.+)", finding_output)
        model_match = re.search(r"Computer Model\s*:\s*(.+)", finding_output)
        if mfr_match: hw_info_agg_dict['manufacturer'] = mfr_match.group(1).strip(); print(
            f"      HW Mfr: {hw_info_agg_dict['manufacturer']}")
        if model_match: hw_info_agg_dict['model'] = model_match.group(1).strip(); print(
            f"      HW Model: {hw_info_agg_dict['model']}")
    elif current_plugin_id in PLUGINS_BIOS:
        version_match = re.search(r"Version\s*:\s*([^\n]+)", finding_output)
        release_date_match = re.search(r"Release date\s*:\s*([^\n]+)", finding_output)
        if version_match: hw_info_agg_dict['bios_version'] = version_match.group(1).strip(); print(
            f"      BIOS Version: {hw_info_agg_dict['bios_version']}")
        if release_date_match:
            parsed_bios_date = parse_datetime_flexible(release_date_match.group(1).strip())
            hw_info_agg_dict[
                'bios_release_date'] = parsed_bios_date.isoformat() if parsed_bios_date else release_date_match.group(
                1).strip()
            print(f"      BIOS Date: {hw_info_agg_dict['bios_release_date']}")
    elif current_plugin_id == PLUGIN_TPM:
        if 'tpm_info' not in hw_info_agg_dict: hw_info_agg_dict['tpm_info'] = []
        tpm_details = {}
        for line in finding_output.strip().split('\n'):
            if ':' in line: key, value = line.split(':', 1); tpm_details[
                key.strip().lower().replace(' ', '_')] = value.strip()
        if tpm_details: add_if_not_present(hw_info_agg_dict['tpm_info'], tpm_details, 'manufacturerid'); print(
            f"      Added TPM Details: {tpm_details}")


def _parse_network_config(finding_output, current_plugin_id, net_conf_agg_dict):
    print(f"    [PARSER SUB] _parse_network_config for plugin {current_plugin_id}")
    if current_plugin_id == PLUGIN_MAC_ADDRESS:
        current_interface_macs = re.findall(r"MAC Address\s*=\s*([0-9A-Fa-f:]{17})", finding_output)
        for mac in current_interface_macs: net_conf_agg_dict['mac_addresses'].add(mac.upper()); print(
            f"      Found MAC: {mac.upper()}")
    # Add DNS (e.g. plugin 6445), Gateways (e.g. plugin 10150) here


def _parse_installed_software(finding_output, asset_snapshot, current_plugin_id):
    print(f"    [PARSER SUB] _parse_installed_software for plugin {current_plugin_id}, snapshot {asset_snapshot.id}")
    for line_idx, line in enumerate(finding_output.strip().split('\n')):
        line = line.strip()
        if not line or line.startswith("The following software") or line.startswith("Nessus detected"): continue
        name_part = line.split(' [version')[0].split(' [installed on')[0].strip()
        if name_part.startswith("- "): name_part = name_part[2:].strip()
        if not name_part: continue
        version_match = re.search(r'\[version\s+([^\]]+)\]', line);
        version = version_match.group(1).strip() if version_match else None
        publisher = None;
        install_path = None
        if current_plugin_id == 178102:  # Example of plugin-specific publisher extraction
            publisher_match = re.search(r"\[Publisher\]\s*:\s*Raw Value\s*:\s*([^\n]+)", finding_output, re.IGNORECASE)
            if publisher_match: publisher = publisher_match.group(1).strip()
        if name_part:
            print(
                f"      Software Candidate line {line_idx}: Name='{name_part}', Version='{version}', Publisher='{publisher}'")
            AssetInstalledSoftware.objects.update_or_create(
                asset_scan_snapshot=asset_snapshot, name__iexact=name_part, version=version,
                # Make version part of uniqueness if desired
                defaults={'name': name_part, 'publisher': publisher, 'install_path': install_path,
                          'plugin_id_source': current_plugin_id}
            )


def _parse_antivirus(finding_output, asset_snapshot, current_plugin_id):
    print(f"    [PARSER SUB] _parse_antivirus for plugin {current_plugin_id}, snapshot {asset_snapshot.id}")
    av_data = {'plugin_source_id': current_plugin_id, 'plugin_source_name': AV_PLUGIN_IDS.get(current_plugin_id)}
    # ... (Detailed AV parsing logic from your POC) ...
    lines = finding_output.strip().split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            k = key.strip().lower().replace(' ', '_').replace('.', '');
            v = value.strip()
            if k == "product_name":
                av_data['product_name'] = v
            elif k == "version":
                av_data['product_version'] = v
            elif k == "engine_version":
                av_data['engine_version'] = v
            elif k in ["antivirus_signature_version", "malware_signature_version"]:
                av_data['signature_version'] = v
            elif k == "antispyware_signature_version":
                av_data['antispyware_signature_version'] = v
            elif k in ["signatures_last_updated", "malware_signature_timestamp"]:
                av_data['signatures_last_updated_text'] = v
            elif k == "path":
                av_data['install_path'] = v
    if av_data.get('product_name'):
        print(f"      AV Product: {av_data.get('product_name')}, Version: {av_data.get('product_version')}")
        av_data['signatures_last_updated_dt'] = parse_datetime_flexible(av_data.get('signatures_last_updated_text'))
        AssetAntivirusDetail.objects.update_or_create(
            asset_scan_snapshot=asset_snapshot, product_name__iexact=av_data['product_name'],
            defaults=av_data
        )


def _parse_listening_services(finding_output, asset_snapshot, current_plugin_id):
    print(f"    [PARSER SUB] _parse_listening_services for plugin {current_plugin_id}, snapshot {asset_snapshot.id}")
    try:
        service_data_outer = json.loads(finding_output)
        listening_ports = safe_get(service_data_outer, ['listening'], [])
        for port_info in listening_ports:
            port = safe_get(port_info, ['port']);
            protocol = safe_get(port_info, ['protocol'])
            # ... (Detailed extraction from your POC) ...
            plugin_output_detail = safe_get(port_info, ['plugin_output'], "")
            process_name_match = re.search(r"The Win32 process '([^']+)' is listening", plugin_output_detail)
            process_name = process_name_match.group(1) if process_name_match else None
            pid_match = re.search(r"\(pid (\d+|N/A)\)", plugin_output_detail)
            pid = pid_match.group(1) if pid_match else None
            service_name_match = re.search(r"hosting the following Windows services :\\n(.*?)\\n", plugin_output_detail,
                                           re.DOTALL)
            service_display_name = service_name_match.group(1).strip().split('(')[
                0].strip() if service_name_match else None
            if port and protocol:
                print(f"      Listening Service: {protocol}/{port}, Process: {process_name}")
                AssetListeningService.objects.update_or_create(
                    asset_scan_snapshot=asset_snapshot, port=int(port), protocol=protocol.upper(),
                    defaults={'process_name': process_name, 'pid': pid,
                              'service_display_name': service_display_name, 'plugin_id_source': current_plugin_id}
                )
    except json.JSONDecodeError:
        print(f"    [PARSER SUB WARNING] JSONDecodeError for listening services plugin {current_plugin_id}")
        logger.warning(f"JSONDecodeError plugin {current_plugin_id} for snapshot {asset_snapshot.id}")


def _parse_user_accounts(finding_output, current_plugin_id, usr_acc_agg_dict):
    print(f"    [PARSER SUB] _parse_user_accounts for plugin {current_plugin_id}")
    if current_plugin_id == PLUGIN_PASSWORD_POLICY:
        for line in finding_output.strip().split('\n'):
            if ':' in line: key, value = line.split(':', 1); usr_acc_agg_dict['password_policy'][
                key.strip()] = value.strip()
        print(f"      Updated password policy: {usr_acc_agg_dict['password_policy']}")
    elif current_plugin_id == PLUGIN_ADMIN_GROUP_MEMBERS:
        members = re.findall(r"-\s*(.*?)\s*\((User|Group)\)", finding_output)
        for name, type in members:
            add_if_not_present(usr_acc_agg_dict['admin_group_members'], {'name': name.strip(), 'type': type.strip()},
                               'name')
            print(f"      Admin Member: {name.strip()} ({type.strip()})")


def _parse_system_hardening(finding_output, current_plugin_id, sys_hard_agg_list):
    check_name = HARDENING_CHECKS_MAP.get(current_plugin_id)
    print(f"    [PARSER SUB] _parse_system_hardening for plugin {current_plugin_id} ({check_name})")
    status_detail = finding_output.strip().replace('\n', ' | ')
    check_item = {'check_name': check_name, 'status_detail': status_detail, 'plugin_id_source': current_plugin_id}
    add_if_not_present(sys_hard_agg_list, check_item, 'check_name')
    print(f"      Hardening Check: {check_name}, Status: {status_detail}")


def _parse_smb_shares(finding_output, current_plugin_id, smb_shares_agg_list):
    print(f"    [PARSER SUB] _parse_smb_shares for plugin {current_plugin_id}")
    shares = re.findall(r"-\s*([A-Za-z0-9\$_-]+)", finding_output)
    for share_name in shares:
        add_if_not_present(smb_shares_agg_list, {'share_name': share_name, 'access_details': 'Enumerated'},
                           'share_name')
        print(f"      SMB Share: {share_name}")


def _evaluate_ce_plus_failures_for_finding(finding, plugin_info, current_plugin_id, ce_plus_failures_agg_list):
    # This function would encapsulate the logic for unsupported software and patching window from your POC
    # based on a single finding.
    print(f"    [PARSER SUB] _evaluate_ce_plus_failures_for_finding for plugin {current_plugin_id}")
    # ... (Detailed logic from POC for unsupported software & patching window) ...
    # Example (simplified):
    raw_severity_finding = finding.get('severity')
    normalized_severity_key = 'info'
    if isinstance(raw_severity_finding, int): normalized_severity_key = NUMERIC_SEVERITY_MAP.get(raw_severity_finding,
                                                                                                 'info').lower()
    # ... (rest of severity and CVSS logic) ...
    is_critical_or_high_vuln = normalized_severity_key in ['critical', 'high']  # Simplified

    if plugin_info.get('unsupported_by_vendor', False) and is_critical_or_high_vuln:
        msg = f"Unsupported software (Plugin: {current_plugin_id})"
        add_if_not_present(ce_plus_failures_agg_list, msg, None);
        print(f"      CE+ Failure (Unsupported): {msg}")
    # ... (Patching window logic) ...


# --- Main Parsing Function (Refactored) ---

@transaction.atomic
def process_scan_data_into_models(scan_log_id: uuid.UUID):
    print(f"[PARSER PRINT] process_scan_data_into_models called for scan_log_id: {scan_log_id}")
    logger.info(f"[PARSER LOGGER] process_scan_data_into_models called for scan_log_id: {scan_log_id}")
    try:
        scan_log = TenableScanLog.objects.select_related('assessment', 'assessment__client').get(id=scan_log_id)
        print(f"[PARSER PRINT] Found ScanLog: {scan_log}")
        logger.info(f"[PARSER LOGGER] Found ScanLog: {scan_log}")
    except TenableScanLog.DoesNotExist:
        print(f"[PARSER PRINT ERROR] TenableScanLog {scan_log_id} not found.")
        logger.error(f"TenableScanLog {scan_log_id} not found.")
        return False, "Scan log not found."

    if not scan_log.saved_report_path:
        print(f"[PARSER PRINT ERROR] No saved_report_path for TenableScanLog {scan_log_id}.")
        logger.error(f"No saved_report_path for TenableScanLog {scan_log_id}.")
        return False, "Scan report path not recorded."

    full_report_path = os.path.join(settings.MEDIA_ROOT, scan_log.saved_report_path)
    print(f"[PARSER PRINT] Attempting to parse file: {full_report_path}")
    logger.info(f"[PARSER LOGGER] Attempting to parse file: {full_report_path}")

    if not os.path.exists(full_report_path):
        print(f"[PARSER PRINT ERROR] File not found: {full_report_path}")
        logger.error(f"File not found: {full_report_path}")
        return False, f"Scan report file not found: {os.path.basename(scan_log.saved_report_path)}" # Return only filename

    # --- MODIFICATIONS START HERE ---
    try:
        # Check for empty file before attempting to load
        if os.path.getsize(full_report_path) == 0:
            print(f"[PARSER PRINT ERROR] JSON file is empty: {full_report_path}")
            logger.error(f"JSON file is empty: {full_report_path}")
            return False, f"Scan report file '{os.path.basename(scan_log.saved_report_path)}' is empty."

        with open(full_report_path, 'r', encoding='utf-8') as f:
            raw_scan_findings = json.load(f)
        print(f"[PARSER PRINT] Loaded JSON. Type: {type(raw_scan_findings)}")
        logger.info(f"[PARSER LOGGER] Loaded JSON. Type: {type(raw_scan_findings)}")

    except json.JSONDecodeError as e:
        print(f"[PARSER PRINT ERROR] Invalid JSON in file {full_report_path}: {e}")
        logger.error(f"Invalid JSON in file {full_report_path}: {e}")
        return False, f"Invalid JSON format in '{os.path.basename(scan_log.saved_report_path)}': {e.msg} (line {e.lineno} col {e.colno})"
    except Exception as e:
        print(f"[PARSER PRINT ERROR] Error loading or reading JSON file {full_report_path}: {e}")
        logger.exception(f"Error loading or reading JSON file {full_report_path}: {e}") # Use logger.exception for stack trace
        return False, f"Error reading scan report file '{os.path.basename(scan_log.saved_report_path)}': {e}"

    if not isinstance(raw_scan_findings, list):
        print(f"[PARSER PRINT ERROR] Expected list of findings in JSON, got {type(raw_scan_findings).__name__}.")
        logger.error(f"Expected list of findings in JSON, got {type(raw_scan_findings).__name__}.")
        return False, f"Invalid scan format in '{os.path.basename(scan_log.saved_report_path)}': expected a list of findings."

    if not raw_scan_findings: # Checks if the list is empty
        print(f"[PARSER PRINT WARNING] JSON file loaded successfully but contains no findings: {full_report_path}")
        logger.warning(f"JSON file loaded successfully but contains no findings: {full_report_path}")
        # You might want to still mark as parsed or handle differently
        scan_log.data_parsed_at = django_timezone.now()
        scan_log.save(update_fields=['data_parsed_at', 'updated_at'])
        return True, f"Scan report '{os.path.basename(scan_log.saved_report_path)}' processed successfully, but contained no findings."
    # --- MODIFICATIONS END HERE ---

    print(f"[PARSER PRINT] JSON loaded, found {len(raw_scan_findings)} entries to process.")
    logger.info(f"[PARSER LOGGER] JSON loaded, found {len(raw_scan_findings)} entries to process.")


    scoped_item_cache = {}
    snapshot_cache = {}
    asset_aggregated_data = defaultdict(lambda: {
        'hardware_info': {},
        'network_config': {'mac_addresses': set(), 'dns_servers': set(), 'gateways': set(),
                           'ip_assignment_methods': []},
        'user_accounts_summary': {'password_policy': {}, 'admin_group_members': [], 'local_users': []},
        'system_hardening': [],
        'smb_shares': [],
        'ce_plus_assessment_failures': [],
        'cves_by_severity': {sev: {} for sev in SEVERITY_LEVELS}
    })
    print(f"[PARSER PRINT] Initialized caches and aggregated_data store.")

    # ... (rest of your parsing logic for findings) ...
    # Ensure the rest of the function correctly iterates through raw_scan_findings

    for i, finding in enumerate(raw_scan_findings):
        print(f"\n[PARSER PRINT] --- Processing Finding {i + 1} of {len(raw_scan_findings)} ---")
        if not isinstance(finding, dict):
            print(f"[PARSER PRINT WARNING] Finding {i + 1} not a dict. Skipping.")
            logger.warning(f"Finding {i + 1} not a dict. Skipping.")
            continue

        asset_info = finding.get('asset', {})
        plugin_info = finding.get('plugin', {})
        finding_output = finding.get('output', "")
        current_plugin_id = safe_get(plugin_info, ['id'])
        print(
            f"[PARSER PRINT Finding {i + 1}] Asset Info: {asset_info.get('hostname', asset_info.get('uuid'))}, Plugin ID: {current_plugin_id}")

        tenable_asset_uuid = str(safe_get(asset_info, ['uuid'])) if safe_get(asset_info, ['uuid']) else None
        hostname = safe_get(asset_info, ['hostname'])
        scoped_item_identifier_value = tenable_asset_uuid or hostname

        if not scoped_item_identifier_value:
            print(f"[PARSER PRINT WARNING Finding {i + 1}] Lacks asset UUID and hostname. Skipping.")
            logger.warning(f"Finding {i + 1} lacks asset UUID and hostname. Skipping.")
            continue
        print(f"[PARSER PRINT Finding {i + 1}] Determined ScopedItem Identifier: {scoped_item_identifier_value}")

        scoped_item = scoped_item_cache.get(scoped_item_identifier_value)
        if not scoped_item:
            print(
                f"[PARSER PRINT Finding {i + 1}] ScopedItem '{scoped_item_identifier_value}' not in cache. Querying DB.")
            try:
                scoped_item_defaults = {
                    'item_type': 'Server' if hostname and 'server' in hostname.lower() else (
                        'Desktop' if hostname else 'Other'),
                }
                scoped_item, created = ScopedItem.objects.get_or_create(
                    identifier=scoped_item_identifier_value,
                    assessment=scan_log.assessment,
                    defaults=scoped_item_defaults
                )
                if created:
                    print(
                        f"[PARSER PRINT Finding {i + 1}] Created ScopedItem: '{scoped_item_identifier_value}' (ID: {scoped_item.id}) with defaults: {scoped_item_defaults}")
                    logger.info(
                        f"Created ScopedItem: '{scoped_item_identifier_value}' for Assessment {scan_log.assessment.id}")
                else:
                    print(
                        f"[PARSER PRINT Finding {i + 1}] Found existing ScopedItem: '{scoped_item_identifier_value}' (ID: {scoped_item.id})")
                scoped_item_cache[scoped_item_identifier_value] = scoped_item
            except IntegrityError as e:
                print(
                    f"[PARSER PRINT WARNING Finding {i + 1}] IntegrityError for ScopedItem '{scoped_item_identifier_value}': {e}. Fetching.")
                logger.warning(f"IntegrityError for ScopedItem '{scoped_item_identifier_value}': {e}. Fetching.")
                try:
                    scoped_item = ScopedItem.objects.get(identifier=scoped_item_identifier_value,
                                                         assessment=scan_log.assessment)
                    scoped_item_cache[scoped_item_identifier_value] = scoped_item
                    print(
                        f"[PARSER PRINT Finding {i + 1}] Found ScopedItem after IntegrityError: '{scoped_item_identifier_value}' (ID: {scoped_item.id})")
                except ScopedItem.DoesNotExist:
                    print(
                        f"[PARSER PRINT ERROR Finding {i + 1}] Failed to get ScopedItem '{scoped_item_identifier_value}' after IntegrityError. Skipping.")
                    logger.error(
                        f"Failed to get ScopedItem '{scoped_item_identifier_value}' after IntegrityError. Skipping.")
                    continue
            except Exception as e:
                print(
                    f"[PARSER PRINT ERROR Finding {i + 1}] Error get/create ScopedItem '{scoped_item_identifier_value}': {e}")
                logger.exception(f"Error get/create ScopedItem '{scoped_item_identifier_value}': {e}. Skipping.")
                continue
        else:
            print(
                f"[PARSER PRINT Finding {i + 1}] ScopedItem '{scoped_item_identifier_value}' (ID: {scoped_item.id}) found in cache.")

        snapshot_key = (scoped_item.id, scan_log.id)
        asset_snapshot = snapshot_cache.get(snapshot_key)
        if not asset_snapshot:
            print(
                f"[PARSER PRINT Finding {i + 1}] AssetScanDataSnapshot not in cache for ScopedItem {scoped_item.id}. Querying DB.")
            parsed_os_from_asset_list = safe_get(asset_info, ['operating_system'], [])
            parsed_os_from_asset = parsed_os_from_asset_list[0] if isinstance(parsed_os_from_asset_list,
                                                                              list) and parsed_os_from_asset_list else (
                parsed_os_from_asset_list if isinstance(parsed_os_from_asset_list, str) else None)
            print(f"[PARSER PRINT Finding {i + 1}] Initial parsed_os_from_asset: {parsed_os_from_asset}")

            asset_snapshot, created = AssetScanDataSnapshot.objects.update_or_create(
                scoped_item=scoped_item,
                scan_log=scan_log,
                defaults={'parsed_operating_system': parsed_os_from_asset}
            )
            if created:
                print(
                    f"[PARSER PRINT Finding {i + 1}] Created AssetScanDataSnapshot (ID: {asset_snapshot.id}) for ScopedItem {scoped_item.id}")
                logger.info(f"Created AssetScanDataSnapshot for ScopedItem {scoped_item.id}, ScanLog {scan_log.id}")
            else:
                print(
                    f"[PARSER PRINT Finding {i + 1}] Found existing AssetScanDataSnapshot (ID: {asset_snapshot.id}) for ScopedItem {scoped_item.id}")
            snapshot_cache[snapshot_key] = asset_snapshot
        else:
            print(f"[PARSER PRINT Finding {i + 1}] AssetScanDataSnapshot (ID: {asset_snapshot.id}) found in cache.")

        agg_data_key = asset_snapshot.id
        print(
            f"[PARSER PRINT Finding {i + 1}] Using agg_data_key (Snapshot ID): {agg_data_key} for plugin {current_plugin_id}")

        if current_plugin_id == PLUGIN_LAST_REBOOT:
            _parse_last_reboot(finding_output, asset_snapshot)
        elif current_plugin_id == PLUGIN_SYSINFO_MFR_MODEL or \
                current_plugin_id in PLUGINS_BIOS or \
                current_plugin_id == PLUGIN_TPM:
            _parse_hardware_info(finding_output, current_plugin_id,
                                 asset_aggregated_data[agg_data_key]['hardware_info'])
        elif current_plugin_id == PLUGIN_MAC_ADDRESS:
            _parse_network_config(finding_output, current_plugin_id,
                                  asset_aggregated_data[agg_data_key]['network_config'])
        elif current_plugin_id in PLUGINS_SOFTWARE:
            _parse_installed_software(finding_output, asset_snapshot, current_plugin_id)
        elif current_plugin_id in AV_PLUGIN_IDS:
            _parse_antivirus(finding_output, asset_snapshot, current_plugin_id)
        elif current_plugin_id == PLUGIN_LISTENING_PORTS:
            _parse_listening_services(finding_output, asset_snapshot, current_plugin_id)
        elif current_plugin_id == PLUGIN_PASSWORD_POLICY or \
                current_plugin_id == PLUGIN_ADMIN_GROUP_MEMBERS:
            _parse_user_accounts(finding_output, current_plugin_id,
                                 asset_aggregated_data[agg_data_key]['user_accounts_summary'])
        elif current_plugin_id in HARDENING_CHECKS_MAP:
            _parse_system_hardening(finding_output, current_plugin_id,
                                    asset_aggregated_data[agg_data_key]['system_hardening'])
        elif current_plugin_id == PLUGIN_SMB_SHARES:
            _parse_smb_shares(finding_output, current_plugin_id, asset_aggregated_data[agg_data_key]['smb_shares'])

        if plugin_info:
            _evaluate_ce_plus_failures_for_finding(finding, plugin_info, current_plugin_id,
                                                   asset_aggregated_data[agg_data_key]['ce_plus_assessment_failures'])
    # --- End of loop through findings ---

    print(f"\n[PARSER PRINT] --- Finalizing and Saving Aggregated Data ({len(asset_aggregated_data)} assets) ---")
    saved_snapshots_count = 0
    for snapshot_id_key, agg_item_data in asset_aggregated_data.items():
        print(f"[PARSER PRINT] Finalizing snapshot ID: {snapshot_id_key}")
        try:
            snapshot_instance = AssetScanDataSnapshot.objects.get(id=snapshot_id_key)
            print(f"  Retrieved snapshot instance: {snapshot_instance}")

            # ... (rest of the aggregation saving logic) ...
            snapshot_instance.hardware_info_json = agg_item_data['hardware_info']
            agg_item_data['network_config']['mac_addresses'] = sorted(
                list(agg_item_data['network_config']['mac_addresses']))
            agg_item_data['network_config']['dns_servers'] = sorted(
                list(agg_item_data['network_config']['dns_servers']))
            agg_item_data['network_config']['gateways'] = sorted(list(agg_item_data['network_config']['gateways']))
            snapshot_instance.network_config_json = agg_item_data['network_config']
            snapshot_instance.user_accounts_summary_json = agg_item_data['user_accounts_summary']
            snapshot_instance.system_hardening_json = agg_item_data['system_hardening']
            snapshot_instance.smb_shares_json = agg_item_data['smb_shares']
            av_details_for_snapshot = list(snapshot_instance.antivirus_products.all())
            ce_plus_failures_list = agg_item_data[
                'ce_plus_assessment_failures']
            print(f"  Initial CE+ failures for snapshot from findings loop: {ce_plus_failures_list}")

            if not av_details_for_snapshot:
                print("  No AV details found for snapshot, adding CE+ failure.")
                add_if_not_present(ce_plus_failures_list, "Antivirus: No Antivirus software detected.", None)
            else:
                for av_product in av_details_for_snapshot:
                    product_name_for_msg = av_product.product_name or "Unknown AV Product"
                    print(f"  Checking AV Product: {product_name_for_msg}")
                    if not av_product.product_version or not av_product.signature_version:
                        msg = f"Antivirus: '{product_name_for_msg}' reported with missing critical details (e.g., product/signature version)."
                        add_if_not_present(ce_plus_failures_list, msg, None);
                        print(f"    AV Failure: {msg}")

                    scan_date_ref = django_timezone.localtime(scan_log.created_at) if django_timezone.is_aware(
                        scan_log.created_at) else django_timezone.make_aware(scan_log.created_at)
                    if av_product.signatures_last_updated_dt:
                        sig_updated_dt_aware = django_timezone.localtime(
                            av_product.signatures_last_updated_dt) if django_timezone.is_aware(
                            av_product.signatures_last_updated_dt) else django_timezone.make_aware(
                            av_product.signatures_last_updated_dt)
                        if (scan_date_ref - sig_updated_dt_aware).days > CE_PLUS_AV_SIGNATURE_AGE_DAYS:
                            days_old = (scan_date_ref - sig_updated_dt_aware).days
                            msg = f"Antivirus: '{product_name_for_msg}' signatures outdated ({days_old} days old, ref date {scan_date_ref.strftime('%Y-%m-%d')})."
                            add_if_not_present(ce_plus_failures_list, msg, None);
                            print(f"    AV Failure: {msg}")
                    elif not av_product.signatures_last_updated_text: # If no timestamp, check if text was present
                        msg = f"Antivirus: '{product_name_for_msg}' signature update status or date could not be determined."
                        add_if_not_present(ce_plus_failures_list, msg, None);
                        print(f"    AV Failure: {msg}")


            snapshot_instance.ce_plus_assessment_failures_json = sorted(
                list(set(ce_plus_failures_list)))
            print(f"  Final CE+ failures for snapshot: {snapshot_instance.ce_plus_assessment_failures_json}")
            snapshot_instance.save()
            print(f"  SAVED snapshot instance ID: {snapshot_instance.id}")
            saved_snapshots_count += 1
        except AssetScanDataSnapshot.DoesNotExist:
            print(f"[PARSER PRINT ERROR] Snapshot with ID {snapshot_id_key} not found during final save.")
            logger.error(f"Snapshot with ID {snapshot_id_key} not found during final save. This should not happen.")
        except Exception as e:
            print(f"[PARSER PRINT ERROR] Error saving final AssetScanDataSnapshot for ID {snapshot_id_key}: {e}")
            logger.exception(f"Error saving final AssetScanDataSnapshot for ID {snapshot_id_key}: {e}")


    print(f"[PARSER PRINT] Processed and attempted to save data for {saved_snapshots_count} asset snapshots.")
    logger.info(f"Processed and saved data for {saved_snapshots_count} asset snapshots.")

    scan_log.data_parsed_at = django_timezone.now()
    scan_log.save(update_fields=['data_parsed_at', 'updated_at']) # Ensure updated_at is also in the list
    print(f"[PARSER PRINT] Updated scan_log {scan_log.id} with data_parsed_at: {scan_log.data_parsed_at}")

    return True, f"Successfully parsed {len(raw_scan_findings) if raw_scan_findings else 0} findings, affecting {saved_snapshots_count} assets."
# ... (Helper functions: parse_datetime_flexible, safe_get, add_if_not_present - assume they are correctly defined as per your file)
# ... (Sub-parsing functions: _parse_last_reboot, _parse_hardware_info, etc. - assume they are correctly defined)


