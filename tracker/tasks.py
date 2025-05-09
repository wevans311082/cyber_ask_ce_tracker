# tracker/tasks.py (Corrected create_or_update_tenable_client_tag function - Second Fix)

# --- Keep your existing imports ---
import logging
from celery import shared_task
from django.core.exceptions import ObjectDoesNotExist
from tenable.errors import APIError, NotFoundError, ForbiddenError
from .models import Client, Assessment, ScopedItem, ExternalIP
from .tenable_client import get_tenable_io_client, get_scan_details, find_scan_by_name, create_agent_scan, launch_scan, get_tenable_io_client, find_scan_by_name, create_agent_scan, launch_scan_on_tenable, get_agent_group_details_by_name
from .tenable_client import create_agent_scan, find_scan_by_name
import requests
from bs4 import BeautifulSoup
from celery import shared_task
from constance import config
from django.utils import timezone
from cyber_ask_assessment_tracker.celery import app
from urllib.parse import urljoin
import re
import logging
import os
from .models import NessusAgentURL
from requests.exceptions import RequestException
from urllib.parse import urljoin, urlparse
import time

from .utils import log_assessment_event

logger = logging.getLogger(__name__)

TENABLE_CLIENT_TAG_CATEGORY = "AssessmentPlatformClients"
# --- END imports ---

TENABLE_API_BASE = "https://www.tenable.com/downloads/api/v2/pages"
AGENT_SLUG = "nessus-agents"  # the “slug” for Nessus Agents in the Downloads API


REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}
# Set a timeout for requests
REQUEST_TIMEOUT = 30 # seconds


TENABLE_POLICY_ID = config.TENABLE_DEFAULT_POLICY_ID
TENABLE_SCANNER_UUID = config.TENABLE_SCANNER_UUID




def _parse_nessus_os_string(os_string):
    """
    Parses the combined OS string from Nessus downloads API into components.
    Handles patterns like:
        - ubuntu1404_amd64
        - debian10_arm64
        - windows_x64
        - macosx
        - centos7_x86_64
        - amzn2_aarch64
        - rhel7_x86_64
        - suse12_x86_64
    Returns a dictionary: {'os_name': str, 'architecture': str, 'os_version_details': str}
    """
    os_name = "Unknown"
    architecture = "Unknown"
    os_version_details = ""

    if not os_string or not isinstance(os_string, str):
        return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}

    os_string_lower = os_string.lower()

    # Specific simple cases first
    if os_string_lower == "macosx":
        os_name = "macOS"
        architecture = "x64/arm64" # Nessus usually provides a universal binary now
        return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}

    # General pattern: <name><version>_<arch> or <name>_<arch>
    # Regex breakdown:
    # ([a-z]+)       - OS Name (letters)
    # (?:(\d+))?     - Optional Version (digits) - non-capturing group around it
    # (?:_?)         - Optional underscore separator - non-capturing
    # ([a-z0-9_]+)?  - Optional Architecture (letters, numbers, underscore)
    match = re.match(r'^([a-z]+)(?:(\d+))?(?:_?)([a-z0-9_]+)?$', os_string_lower)

    if match:
        raw_os_name, raw_version, raw_arch = match.groups()

        # --- OS Name Mapping ---
        os_map = {
            "amzn": "Amazon Linux", "amazon": "Amazon Linux",
            "centos": "CentOS",
            "debian": "Debian",
            "fedora": "Fedora",
            "freebsd": "FreeBSD",
            "oracle": "Oracle Linux", "ol": "Oracle Linux",
            "rhel": "RHEL", "redhat": "RHEL",
            "suse": "SUSE", "sles": "SUSE",
            "ubuntu": "Ubuntu",
            "windows": "Windows"
            # Add more mappings as needed
        }
        os_name = os_map.get(raw_os_name, raw_os_name.capitalize())

        # --- Version Details ---
        os_version_details = raw_version if raw_version else ""

        # --- Architecture Mapping/Normalization ---
        if raw_arch:
            arch_map = {
                "amd64": "x64",
                "x86_64": "x64",
                "64bit": "x64",
                "x64": "x64",
                "i386": "x86",
                "i686": "x86",
                "32bit": "x86",
                "x86": "x86",
                "arm64": "arm64",
                "aarch64": "arm64",
                "armv7hl": "armhf", # Example, adjust as needed
                # Add more mappings
            }
            architecture = arch_map.get(raw_arch, raw_arch) # Use raw if no map found
        elif os_name == "Windows" and not raw_arch:
             # Assume x64 for windows if arch missing, common case
             architecture = "x64"

    else:
        # Fallback if regex doesn't match complex cases, use original string
        os_name = os_string

    return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}
# === END HELPER FUNCTION ===

def _parse_nessus_filename(filename):
    """
    Parses the Nessus Agent filename into components.
    Handles patterns like:
        - NessusAgent-10.7.1-ubuntu1404_amd64.deb
        - NessusAgent-latest-el8.aarch64.rpm
        - NessusAgent-10.7.1-x64.msi (Windows)
        - NessusAgent-10.7.1-debian10_arm64.deb
        - NessusAgent-10.7.1-macosx.dmg
        - NessusAgent-10.8.0-amzn2.x86_64.rpm
        - NessusAgent-10.8.4.dmg  <-- Handles this simpler case now
    Returns a dictionary: {'os_name': str, 'architecture': str, 'os_version_details': str}
    """
    os_name = "Unknown"
    architecture = "Unknown"
    os_version_details = ""

    if not filename or not isinstance(filename, str):
        return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}

    # --- Common Mappings ---
    arch_map = { "amd64": "x64", "x86_64": "x64", "64bit": "x64", "x64": "x64", "i386": "x86", "i686": "x86", "32bit": "x86", "x86": "x86", "arm64": "arm64", "aarch64": "arm64", "armv7hl": "armhf", "armhf": "armhf", }
    os_map = { "amzn": "Amazon Linux", "amazon": "Amazon Linux", "centos": "CentOS", "debian": "Debian", "el": "EL", "fedora": "Fedora", "freebsd": "FreeBSD", "macos": "macOS", "macosx": "macOS", "oracle": "Oracle Linux", "ol": "Oracle Linux", "rhel": "RHEL", "redhat": "RHEL", "sles": "SUSE", "suse": "SUSE", "ubuntu": "Ubuntu", "windows": "Windows", "win": "Windows" }

    # --- Regex Patterns ---
    # Pattern 1: Detailed format (includes OS/Arch part)
    # Example: NessusAgent-latest-el8.aarch64.rpm -> Group 1 = el8.aarch64, Group 2 = rpm
    regex_detailed = re.compile(r'^NessusAgent-(?:latest|[\d.]+)-([\w\d._-]+?)\.(rpm|deb|msi|dmg|tgz|txz|zip)$', re.IGNORECASE)

    # Pattern 2: Simpler format (often macOS DMG, missing OS/Arch part)
    # Example: NessusAgent-10.8.4.dmg -> Group 1 = dmg
    regex_simple_dmg = re.compile(r'^NessusAgent-(?:latest|[\d.]+)\.(dmg)$', re.IGNORECASE)

    # --- Attempt Matching ---
    match_detailed = regex_detailed.match(filename)
    match_simple_dmg = None
    if not match_detailed:
        match_simple_dmg = regex_simple_dmg.match(filename)

    # --- Process Matches ---
    if match_detailed:
        core_part = match_detailed.group(1).lower() # e.g., "el8.aarch64", "ubuntu1404_amd64", "x64", "macosx"
        extension = match_detailed.group(2).lower()

        # Handle specific simple cases identified by core_part or extension
        if core_part == "macosx":
            os_name = "macOS"
            architecture = "x64/arm64" # Universal binary usually
        elif extension == "msi": # Strong indicator of Windows
            os_name = "Windows"
            architecture = arch_map.get(core_part, core_part) # Try to map 'x64' etc.
        else:
            # Try splitting core_part by common separators (., _)
            # Regex: ^([a-z]+(?:debian)?\d*[a-z]*) - OS + Version
            #        (?:[._])                    - Separator . or _
            #        ([a-z0-9_]+)$               - Architecture
            sub_match = re.match(r'^([a-z]+(?:debian)?\d*[a-z]*)(?:[._])([a-z0-9_]+)$', core_part)
            if sub_match:
                os_ver_str = sub_match.group(1) # e.g., "el8", "ubuntu1404", "debian10"
                arch_str = sub_match.group(2)   # e.g., "aarch64", "amd64"
                os_ver_split_match = re.match(r'^([a-z]+)(\d*.*)$', os_ver_str)
                if os_ver_split_match:
                    raw_os = os_ver_split_match.group(1)
                    raw_ver = os_ver_split_match.group(2)
                    os_name = os_map.get(raw_os, raw_os.capitalize())
                    os_version_details = raw_ver
                else: os_name = os_map.get(os_ver_str, os_ver_str.capitalize())
                architecture = arch_map.get(arch_str, arch_str) # Normalize architecture
            else:
                # Fallback if core_part doesn't match os_arch pattern
                os_name = os_map.get(core_part, core_part.capitalize())
                # Could architecture be hidden here? Unlikely without separator.

    elif match_simple_dmg:
        # Handle the simple DMG case (e.g., NessusAgent-10.8.4.dmg)
        os_name = "macOS"
        architecture = "x64/arm64" # Assume universal/common arch
        os_version_details = "" # Version details not present in filename

    else:
        # Fallback if neither regex matches
        logger.warning(f"Could not parse filename format: {filename}")
        # Basic guess as fallback
        parts = filename.split('-')
        if len(parts) > 1 and '.' in parts[-1]:
             os_name = parts[-1].split('.')[0].capitalize() # Guess OS from part before extension

    return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}
    """
    Parses the Nessus Agent filename into components.
    Handles patterns like:
        - NessusAgent-10.7.1-ubuntu1404_amd64.deb
        - NessusAgent-latest-el8.aarch64.rpm
        - NessusAgent-10.7.1-x64.msi (Windows)
        - NessusAgent-10.7.1-debian10_arm64.deb
        - NessusAgent-10.7.1-macosx.dmg
        - NessusAgent-10.8.0-amzn2.x86_64.rpm
    Returns a dictionary: {'os_name': str, 'architecture': str, 'os_version_details': str}
    """
    os_name = "Unknown"
    architecture = "Unknown"
    os_version_details = ""

    if not filename or not isinstance(filename, str):
        return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}

    # --- Architecture Mapping (used later) ---
    arch_map = {
        "amd64": "x64", "x86_64": "x64", "64bit": "x64", "x64": "x64",
        "i386": "x86", "i686": "x86", "32bit": "x86", "x86": "x86",
        "arm64": "arm64", "aarch64": "arm64",
        "armv7hl": "armhf", "armhf": "armhf",
        # Add more mappings if needed
    }
    # --- OS Name Mapping (used later) ---
    os_map = {
        "amzn": "Amazon Linux", "amazon": "Amazon Linux",
        "centos": "CentOS",
        "debian": "Debian",
        "el": "EL", # Enterprise Linux (RHEL, CentOS, Oracle, Alma, Rocky etc.)
        "fedora": "Fedora",
        "freebsd": "FreeBSD",
        "macos": "macOS", "macosx": "macOS", # Handle macosx variant
        "oracle": "Oracle Linux", "ol": "Oracle Linux",
        "rhel": "RHEL", "redhat": "RHEL",
        "sles": "SUSE", "suse": "SUSE",
        "ubuntu": "Ubuntu",
        "windows": "Windows", "win": "Windows"
        # Add more mappings as needed
    }

    # Regex breakdown (more robust):
    # ^NessusAgent-          : Starts with "NessusAgent-"
    # (?:latest|[\d.]+)     : Version part (non-capturing): 'latest' or digits/dots
    # -                      : Separator
    # ([\w\d.-]+?)           : Group 1: OS/Version/Arch part (non-greedy, allows ., -)
    # \.                     : Separator (literal dot before extension)
    # (rpm|deb|msi|dmg|tgz|txz|zip)$ : Group 2: Extension (capturing)
    # This simpler regex aims to grab the core OS/Arch part first
    # Example: NessusAgent-latest-el8.aarch64.rpm -> Group 1 = el8.aarch64
    # Example: NessusAgent-10.7.1-ubuntu1404_amd64.deb -> Group 1 = ubuntu1404_amd64
    # Example: NessusAgent-10.7.1-x64.msi -> Group 1 = x64 (Windows case)
    # Example: NessusAgent-10.7.1-macosx.dmg -> Group 1 = macosx
    match = re.match(r'^NessusAgent-(?:latest|[\d.]+)-([\w\d._-]+?)\.(rpm|deb|msi|dmg|tgz|txz|zip)$', filename, re.IGNORECASE)

    if match:
        core_part = match.group(1).lower() # e.g., "el8.aarch64", "ubuntu1404_amd64", "x64", "macosx"
        extension = match.group(2).lower() # e.g., "rpm", "deb", "msi"

        # Handle specific simple cases based on core_part or extension
        if core_part == "macosx":
            os_name = "macOS"
            architecture = "x64/arm64" # Universal binary usually
        elif extension == "msi": # Strong indicator of Windows
            os_name = "Windows"
            # Architecture might be in the core_part
            architecture = arch_map.get(core_part, core_part) # Try to map 'x64' etc.
        else:
            # Try splitting core_part by common separators (., _)
            # Assume format like <os+version>.<arch> or <os+version>_<arch>
            # Regex: ^([a-z]+(?:debian)?\d*[a-z]*) - OS + Version (allows trailing letters like 'lts', handles 'debian10')
            #        (?:[._])                    - Separator . or _
            #        ([a-z0-9_]+)$               - Architecture
            sub_match = re.match(r'^([a-z]+(?:debian)?\d*[a-z]*)(?:[._])([a-z0-9_]+)$', core_part)
            if sub_match:
                os_ver_str = sub_match.group(1) # e.g., "el8", "ubuntu1404", "debian10"
                arch_str = sub_match.group(2)   # e.g., "aarch64", "amd64"

                # Extract OS Name and Version from os_ver_str
                os_ver_split_match = re.match(r'^([a-z]+)(\d*.*)$', os_ver_str) # Separate letters and the rest (version)
                if os_ver_split_match:
                    raw_os = os_ver_split_match.group(1)
                    raw_ver = os_ver_split_match.group(2)
                    os_name = os_map.get(raw_os, raw_os.capitalize())
                    os_version_details = raw_ver
                else:
                     # Could not split os/version, use the whole string
                     os_name = os_map.get(os_ver_str, os_ver_str.capitalize())

                architecture = arch_map.get(arch_str, arch_str) # Normalize architecture
            else:
                # Fallback if core_part doesn't match os_arch pattern (e.g., maybe just OS name?)
                os_name = os_map.get(core_part, core_part.capitalize())

    else:
        # Fallback if the main regex doesn't match at all
        logger.warning(f"Could not parse filename format: {filename}")
        # Maybe try a simpler split? Or leave as Unknown.
        parts = filename.split('-')
        if len(parts) > 2:
             os_name = parts[2].split('.')[0] # Very basic guess

    return {'os_name': os_name, 'architecture': architecture, 'os_version_details': os_version_details}
# === END UPDATED HELPER FUNCTION ===


@shared_task(bind=True, max_retries=3)
def scrape_nessus_agent_urls(self):
    logger.info("Starting Nessus Agent URL scraping via Downloads API.")
    api_url = f"{TENABLE_API_BASE}/{AGENT_SLUG}"
    try:
        resp = requests.get(api_url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except RequestException as e:
        logger.error(f"Failed to fetch Nessus Agents via API: {e}")
        raise self.retry(exc=e, countdown=60 * 5)

    try:
        data = resp.json()
    except ValueError as e:
        logger.error(f"Failed to parse JSON response from {api_url}: {e}")
        logger.debug(f"Response text was: {resp.text}")
        raise self.retry(exc=e, countdown=60 * 5)

    releases = data.get("releases", {})
    latest   = releases.get("latest", {})
    if not latest:
        logger.warning("No 'releases.latest' found in API response; nothing to scrape.")
        return

    found_urls = set()
    created_count = updated_count = invalidated_count = 0

    for category, items in latest.items():
        if category.lower().startswith("plugins"):
            logger.debug(f"Skipping category '{category}' (not an agent).")
            continue

        if not isinstance(items, list) or not items:
            logger.debug(f"Category '{category}' is empty; skipping.")
            continue

        for idx, item in enumerate(items, start=1):
            raw_url = item.get("file_url")
            if not raw_url:
                logger.debug(f"[{category}][{idx}] No download URL; skipping.")
                continue

            download_url = (
                raw_url
                if "i_agree" in raw_url
                else f"{raw_url}?i_agree_to_tenable_license_agreement=true"
            )
            found_urls.add(download_url)

            # --- Start Parsing Logic (using filename) ---
            agent_version = item.get("version") or ""
            # Get filename from API 'file' field OR parse from URL
            file_name = item.get("file") or os.path.basename(urlparse(download_url).path)

            # Parse the filename using the updated helper function
            parsed_details = _parse_nessus_filename(file_name) # <-- Pass filename

            os_name = parsed_details['os_name']
            architecture = parsed_details['architecture']
            os_version_details = parsed_details['os_version_details']
            # --- End Parsing Logic ---

            try:
                obj, created = NessusAgentURL.objects.update_or_create(
                    download_url=download_url,
                    defaults={
                        "file_name":            file_name,
                        "os_name":              os_name,          # Use parsed value
                        "architecture":         architecture,     # Use parsed value
                        "agent_version":        agent_version,
                        "os_version_details":   os_version_details, # Use parsed value
                        "last_scraped":         timezone.now(),
                        "is_valid":             True,
                    },
                )
                log_prefix = f"[{category}][{idx}] ({file_name})"
                if created:
                    created_count += 1
                    logger.info(f"{log_prefix} Created entry: OS={os_name}, Arch={architecture}, Ver={os_version_details}")
                else:
                    updated_fields = ["last_scraped"]
                    # Check if any fields actually changed
                    if not obj.is_valid: updated_fields.append("is_valid"); obj.is_valid = True
                    if obj.file_name != file_name: updated_fields.append("file_name"); obj.file_name = file_name
                    if obj.os_name != os_name: updated_fields.append("os_name"); obj.os_name = os_name
                    if obj.architecture != architecture: updated_fields.append("architecture"); obj.architecture = architecture
                    if obj.agent_version != agent_version: updated_fields.append("agent_version"); obj.agent_version = agent_version
                    if obj.os_version_details != os_version_details: updated_fields.append("os_version_details"); obj.os_version_details = os_version_details

                    obj.last_scraped = timezone.now() # Always update scraped time

                    if len(updated_fields) > 1: # More than just last_scraped changed
                        obj.save(update_fields=updated_fields)
                        updated_count += 1
                        logger.info(f"{log_prefix} Updated entry: OS={os_name}, Arch={architecture}, Ver={os_version_details}")
                    elif "last_scraped" in updated_fields: # Only timestamp needs update
                         obj.save(update_fields=["last_scraped"])
                         logger.debug(f"{log_prefix} Refreshed timestamp for existing entry.")


            except Exception as db_err:
                logger.error(f"[{category}][{idx}] DB error for {download_url} ({file_name}): {db_err}")

    # invalidate any URLs that have disappeared
    stale_qs = NessusAgentURL.objects.filter(is_valid=True).exclude(download_url__in=found_urls)
    invalidated_count = stale_qs.update(is_valid=False)
    if invalidated_count > 0:
         logger.warning(f"Invalidated {invalidated_count} stale Nessus Agent URLs.")

    logger.info(
        f"Done scraping Nessus Agents. "
        f"Categories={len(latest)}, Unique URLs Found={len(found_urls)}, "
        f"Created={created_count}, Updated={updated_count}, Invalidated={invalidated_count}"
    )


@shared_task(bind=True, max_retries=2)
def validate_agent_urls(self):
    logger.info("Starting Nessus Agent URL validation task.")
    # Fetch only IDs first for potentially large querysets
    url_ids_to_validate = NessusAgentURL.objects.filter(is_valid=True).values_list('id', flat=True)
    total_to_check = len(url_ids_to_validate)
    validated_count = 0
    failed_count = 0
    logger.info(f"Found {total_to_check} potentially valid URLs to check.")

    # Process in chunks to avoid holding too many objects in memory if needed
    # chunk_size = 100
    # for i in range(0, total_to_check, chunk_size):
    #    chunk_ids = url_ids_to_validate[i:i + chunk_size]
    #    urls_chunk = NessusAgentURL.objects.filter(id__in=chunk_ids)

    urls_to_validate = NessusAgentURL.objects.filter(id__in=url_ids_to_validate) # Iterate over full QuerySet for now

    for agent_url_obj in urls_to_validate:
        is_currently_valid = False
        current_url = agent_url_obj.download_url
        try:
            # Use HEAD request to check existence without downloading the file
            head_response = requests.head(current_url, timeout=REQUEST_TIMEOUT, allow_redirects=True, headers=REQUEST_HEADERS)
            # Consider 2xx and 3xx responses as valid (3xx indicates redirects)
            if 200 <= head_response.status_code < 400:
                is_currently_valid = True
            else:
                 logger.warning(f"URL validation failed for {current_url} - Status: {head_response.status_code}")

        except requests.exceptions.Timeout:
             logger.error(f"Timeout error validating URL {current_url}")
             is_currently_valid = False # Mark invalid on timeout
        except requests.exceptions.RequestException as e:
             logger.error(f"Network error validating URL {current_url}: {e}")
             # Keep existing validity status on network error? Or mark as invalid? Decide policy.
             # Mark as invalid if check fails.
             is_currently_valid = False

        validated_count += 1

        # Update DB only if status changed
        if agent_url_obj.is_valid != is_currently_valid:
            agent_url_obj.is_valid = is_currently_valid
            agent_url_obj.last_validated = timezone.now()
            agent_url_obj.save(update_fields=['is_valid', 'last_validated'])
            if not is_currently_valid:
                failed_count += 1
                logger.warning(f"Marked URL as invalid: {current_url}")
        else:
             # Still update timestamp even if validity didn't change
             agent_url_obj.last_validated = timezone.now()
             agent_url_obj.save(update_fields=['last_validated'])

        if validated_count % 50 == 0: # Log progress periodically
             logger.info(f"Validation progress: Checked {validated_count}/{total_to_check} URLs...")


    logger.info(f"Validation finished. Checked: {validated_count}, Marked Invalid: {failed_count}")



@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def sync_client_with_tenable(self, client_id):
    """
    Ensures both a Tag Value and an Agent Group exist in Tenable.io for the client.
    Updates the client model with the Tag Value UUID.
    Renamed from create_or_update_tenable_client_tag.
    """
    try:
        client = Client.objects.get(pk=client_id)
        logger.info(f"Starting Tenable sync (Tag & Group) for Client ID: {client_id} ({client.name})")
        tio = get_tenable_io_client()

        if not tio:
            logger.error(f"Cannot sync Tenable entities for Client {client_id}: Tenable client failed to initialize.")
            return

        tag_category_name = TENABLE_CLIENT_TAG_CATEGORY
        tag_value_name = client.name # Use client name for tag value
        agent_group_name = client.name # Use client name for agent group name

        # --- Step 1: Ensure Tag Category Exists ---
        category_uuid = None
        try:
            categories = tio.tags.list_categories()
            for cat in categories:
                if cat['name'] == tag_category_name:
                    category_uuid = cat['uuid']
                    logger.debug(f"Found existing tag category '{tag_category_name}' (UUID: {category_uuid})")
                    break
            if not category_uuid:
                logger.info(f"Creating tag category '{tag_category_name}'")
                cat_info = tio.tags.create_category(name=tag_category_name, description="Tags managed by Assessment Platform")
                category_uuid = cat_info['uuid']
                logger.info(f"Created tag category '{tag_category_name}' (UUID: {category_uuid})")
        except APIError as e:
            logger.exception(f"Tenable API error managing category '{tag_category_name}' for Client {client_id}: {e}")
            self.retry(exc=e)
            return
        except ForbiddenError:
             logger.error(f"Permission denied managing tag category '{tag_category_name}'. Check API key permissions.")
             return # Don't retry permission errors

        if not category_uuid:
            logger.error(f"Failed to find/create category '{tag_category_name}'. Aborting sync for Client {client_id}.")
            return

        # --- Step 2: Ensure Tag Value Exists (and update UUID on client model) ---
        tag_value_uuid = None
        current_tag_uuid_on_client = client.tenable_tag_uuid
        try:
            existing_values = tio.tags.list(filter=('category_uuid', 'eq', category_uuid))
            found_value_details = None
            for val in existing_values:
                if val.get('value') == tag_value_name:
                    found_value_details = val
                    tag_value_uuid = val.get('uuid')
                    logger.debug(f"Found existing tag value '{tag_value_name}' (UUID: {tag_value_uuid})")
                    break
                elif val.get('uuid') == current_tag_uuid_on_client: # Found by old UUID, name might differ
                    found_value_details = val
                    tag_value_uuid = val.get('uuid')
                    logger.warning(f"Found tag by stored UUID {tag_value_uuid}, value differs ('{val.get('value')}' vs '{tag_value_name}'). Will edit.")
                    break

            if tag_value_uuid: # Found existing tag
                if found_value_details and found_value_details.get('value') != tag_value_name: # Check if name needs update
                    logger.info(f"Updating tag value for UUID {tag_value_uuid} from '{found_value_details.get('value')}' to '{tag_value_name}'")
                    tio.tags.edit_value(category_uuid=category_uuid, value_uuid=tag_value_uuid, value=tag_value_name)
            else: # Tag value not found, create it
                logger.info(f"Creating tag value '{tag_value_name}' in category '{tag_category_name}'")
                value_info = tio.tags.create(category=category_uuid, value=tag_value_name, description=f"Client ID: {client.id}")
                tag_value_uuid = value_info.get('uuid')
                if tag_value_uuid:
                     logger.info(f"Created tag value '{tag_value_name}' (UUID: {tag_value_uuid})")
                else:
                     logger.error(f"Failed to get UUID for newly created tag value '{tag_value_name}'")
                     # Decide how to handle this - maybe retry? For now, continue to group creation.

            # Update Client Model's tag UUID if it changed or was newly created
            if client.tenable_tag_uuid != tag_value_uuid and tag_value_uuid:
                logger.info(f"Updating Client {client_id} tenable_tag_uuid to '{tag_value_uuid}'")
                client.tenable_tag_uuid = tag_value_uuid
                client.save(update_fields=['tenable_tag_uuid'])

        except APIError as e:
            logger.exception(f"Tenable API error managing tag value '{tag_value_name}' for Client {client_id}: {e}")
            self.retry(exc=e)
            # If tag fails, maybe don't proceed to group? Return here for now.
            return
        except ForbiddenError:
             logger.error(f"Permission denied managing tag value '{tag_value_name}'. Check API key permissions.")
             return

        # --- Step 3: Ensure Agent Group Exists ---
        agent_group_id = None # Optional: Store group ID on client model later
        try:
            agent_groups = tio.agent_groups.list()
            found_group = False
            for group in agent_groups:
                if group['name'] == agent_group_name:
                    found_group = True
                    agent_group_id = group.get('id')
                    logger.debug(f"Found existing agent group '{agent_group_name}' (ID: {agent_group_id})")
                    break

            if not found_group:
                logger.info(f"Creating agent group '{agent_group_name}' for Client {client.id}")
                created_group = tio.agent_groups.create(name=agent_group_name)
                agent_group_id = created_group.get('id')
                logger.info(f"Created agent group '{agent_group_name}' (ID: {agent_group_id})")

            # --- Optional: Update Client model with agent_group_id ---
            # if client.tenable_agent_group_id != agent_group_id and agent_group_id:
            #    client.tenable_agent_group_id = agent_group_id
            #    client.save(update_fields=['tenable_agent_group_id'])
            #    logger.info(f"Updated Client {client_id} tenable_agent_group_id to '{agent_group_id}'")

        except APIError as e:
            logger.exception(f"Tenable API error managing agent group '{agent_group_name}' for Client {client_id}: {e}")
            # Don't retry group errors? Or retry? For now, log and finish.
        except ForbiddenError:
             logger.error(f"Permission denied managing agent group '{agent_group_name}'. Check API key permissions.")
             # Don't retry permission errors

        logger.info(f"Finished Tenable sync for Client {client_id}.")

    except ObjectDoesNotExist: # Changed from Client.DoesNotExist for consistency
         logger.error(f"Client with ID {client_id} not found for Tenable sync.")
    except Exception as e:
        logger.exception(f"Unexpected error during Tenable sync for Client {client_id}: {e}")
        # Decide if retryable based on exception type if needed
        # self.retry(exc=e)



@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def create_or_update_tenable_client_tag(self, client_id):
    """
    Celery task to create or update a tag value in Tenable.io for a specific client.
    Uses APIError for Tenable-specific issues.
    """
    try:
        client = Client.objects.get(pk=client_id)
        logger.info(f"Starting Tenable tag sync for Client ID: {client_id} ({client.name})")
        tio = get_tenable_io_client()

        if not tio:
            logger.error(f"Cannot sync Tenable tag for Client {client_id}: Tenable client failed to initialize.")
            return

        category_name = TENABLE_CLIENT_TAG_CATEGORY
        tag_value = client.name
        category_uuid = None

        # 1. Ensure Category Exists
        try:
            categories = tio.tags.list_categories()
            for cat in categories:
                 if cat['name'] == category_name:
                     category_uuid = cat['uuid']
                     logger.debug(f"Found existing Tenable tag category '{category_name}' with UUID: {category_uuid}")
                     break
            if not category_uuid:
                 logger.info(f"Creating Tenable tag category '{category_name}'")
                 # Use create_category here
                 cat_info = tio.tags.create_category(name=category_name, description="Tags managed by Assessment Platform")
                 category_uuid = cat_info['uuid']
                 logger.info(f"Created Tenable tag category '{category_name}' with UUID: {category_uuid}")

        except APIError as e:
            logger.exception(f"Tenable API error checking/creating category '{category_name}' for Client {client_id}: {e}")
            self.retry(exc=e)
            return

        if not category_uuid:
            logger.error(f"Failed to find or create category '{category_name}'. Cannot proceed with tag value sync for Client {client_id}.")
            return

        # 2. Find or Create Tag Value
        tag_value_uuid = None
        current_tag_uuid_on_client = client.tenable_tag_uuid

        try:
            # Use tio.tags.list() with a filter
            existing_values = tio.tags.list(filter=('category_uuid', 'eq', category_uuid))

            found_value = None
            for val in existing_values:
                current_val_name = val.get('value')
                current_val_uuid = val.get('uuid')

                if current_val_name == tag_value:
                    found_value = val
                    tag_value_uuid = current_val_uuid
                    logger.debug(f"Found existing Tenable tag value '{tag_value}' with UUID: {tag_value_uuid}")
                    break
                elif current_val_uuid == current_tag_uuid_on_client:
                    found_value = val
                    tag_value_uuid = current_val_uuid
                    logger.warning(f"Found Tenable tag by stored UUID {tag_value_uuid}, but value differs ('{current_val_name}' vs '{tag_value}'). Will attempt to edit.")
                    break

            if tag_value_uuid: # Found existing tag
                if found_value and found_value.get('value') != tag_value:
                    try:
                        logger.info(f"Updating Tenable tag value for UUID {tag_value_uuid} from '{found_value.get('value')}' to '{tag_value}'")
                        # Assuming edit_value is correct based on docs/previous checks
                        tio.tags.edit_value(category_uuid=category_uuid, value_uuid=tag_value_uuid, value=tag_value)
                    except APIError as e_edit:
                        logger.exception(f"Failed to update Tenable tag value for UUID {tag_value_uuid}: {e_edit}")
                        # Decide if retryable
            else: # Tag value not found, create it
                logger.info(f"Creating Tenable tag value '{tag_value}' in category '{category_name}'")
                # --- THIS LINE IS CORRECTED ---
                # Use tio.tags.create(), passing the category UUID to the 'category' param
                value_info = tio.tags.create(category=category_uuid, value=tag_value, description=f"Client ID: {client.id}")
                # --- END CORRECTION ---
                tag_value_uuid = value_info['uuid'] # Assuming response contains 'uuid'
                logger.info(f"Created Tenable tag value '{tag_value}' with UUID: {tag_value_uuid}")

            # 3. Update Client Model if needed
            if client.tenable_tag_uuid != tag_value_uuid:
                logger.info(f"Updating Client {client_id} tenable_tag_uuid from '{client.tenable_tag_uuid}' to '{tag_value_uuid}'")
                client.tenable_tag_uuid = tag_value_uuid
                client.save(update_fields=['tenable_tag_uuid'])

        except APIError as e:
            logger.exception(f"Tenable API error finding/creating/updating value '{tag_value}' for Client {client_id}: {e}")
            self.retry(exc=e)

    except Client.DoesNotExist:
         logger.error(f"Client with ID {client_id} not found for Tenable tag sync.")
    except Exception as e: # Catch broader exceptions as a fallback
        logger.exception(f"Unexpected error during Tenable tag sync for Client {client_id}: {e}")


# --- Keep your apply_tenable_tag_to_assets task as it was ---
@shared_task(bind=True, max_retries=3, default_retry_delay=120)
def apply_tenable_tag_to_assets(self, client_id):
    """
    Finds assets linked to agents in the client's specific Agent Group
    and applies the client's specific Tag Value to them.
    """
    try:
        client = Client.objects.get(pk=client_id)
        logger.info(f"Starting Tenable asset tagging via group for Client ID: {client_id} ({client.name})")
        tio = get_tenable_io_client()

        if not tio:
            logger.error(f"Cannot tag assets for Client {client_id}: Tenable client failed to initialize.")
            return

        # 1. Get the Client's Tag Value UUID
        tag_value_uuid = client.tenable_tag_uuid
        if not tag_value_uuid:
            logger.error(f"Client {client_id} ({client.name}) does not have a Tenable Tag UUID stored. Cannot apply tags.")
            return
        logger.debug(f"Using Tag Value UUID: {tag_value_uuid}")

        # 2. Find the Client's Agent Group ID
        agent_group_name = client.name
        agent_group_id = None
        try:
            agent_groups = tio.agent_groups.list()
            for group in agent_groups:
                if group['name'] == agent_group_name:
                    agent_group_id = group.get('id')
                    logger.debug(f"Found agent group '{agent_group_name}' (ID: {agent_group_id})")
                    break
            if not agent_group_id:
                logger.error(f"Agent group '{agent_group_name}' not found in Tenable.io for Client {client.id}. Cannot find agents.")
                # Optionally trigger the sync task again?
                # sync_client_with_tenable.delay(client.id)
                return
        except APIError as e:
            logger.exception(f"API error finding agent group '{agent_group_name}': {e}")
            self.retry(exc=e)
            return
        except ForbiddenError:
            logger.error(f"Permission denied listing agent groups. Check API key permissions.")
            return


        # 3. List Agents in that Group and Get Linked Asset UUIDs
        asset_uuids_to_tag = set()
        try:
            # Filter agents by group ID
            # NOTE: The exact filter format might vary. Check pyTenable docs.
            # Example filter attempts:
            # agents = tio.agents.list(filter=('groups', 'eq', agent_group_id)) # May not work
            # agents = tio.agents.list(filter=('group_id', 'eq', [agent_group_id])) # Needs confirmation
            # Fallback: List all and filter manually (less efficient)
            all_agents = tio.agents.list() # Fetch all agents
            agents_in_group = []
            for agent in all_agents:
                agent_groups_list = agent.get('groups', []) # Assuming 'groups' is a list of dicts [{id:.., name:...}, ...]
                if any(ag['id'] == agent_group_id for ag in agent_groups_list):
                     agents_in_group.append(agent) # Keep agent if it's in the target group

            for agent in agents_in_group:
                # Agent record structure might vary, check actual API response or pyTenable docs
                # Assuming 'linked_on_asset_uuid' or similar field exists
                asset_uuid = agent.get('linked_on_asset_uuid') # Check actual field name
                if not asset_uuid:
                     asset_uuid = agent.get('asset', {}).get('uuid') # Alternative potential location
                if asset_uuid:
                    asset_uuids_to_tag.add(asset_uuid)
                else:
                    logger.warning(f"Agent ID {agent.get('id')} in group '{agent_group_name}' has no linked asset UUID.")

            logger.info(f"Found {len(asset_uuids_to_tag)} unique asset UUIDs linked to agents in group '{agent_group_name}'.")

        except APIError as e:
            logger.exception(f"API error listing agents: {e}") # Error listing all agents
            self.retry(exc=e)
            return
        except ForbiddenError:
            logger.error(f"Permission denied listing agents. Check API key permissions.")
            return

        # 4. Apply the Tag to the Found Asset UUIDs
        if not asset_uuids_to_tag:
            logger.info(f"No assets found to tag for Client {client.id} based on agent group membership.")
            return

        try:
            # Convert set to list for the API call
            asset_uuid_list = list(asset_uuids_to_tag)
            logger.info(f"Applying tag UUID {tag_value_uuid} to {len(asset_uuid_list)} assets...")
            # Note: Check pyTenable docs for batch size limits if any. Assign might handle batches.
            job_info = tio.tags.assign(assets=asset_uuid_list, tags=[tag_value_uuid])
            job_uuid = job_info.get('job_uuid') # Or similar identifier for the async job
            if job_uuid:
                 logger.info(f"Tag assignment job initiated successfully (Job UUID: {job_uuid}). Tagging may take time to reflect in Tenable.io.")
            else:
                 logger.warning("Tag assignment initiated, but could not retrieve job UUID.") # Still likely worked

        except APIError as e:
            logger.exception(f"API error applying tag UUID {tag_value_uuid} to assets: {e}")
            self.retry(exc=e)
            return
        except ForbiddenError:
            logger.error(f"Permission denied applying tags. Check API key permissions.")
            return
        except Exception as e: # Catch other potential errors during assignment
             logger.exception(f"Unexpected error applying tags: {e}")
             self.retry(exc=e) # Retry generic errors? Maybe not always safe.
             return

    except ObjectDoesNotExist:
         logger.error(f"Client with ID {client_id} not found for Tenable asset tagging.")
    except Exception as e:
        logger.exception(f"Unexpected error during asset tagging for Client {client_id}: {e}")
        # Decide if retryable
        # self.retry(exc=e)


@app.task(bind=True)
def launch_tenable_scan_task2(self, assessment_id: int):
    """
    Celery task to find/create and launch a Tenable agent scan for a CE+ assessment.
    Targets scan using Agent Group ID stored on the Client model.
    """
    print(f"!!! [DEBUG Celery Task launch_tenable_scan_task] ENTERING TASK for Assessment {assessment_id} !!!")
    task_id = self.request.id
    logger.info(f"[Task:{task_id}] Starting Tenable scan launch for Assessment ID: {assessment_id}")
    print(f"[DEBUG Celery Task {task_id}] Starting for Assessment {assessment_id}")

    try:
        # --- Get Assessment and Client Data ---
        try:
            # Select related client to potentially prefetch agent group ID
            assessment = Assessment.objects.select_related('client').get(pk=assessment_id)
        except Assessment.DoesNotExist:
            logger.error(f"[Task:{task_id}] Assessment {assessment_id} not found.")
            print(f"[DEBUG Celery Task {task_id}] Assessment {assessment_id} not found.")
            return f"Error: Assessment {assessment_id} not found."

        client = assessment.client
        if not client:
            log_assessment_event(assessment, None, "Scan launch failed: Assessment not linked to a client.")
            logger.error(f"[Task:{task_id}] Assessment {assessment_id} has no linked client.")
            print(f"[DEBUG Celery Task {task_id}] No client linked.")
            return f"Error: Assessment {assessment_id} has no client."

        # --- Get Agent Group ID from Client ---
        agent_group_id = client.tenable_agent_group_id
        if not agent_group_id:
            log_msg = f"Scan launch failed: Client '{client.name}' (ID: {client.id}) does not have a Tenable Agent Group ID stored. Run the 'sync_client_with_tenable' task first."
            log_assessment_event(assessment, None, log_msg)
            logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
            print(f"[DEBUG Celery Task {task_id}] Client missing Tenable Agent Group ID.")
            # Optionally trigger sync task: sync_client_with_tenable.delay(client.id)
            return f"Error: Client {client.id} missing Tenable Agent Group ID."
        else:
             print(f"[DEBUG Celery Task {task_id}] Found Agent Group ID for Client: {agent_group_id}")


        # --- Get Tenable Scan Config ---
        policy_uuid = getattr(config, 'TENABLE_SCAN_POLICY_UUID', None) # Not directly used in create anymore, but keep for context/future
        policy_id = getattr(config, 'TENABLE_SCAN_POLICY_ID', None)
        scanner_uuid = getattr(config, 'TENABLE_SCANNER_UUID', None)
        if not policy_id or not scanner_uuid: # Removed check for policy_uuid as it's not primary now
            log_msg = "Scan launch failed: Tenable Scan Policy ID or Scanner UUID is not configured in Constance settings."
            log_assessment_event(assessment, None, log_msg)
            logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
            print(f"[DEBUG Celery Task {task_id}] Constance Policy ID/Scanner UUID missing.")
            return f"Error: Tenable scan configuration missing for Assessment {assessment_id}."

        # --- Determine Scan UUID (Find Existing or Create New) ---
        # ...(Finding existing scan logic remains the same as previous version)...
        scan_to_launch_uuid = None
        scan_id_to_launch = None
        scan_needs_creation = False
        expected_scan_name = f"CE+ Scan - Assessment {assessment.id} - {client.name}"
        print(f"[DEBUG Celery Task {task_id}] Expected scan name: '{expected_scan_name}'")

        if assessment.tenable_scan_uuid:
            print(f"[DEBUG Celery Task {task_id}] Found stored scan UUID: {assessment.tenable_scan_uuid}. Verifying existence...")
            existing_scan_details = get_scan_details(str(assessment.tenable_scan_uuid))
            if existing_scan_details:
                scan_to_launch_uuid = str(assessment.tenable_scan_uuid)
                scan_id_to_launch = existing_scan_details.get('info', {}).get('id')
                print(f"[DEBUG Celery Task {task_id}] Stored scan UUID {scan_to_launch_uuid} (ID: {scan_id_to_launch}) verified.")
            else:
                log_assessment_event(assessment, None, f"Stored Tenable scan UUID ({assessment.tenable_scan_uuid}) not found. Will create new.")
                logger.warning(f"[Task:{task_id}] Stored scan UUID {assessment.tenable_scan_uuid} no longer exists.")
                print(f"[DEBUG Celery Task {task_id}] Stored scan UUID {assessment.tenable_scan_uuid} NOT found. Clearing field.")
                assessment.tenable_scan_uuid = None
                assessment.save(update_fields=['tenable_scan_uuid'])
                scan_needs_creation = True
        else:
            print(f"[DEBUG Celery Task {task_id}] No stored UUID. Searching by name '{expected_scan_name}'...")
            existing_scan_details = find_scan_by_name(expected_scan_name)
            if existing_scan_details and existing_scan_details.get('info', {}).get('uuid'):
                found_uuid = existing_scan_details['info']['uuid']
                found_id = existing_scan_details.get('info',{}).get('id')
                scan_to_launch_uuid = found_uuid
                scan_id_to_launch = found_id
                assessment.tenable_scan_uuid = found_uuid
                assessment.save(update_fields=['tenable_scan_uuid'])
                log_assessment_event(assessment, None, f"Found existing scan '{expected_scan_name}' (ID: {found_id}, UUID: {found_uuid}). Will re-launch.")
                print(f"[DEBUG Celery Task {task_id}] Found existing scan by name. ID: {found_id}, UUID: {found_uuid}. Stored UUID.")
            else:
                print(f"[DEBUG Celery Task {task_id}] No existing scan found. Flagging for creation.")
                scan_needs_creation = True


        # --- Create scan if needed (Using Agent Group ID) ---
        if scan_needs_creation:
            print(
                f"[DEBUG Celery Task {task_id}] Attempting to create new scan targeting Agent Group ID: {agent_group_id}")
            try:
                # Ensure variable names here (policy_id, scanner_uuid, agent_group_id)
                # are the ones holding the values you intend to pass.
                created_id, created_uuid = create_agent_scan(
                    name=expected_scan_name,
                    policy_id_val=policy_id,  # Use policy_id_val
                    scanner_uuid_val=scanner_uuid,  # Use scanner_uuid_val
                    agent_group_id_val=agent_group_id  # Use agent_group_id_val
                )
            except Exception as create_exc:
                 logger.exception(f"[Task:{task_id}] Exception calling create_agent_scan for '{expected_scan_name}': {create_exc}")
                 print(f"[DEBUG Celery Task {task_id}] Exception during create_agent_scan call: {create_exc}")
                 created_id, created_uuid = None, None

            # Check if UUID was successfully obtained
            if created_uuid:
                scan_to_launch_uuid = created_uuid
                scan_id_to_launch = created_id
                assessment.tenable_scan_uuid = created_uuid
                try:
                    assessment.save(update_fields=['tenable_scan_uuid'])
                    log_assessment_event(assessment, None, f"Created new Tenable scan '{expected_scan_name}' (ID: {created_id}, UUID: {created_uuid}) targeting Agent Group {agent_group_id}.")
                    print(f"[DEBUG Celery Task {task_id}] New scan created. ID: {created_id}, UUID: {created_uuid}. Stored UUID.")
                except Exception as save_exc:
                    # Handle save errors (Validation or DB)
                    log_msg = f"Failed to save newly created Tenable scan UUID ({created_uuid}) for '{expected_scan_name}'. Error: {save_exc}"
                    log_assessment_event(assessment, None, log_msg + " Scan may exist in Tenable but is not linked.")
                    logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
                    print(f"[DEBUG Celery Task {task_id}] Error saving UUID {created_uuid}: {save_exc}")
                    return f"Error: Failed to save scan UUID for Assessment {assessment_id}."
            else:
                # Handle case where create_agent_scan failed
                log_msg = f"Failed to create Tenable scan '{expected_scan_name}' targeting Agent Group {agent_group_id}."
                if created_id: # If ID was returned but UUID wasn't (e.g., details fetch failed)
                    log_msg += f" Scan might exist with ID {created_id} but UUID retrieval failed."
                log_assessment_event(assessment, None, log_msg)
                logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
                print(f"[DEBUG Celery Task {task_id}] Scan creation failed. Scan ID from attempt: {created_id}.")
                return f"Error: Failed to create Tenable scan for Assessment {assessment_id}."

        # --- Launch the Scan (Keep as is) ---
        if scan_to_launch_uuid:
            print(f"[DEBUG Celery Task {task_id}] Attempting to launch scan UUID: {scan_to_launch_uuid}")
            # ...(launch logic remains the same as previous version)...
            try:
                 success = launch_scan(scan_to_launch_uuid)
                 if success:
                     log_assessment_event(assessment, None, f"Successfully initiated launch for Tenable scan '{expected_scan_name}' (UUID: {scan_to_launch_uuid}).")
                     logger.info(f"[Task:{task_id}] Successfully launched scan {scan_to_launch_uuid} for assessment {assessment_id}.")
                     print(f"[DEBUG Celery Task {task_id}] Scan launch successful.")
                     return f"Success: Scan {scan_to_launch_uuid} launched for Assessment {assessment_id}."
                 else:
                     log_msg = f"Failed to launch Tenable scan '{expected_scan_name}' (UUID: {scan_to_launch_uuid}). API call returned failure."
                     log_assessment_event(assessment, None, log_msg)
                     logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
                     print(f"[DEBUG Celery Task {task_id}] Scan launch command failed (returned False).")
                     return f"Error: Failed to launch scan {scan_to_launch_uuid} for Assessment {assessment_id}."
            except Exception as launch_exc:
                 log_msg = f"Exception occurred while launching Tenable scan '{expected_scan_name}' (UUID: {scan_to_launch_uuid}): {launch_exc}"
                 log_assessment_event(assessment, None, log_msg)
                 logger.exception(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
                 print(f"[DEBUG Celery Task {task_id}] Exception during launch_scan call: {launch_exc}")
                 return f"Error: Exception launching scan {scan_to_launch_uuid} for Assessment {assessment_id}."

        else:
            # Should not happen if logic is correct
            log_msg = "Scan launch failed: Could not determine or create a valid Tenable scan UUID to launch."
            log_assessment_event(assessment, None, log_msg)
            logger.error(f"[Task:{task_id}] {log_msg} (Assessment {assessment_id})")
            print(f"[DEBUG Celery Task {task_id}] Logic error: No scan UUID determined for launch.")
            return f"Error: Could not determine scan UUID for Assessment {assessment_id}."

    except Exception as exc:
        # Catch any broader unexpected errors
        logger.exception(f"[Task:{task_id}] Unexpected error during Tenable scan launch processing for assessment {assessment_id}: {exc}")
        print(f"[DEBUG Celery Task {task_id}] UNEXPECTED PROCESSING ERROR: {exc}")
        try:
            assessment = Assessment.objects.get(pk=assessment_id)
            log_assessment_event(assessment, None, f"Scan launch failed due to unexpected task error: {exc}")
        except Exception: pass
        return f"Error: Unexpected failure during scan launch processing for Assessment {assessment_id}."

@app.task(bind=True)
def launch_tenable_scan_task_debug(self, assessment_id: int):
    """
    Celery task to find/create and launch a Tenable agent scan for a CE+ assessment.
    """
    # --- Test: Only print statement, rest is commented ---
    print(f"!!! [DEBUG Celery Task launch_tenable_scan_task] ENTERING TASK for Assessment {assessment_id} !!!")

@app.task
def simple_test_task(x, y):
    result = x + y
    # Use print for immediate visibility in worker log for this test
    print(f"[DEBUG Simple Test Task] Executing: {x} + {y} = {result}")
    # Add a small delay to ensure log messages flush
    time.sleep(1)
    return result

@shared_task(bind=True, max_retries=3, default_retry_delay=60) # Example retry settings
def task_create_tenable_scan(self, assessment_id):
    try:
        assessment = Assessment.objects.get(id=assessment_id)
        if assessment.tenable_scan_uuid:
            logger.info(f"Assessment {assessment_id} already has a Tenable scan UUID: {assessment.tenable_scan_uuid}. Skipping creation.")
            return f"Scan already exists for Assessment {assessment_id}"

        client = assessment.client
        if not client.tenable_agent_group_id:
            logger.info(f"Client {client.name} for Assessment {assessment_id} does not have a Tenable Agent Group ID. Skipping scan creation.")
            return f"No Agent Group ID for Client of Assessment {assessment_id}"

        # These MUST be configured in Django Admin -> Constance
        default_policy_id_str = getattr(config, 'DEFAULT_TENABLE_POLICY_ID', None)
        default_scanner_uuid = getattr(config, 'DEFAULT_TENABLE_SCANNER_UUID', None)

        if not default_policy_id_str or not default_scanner_uuid:
            err_msg = f"Missing default Tenable policy ID or scanner UUID in Constance settings for Assessment {assessment_id}"
            logger.error(err_msg)
            # self.retry(exc=ValueError(err_msg)) # Optionally retry if config might appear later
            return f"Error: {err_msg}"

        try:
            default_policy_id = int(default_policy_id_str)
        except ValueError:
            err_msg = f"DEFAULT_TENABLE_POLICY_ID ('{default_policy_id_str}') is not a valid integer."
            logger.error(err_msg)
            return f"Error: {err_msg}"

        scan_name = f"Assessment_{assessment.id}_{client.name.replace(' ', '_')}_{assessment.type.replace(' ', '_')}"
        logger.info(f"Task: Creating Tenable scan '{scan_name}' for Assessment {assessment.id}, Client {client.name}, Agent Group ID: {client.tenable_agent_group_id}")

        scan_id, scan_uuid = create_agent_scan(
            name=scan_name,
            policy_id=default_policy_id,
            scanner_uuid=str(default_scanner_uuid), # Ensure it's a string
            agent_group_id=int(client.tenable_agent_group_id) # Ensure it's an int
        )

        if scan_uuid:
            assessment.tenable_scan_uuid = scan_uuid
            assessment.save(update_fields=['tenable_scan_uuid'])
            logger.info(f"Tenable scan created for Assessment {assessment.id} with UUID: {scan_uuid}")
            return f"Scan created for Assessment {assessment_id} with UUID: {scan_uuid}"
        else:
            err_msg = f"Failed to create Tenable scan for Assessment {assessment.id} (scan_id: {scan_id}). Check tenable_client logs."
            logger.error(err_msg)
            # self.retry(exc=Exception(err_msg)) # Optionally retry
            return f"Error: {err_msg}"

    except Assessment.DoesNotExist:
        logger.error(f"Assessment with ID {assessment_id} not found in task_create_tenable_scan.")
        return f"Error: Assessment {assessment_id} not found."
    except Exception as e:
        logger.exception(f"Unexpected error in task_create_tenable_scan for assessment ID {assessment_id}: {e}")
        # It's often better to retry for unexpected errors, as they might be transient
        self.retry(exc=e) # Celery will use the default_retry_delay and max_retries
        # Return statement here might not be reached if retry is successful on a subsequent attempt.
        # If max_retries is exhausted, the task will raise the last exception.
        return f"Error: Unexpected error for Assessment {assessment_id}. Retrying."


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def task_launch_tenable_scan(self, assessment_id):
    from .tenable_client import launch_scan # Local import can be fine in tasks
    try:
        assessment = Assessment.objects.get(id=assessment_id)
        if not assessment.tenable_scan_uuid:
            logger.warning(f"Cannot launch scan for Assessment {assessment_id}: No Tenable scan UUID found.")
            return f"No scan UUID for Assessment {assessment_id}"

        logger.info(f"Task: Launching Tenable scan {assessment.tenable_scan_uuid} for Assessment {assessment_id}")
        success = launch_scan(assessment.tenable_scan_uuid)

        if success:
            logger.info(f"Successfully triggered launch for scan {assessment.tenable_scan_uuid}")
            # TODO: Update assessment status or log this event in the model if needed
            return f"Scan {assessment.tenable_scan_uuid} launch command sent."
        else:
            logger.error(f"Failed to launch Tenable scan {assessment.tenable_scan_uuid}. Check tenable_client logs.")
            # self.retry(exc=Exception("Scan launch failed at API level")) # Optionally retry
            return f"Error: Scan {assessment.tenable_scan_uuid} launch failed."

    except Assessment.DoesNotExist:
        logger.error(f"Assessment {assessment_id} not found in task_launch_tenable_scan")
        return f"Error: Assessment {assessment_id} not found."
    except Exception as e:
        logger.exception(f"Unexpected error launching scan for assessment {assessment_id}: {e}")
        self.retry(exc=e)
        return f"Error: Unexpected error launching scan for Assessment {assessment_id}. Retrying."


@shared_task(bind=True, max_retries=3, default_retry_delay=60)  # Added bind=True
def launch_tenable_scan_task(self, assessment_id: int):
    task_id = self.request.id
    logger.info(f"[Task:{task_id}] Starting Tenable scan launch for Assessment ID: {assessment_id}")

    try:
        assessment = Assessment.objects.select_related('client').get(pk=assessment_id)
        client = assessment.client
    except Assessment.DoesNotExist:
        logger.error(f"[Task:{task_id}] Assessment ID {assessment_id} not found.")
        return f"Error: Assessment {assessment_id} not found."
    except Client.DoesNotExist:  # Should be caught by select_related if client is null and accessed
        logger.error(f"[Task:{task_id}] Client for Assessment ID {assessment_id} not found.")
        assessment.scan_status = Assessment.SCAN_ERROR
        assessment.scan_status_message = "Client record not found."
        assessment.save()
        return f"Error: Client for Assessment {assessment_id} not found."

    assessment.scan_status = Assessment.SCAN_PENDING  # Mark as pending while we work
    assessment.scan_status_message = "Preparing to launch scan..."
    assessment.save()

    # --- Get Target Agent Group Name from Client model ---
    # Assumes you've added 'tenable_agent_group_target_name' to Client model
    target_agent_group_name = client.tenable_agent_group_target_name
    if not target_agent_group_name:
        # Fallback to client.name if the specific field is not set
        logger.warning(
            f"[Task:{task_id}] 'tenable_agent_group_target_name' not set for Client ID {client.id}. Falling back to client.name ('{client.name}').")
        target_agent_group_name = client.name  # Or client.company_name, whichever holds "TEST WE"

    if not target_agent_group_name:
        errmsg = f"Client '{client.id}' for Assessment {assessment_id} has no defined name to search for an agent group."
        logger.error(f"[Task:{task_id}] {errmsg}")
        assessment.scan_status = Assessment.SCAN_ERROR
        assessment.scan_status_message = "Configuration error: Client has no agent group name."
        assessment.save()
        return f"Error: {errmsg}"

    logger.info(
        f"[Task:{task_id}] Target Tenable Agent Group Name for Client '{client.name}': '{target_agent_group_name}'")

    # --- Dynamically fetch Agent Group details (ID and UUID) by its Name ---
    agent_group_details = get_agent_group_details_by_name(target_agent_group_name)

    if not agent_group_details or 'uuid' not in agent_group_details:  # We need the UUID for scan creation
        errmsg = f"Could not find Tenable Agent Group details (or UUID) for name '{target_agent_group_name}' for Assessment {assessment_id}."
        logger.error(f"[Task:{task_id}] {errmsg}")
        assessment.scan_status = Assessment.SCAN_ERROR
        assessment.scan_status_message = f"Configuration error: Tenable Agent Group '{target_agent_group_name}' not found or API error during lookup."
        assessment.save()
        return f"Error: {errmsg}"

    # Use the Agent Group UUID for creating the scan, as per your standalone script's success
    agent_group_identifier_for_scan = agent_group_details['uuid']
    logger.info(
        f"[Task:{task_id}] Found Agent Group: ID={agent_group_details['id']}, UUID='{agent_group_identifier_for_scan}' for Name='{target_agent_group_name}'")

    # --- Policy and Scanner Configuration ---
    policy_id_to_use = TENABLE_POLICY_ID
    scanner_uuid_to_use = TENABLE_SCANNER_UUID

    if not all([policy_id_to_use, scanner_uuid_to_use]):
        errmsg = "Missing Tenable Policy ID or Scanner UUID in global configuration (Constance)."
        logger.error(f"[Task:{task_id}] {errmsg}")
        assessment.scan_status = Assessment.SCAN_ERROR
        assessment.scan_status_message = "Configuration error: Missing Tenable Policy/Scanner settings."
        assessment.save()
        return f"Error: {errmsg}"

    # --- Scan Naming and Uniqueness ---
    expected_scan_name = f"CE+ Scan - Assessment {assessment.id} - {client.name}"  # Adjust if client.name isn't suitable for scan name part

    # --- Check for Existing Scan or Create New ---
    scan_to_launch_id = None
    scan_to_launch_uuid = assessment.tenable_scan_uuid  # Use stored UUID first if available

    if scan_to_launch_uuid:
        logger.info(f"[Task:{task_id}] Assessment has a stored Tenable Scan UUID: {scan_to_launch_uuid}. Verifying...")
        # Here you might want to add a check to see if this scan still exists on Tenable
        # and if its settings (like agent group) match. For now, we'll trust the UUID.
        # If find_scan_by_name returns ID and UUID, we might need to reconcile.
        # Let's assume if UUID is present, we try to get its ID for launching.
        # For simplicity, let's re-fetch by name to ensure consistency for now,
        # or ensure create_agent_scan and find_scan_by_name both update assessment.tenable_scan_uuid AND assessment.tenable_scan_id (new field)

        # For now, let's prioritize finding by name to ensure we have the latest ID for launching
        found_id, found_uuid = find_scan_by_name(expected_scan_name)
        if found_id and found_uuid:
            logger.info(f"[Task:{task_id}] Found existing scan by name: ID={found_id}, UUID={found_uuid}")
            scan_to_launch_id = found_id
            scan_to_launch_uuid = found_uuid  # Update stored UUID if different
            assessment.tenable_scan_uuid = found_uuid
            # You might want to add assessment.tenable_scan_id = found_id if you add that field
        else:
            logger.info(
                f"[Task:{task_id}] Stored UUID {scan_to_launch_uuid} not found by current name '{expected_scan_name}'. Will attempt to create a new scan.")
            scan_to_launch_uuid = None  # Clear it so we create a new one
            assessment.tenable_scan_uuid = None

    if not scan_to_launch_id:  # If not found by name (or initial UUID was invalid)
        logger.info(
            f"[Task:{task_id}] No existing scan found or applicable. Attempting to create new scan '{expected_scan_name}' targeting Agent Group UUID: {agent_group_identifier_for_scan}")
        try:
            created_id, created_uuid = create_agent_scan(
                name=expected_scan_name,
                policy_id_val=policy_id_to_use,
                scanner_uuid_val=scanner_uuid_to_use,
                agent_group_identifier=agent_group_identifier_for_scan  # Pass the Agent Group UUID
            )

            if created_id and created_uuid:
                scan_to_launch_id = created_id
                scan_to_launch_uuid = created_uuid
                assessment.tenable_scan_uuid = created_uuid  # Store the UUID of the newly created scan
                logger.info(f"[Task:{task_id}] Successfully created scan: ID={created_id}, UUID={created_uuid}")
            else:
                errmsg = f"Failed to create Tenable scan '{expected_scan_name}' targeting Agent Group '{target_agent_group_name}' (UUID: {agent_group_identifier_for_scan})."
                logger.error(f"[Task:{task_id}] {errmsg}")
                assessment.scan_status = Assessment.SCAN_ERROR
                assessment.scan_status_message = "Error: Failed to create Tenable scan."
                assessment.save()
                # Log placeholder for actual assessment log
                # AssessmentLog.objects.create(assessment=assessment, message=errmsg, log_type=AssessmentLog.ERROR)
                return f"Error: {errmsg} (Assessment {assessment_id})"
        except Exception as e:  # Catch any other unexpected error during creation
            errmsg = f"Unexpected error during scan creation for Assessment {assessment_id}: {e}"
            logger.error(f"[Task:{task_id}] {errmsg}", exc_info=True)
            assessment.scan_status = Assessment.SCAN_ERROR
            assessment.scan_status_message = "Error: Unexpected error creating Tenable scan."
            assessment.save()
            return f"Error: {errmsg}"

    # --- Launch the Scan ---
    if scan_to_launch_id:
        logger.info(
            f"[Task:{task_id}] Attempting to launch Tenable scan ID: {scan_to_launch_id} (UUID: {scan_to_launch_uuid})")
        # Pass the INTEGER ID to launch_scan_on_tenable
        if launch_scan_on_tenable(str(scan_to_launch_id)):  # launch_scan_on_tenable expects string for now
            logger.info(f"[Task:{task_id}] Successfully initiated launch for Tenable scan ID: {scan_to_launch_id}.")
            assessment.scan_status = Assessment.SCAN_LAUNCHED
            assessment.scan_status_message = f"Scan launched on Tenable (Scan ID: {scan_to_launch_id}, UUID: {scan_to_launch_uuid}). Awaiting results."
            assessment.last_tenable_scan_launch_time = timezone.now()
        else:
            errmsg = f"Failed to launch Tenable scan ID: {scan_to_launch_id} for Assessment {assessment_id}."
            logger.error(f"[Task:{task_id}] {errmsg}")
            assessment.scan_status = Assessment.SCAN_ERROR
            assessment.scan_status_message = "Error: Failed to launch Tenable scan after creation/verification."
    else:
        # This case should ideally not be reached if creation was successful
        errmsg = f"No Tenable scan ID available to launch for Assessment {assessment_id}."
        logger.error(f"[Task:{task_id}] {errmsg}")
        assessment.scan_status = Assessment.SCAN_ERROR
        assessment.scan_status_message = "Error: No scan available to launch."

    assessment.save()
    logger.info(
        f"[Task:{task_id}] Completed Tenable scan launch process for Assessment ID: {assessment_id}. Status: {assessment.get_scan_status_display()}")
    return f"Tenable scan launch process for Assessment {assessment_id} finished with status: {assessment.scan_status_message}"