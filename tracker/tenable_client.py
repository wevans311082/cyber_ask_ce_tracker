# tracker/tenable_client.py

import logging
from constance import config
from tenable.io import TenableIO
# --- CORRECTED IMPORT ---
from tenable.errors import APIError, NotFoundError, ForbiddenError # Import APIError as the base for Tenable API issues
# --- END CORRECTION ---

logger = logging.getLogger(__name__)

def get_tenable_io_client():
    """
    Initializes and returns a TenableIO client instance using
    API keys stored via django-constance.

    Returns:
        TenableIO: An initialized TenableIO client instance or None if config missing/connection fails.
    """
    access_key = getattr(config, 'TENABLE_ACCESS_KEY', None)
    secret_key = getattr(config, 'TENABLE_SECRET_KEY', None)
    url = getattr(config, 'TENABLE_URL', 'https://cloud.tenable.com') # Default to cloud

    if not all([access_key, secret_key, url]):
        logger.error("Tenable API Keys or URL not configured in Admin settings (via django-constance).")
        return None

    try:
        logger.debug(f"Attempting to connect to Tenable.io at {url}")
        tio = TenableIO(access_key, secret_key, url=url)
        # Optional quick check - this call itself might raise APIError on auth failure
        # tio.about.build()
        logger.info("Successfully initialized Tenable.io client.")
        return tio
    # --- CORRECTED EXCEPTION HANDLING ---
    except APIError as e:
        # Catch specific Tenable API errors (like auth failure during init)
        logger.exception(f"Tenable API error during client initialization or connection check: {e}")
        return None
    except Exception as e:
        # Catch other potential errors (network issues, config problems)
        logger.exception(f"Unexpected error initializing Tenable.io client at {url}: {e}")
        return None
    # --- END CORRECTION ---
def get_scan_details(scan_uuid: str) -> dict | None:
    """
    Fetches details for a specific scan using its UUID.
    Returns the scan details dictionary or None if not found or on error.
    """
    tio = get_tenable_io_client()
    if not tio:
        return None

    try:
        print(f"[DEBUG get_scan_details] Fetching details for scan UUID: {scan_uuid}") # DEBUG
        # Use tio.scans.details(scan_id=...) - scan_id can be the numeric ID or the UUID string
        scan_info = tio.scans.details(scan_uuid)
        print(f"[DEBUG get_scan_details] Found scan: {scan_info.get('info', {}).get('name')}") # DEBUG
        return scan_info # Returns dict with 'info', 'hosts', etc.
    except NotFoundError:
        logger.warning(f"Scan with UUID '{scan_uuid}' not found in Tenable.io.")
        print(f"[DEBUG get_scan_details] Scan UUID {scan_uuid} not found (404).") # DEBUG
        return None
    except APIError as e:
        logger.exception(f"Tenable API Error fetching details for scan UUID {scan_uuid}: {e}")
        print(f"[DEBUG get_scan_details] API Error fetching scan {scan_uuid}: {e}") # DEBUG
        return None
    except Exception as e:
        logger.exception(f"Unexpected error fetching details for scan UUID {scan_uuid}: {e}")
        print(f"[DEBUG get_scan_details] Unexpected Error fetching scan {scan_uuid}: {e}") # DEBUG
        return None
def find_scan_by_name(scan_name: str) -> dict | None:
    """
    Finds the *first* scan matching the provided name.
    Returns the scan details dictionary (containing UUID) or None.
    Note: Scan names are not guaranteed unique in Tenable.io.
    """
    tio = get_tenable_io_client()
    if not tio:
        return None

    try:
        print(f"[DEBUG find_scan_by_name] Searching for scan named: '{scan_name}'") # DEBUG
        scans = tio.scans.list() # Fetches all scans user can see
        for scan in scans:
            # Check if 'name' key exists and matches
            if scan.get('name') == scan_name:
                logger.info(f"Found existing scan matching name '{scan_name}' with UUID {scan.get('uuid')}")
                print(f"[DEBUG find_scan_by_name] Found matching scan: ID={scan.get('id')}, UUID={scan.get('uuid')}") # DEBUG
                # Fetch full details as list() might be summary
                return get_scan_details(scan.get('uuid'))
        logger.info(f"No scan found matching name '{scan_name}'.")
        print(f"[DEBUG find_scan_by_name] No scan found matching name '{scan_name}'.") # DEBUG
        return None
    except APIError as e:
        logger.exception(f"Tenable API Error finding scan by name '{scan_name}': {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error finding scan by name '{scan_name}': {e}")
        return None
def create_agent_scan(name: str, policy_id: int, scanner_uuid: str, agent_group_id: int) -> tuple[int | None, str | None]:
    """
    Creates a new agent scan in Tenable.io using a single API call,
    targeting a specific agent_group_id.
    Returns a tuple of (scan_id, scan_uuid), or (None, None) on error.
    """
    tio = get_tenable_io_client()
    if not tio:
        return None, None

    new_scan_id = None
    actual_scan_uuid = None

    try:
        print(f"[DEBUG create_agent_scan] Creating agent scan named: '{name}'")
        # Target using agent_group_id
        print(f"[DEBUG create_agent_scan] Policy ID: {policy_id}, Scanner UUID: {scanner_uuid}, Agent Group ID: {agent_group_id}")

        # Settings for the single create call
        scan_settings = {
            'name': name,
            'description': f"Automated CE+ agent scan created by Assessment Tracker.",
            'policy_id': policy_id, # Use integer ID
            'scanner_id': scanner_uuid, # Use UUID string
            'agent_group_id': [agent_group_id], # Use agent group ID (needs to be a list)
            'enabled': True, # Default is usually true, but explicit is fine
            # Do NOT include agent_filters
        }
        print(f"[DEBUG create_agent_scan] Create settings: {scan_settings}")

        # Single API call using tio.scans.create()
        creation_response = tio.scans.create(**scan_settings)
        print(f"[DEBUG create_agent_scan] Raw creation response: {creation_response}")

        # Extract the reliable integer ID (same logic as before)
        if isinstance(creation_response, dict):
            if 'id' in creation_response:
                new_scan_id = creation_response.get('id')
            elif 'scan' in creation_response and isinstance(creation_response['scan'], dict):
                 new_scan_id = creation_response['scan'].get('id')

        if not isinstance(new_scan_id, int):
            logger.error(f"Failed to extract valid integer scan ID from create response for '{name}'. Response: {creation_response}")
            print(f"[DEBUG create_agent_scan] Failed to get integer ID from create response: {creation_response}")
            return None, None

        print(f"[DEBUG create_agent_scan] Scan created with ID: {new_scan_id}. Fetching details for UUID...")

        # Fetch details using ID to get actual UUID (same logic as before)
        try:
            scan_details = tio.scans.details(scan_id=new_scan_id)
            actual_scan_uuid = scan_details.get('info', {}).get('uuid')
            if actual_scan_uuid:
                logger.info(f"Successfully created Tenable agent scan '{name}' (ID: {new_scan_id}, UUID: {actual_scan_uuid}) targeting Agent Group {agent_group_id}")
                print(f"[DEBUG create_agent_scan] Scan created and confirmed. ID: {new_scan_id}, UUID: {actual_scan_uuid}")
                return new_scan_id, actual_scan_uuid
            else:
                 logger.error(f"Failed to retrieve UUID for newly created scan ID {new_scan_id} ('{name}'). Details response missing UUID: {scan_details}")
                 print(f"[DEBUG create_agent_scan] Failed to get UUID from details response for ID {new_scan_id}")
                 return new_scan_id, None # Return ID even if UUID fetch failed

        except Exception as details_err:
             # Log error but return ID if create succeeded
             logger.warning(f"Error fetching details for new scan ID {new_scan_id}: {details_err}")
             print(f"[DEBUG create_agent_scan] Error fetching details for {new_scan_id}: {details_err}")
             return new_scan_id, None

    except APIError as e:
        logger.exception(f"Tenable API Error creating scan '{name}': {e}")
        print(f"[DEBUG create_agent_scan] API Error during create: {e}")
        print(f"[DEBUG create_agent_scan] Settings used: {scan_settings}") # Log settings on error
        return None, None
    except Exception as e:
        logger.exception(f"Unexpected error creating scan '{name}': {e}")
        print(f"[DEBUG create_agent_scan] Unexpected Error during create: {e}")
        print(f"[DEBUG create_agent_scan] Settings used: {scan_settings}") # Log settings on error
        return None, None
def launch_scan(scan_uuid: str) -> bool:
    """
    Launches a Tenable scan using its UUID.
    Returns True on success, False on error.
    """
    tio = get_tenable_io_client()
    if not tio:
        return False

    try:
        print(f"[DEBUG launch_scan] Launching scan with UUID: {scan_uuid}") # DEBUG
        # Use tio.scans.launch() - scan_id can be numeric ID or UUID string
        tio.scans.launch(scan_uuid)
        # Note: Launch often returns the scan_history_uuid (UUID of the specific run instance)
        # We might want to store or log this later.
        logger.info(f"Successfully launched Tenable scan with UUID: {scan_uuid}")
        print(f"[DEBUG launch_scan] Scan launch command sent successfully for UUID: {scan_uuid}") # DEBUG
        return True
    except APIError as e:
        # Handle specific errors, e.g., scan already running?
        logger.exception(f"Tenable API Error launching scan UUID {scan_uuid}: {e}")
        print(f"[DEBUG launch_scan] API Error launching scan {scan_uuid}: {e}") # DEBUG
        return False
    except Exception as e:
        logger.exception(f"Unexpected error launching scan UUID {scan_uuid}: {e}")
        print(f"[DEBUG launch_scan] Unexpected Error launching scan {scan_uuid}: {e}") # DEBUG
        return False

# CHANGES END

# --- Functions for Tagging (Keep existing if any, or add as needed later) ---
# Example placeholders if needed later:
# def check_agent_tags(agent_uuid: str, required_tag_uuid: str) -> bool: ...
# def apply_tag_to_agent(agent_uuid: str, tag_uuid: str) -> bool: ...