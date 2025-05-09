# tracker/tenable_client.py

import logging
from constance import config
from tenable.io import TenableIO
# --- CORRECTED IMPORT ---
from tenable.errors import APIError, NotFoundError, ForbiddenError # Import APIError as the base for Tenable API issues
# --- END CORRECTION ---

logger = logging.getLogger(__name__)

_tio_client = None

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
        # tio.about.build() # Example: tio.scanners.list() or tio.folders.list() could also work if less verbose
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
        scan_info = tio.scans.details(scan_uuid) # scan_uuid can be the UUID string
        print(f"[DEBUG get_scan_details] Found scan: {scan_info.get('info', {}).get('name')}") # DEBUG
        return scan_info
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
def find_scan_by_name2(scan_name: str) -> dict | None:
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
        scans = tio.scans.list()
        for scan in scans:
            if scan.get('name') == scan_name:
                logger.info(f"Found existing scan matching name '{scan_name}' with UUID {scan.get('uuid')}")
                print(f"[DEBUG find_scan_by_name] Found matching scan: ID={scan.get('id')}, UUID={scan.get('uuid')}") # DEBUG
                return get_scan_details(scan.get('uuid')) # Fetch full details using UUID
        logger.info(f"No scan found matching name '{scan_name}'.")
        print(f"[DEBUG find_scan_by_name] No scan found matching name '{scan_name}'.") # DEBUG
        return None
    except APIError as e:
        logger.exception(f"Tenable API Error finding scan by name '{scan_name}': {e}")
        return None
    except Exception as e:
        logger.exception(f"Unexpected error finding scan by name '{scan_name}': {e}")
        return None
def create_agent_scan2(name: str, policy_id_val: any, scanner_uuid_val: any, agent_group_id_val: any) -> tuple[int | None, str | None]:
    """
    Creates a new agent scan in Tenable.io, targeting a specific agent_group_id.
    Ensures correct data types for IDs.
    Returns a tuple of (scan_id, scan_uuid), or (None, None) on error.
    """
    tio = get_tenable_io_client()
    if not tio:
        return None, None

    new_scan_id = None
    actual_scan_uuid = None
    scan_settings_for_api = {} # To avoid using 'scan_settings' if it was a local var in an exception block

    try:
        # --- Ensure correct data types ---
        try:
            current_policy_id = int(policy_id_val)
        except (ValueError, TypeError) as e:
            log_msg = f"Invalid Policy ID: '{policy_id_val}'. Must be an integer. Error: {e}"
            logger.error(f"[create_agent_scan] {log_msg}")
            print(f"[DEBUG create_agent_scan] {log_msg}")
            return None, None

        try:
            current_agent_group_id = int(agent_group_id_val)
        except (ValueError, TypeError) as e:
            log_msg = f"Invalid Agent Group ID: '{agent_group_id_val}'. Must be an integer. Error: {e}"
            logger.error(f"[create_agent_scan] {log_msg}")
            print(f"[DEBUG create_agent_scan] {log_msg}")
            return None, None

        current_scanner_uuid = str(scanner_uuid_val) # Ensure scanner_uuid is a string

        # --- Construct scan settings for the API ---
        scan_settings_for_api = {
            'name': str(name), # Ensure name is a string
            'description': f"Automated CE+ agent scan created by Assessment Tracker.",
            'policy_id': current_policy_id,       # Now definitely an int
            'scanner_id': current_scanner_uuid,   # Now definitely a str
            'agent_group_id': [current_agent_group_id], # List containing an int
            'enabled': True,
        }

        print(f"[DEBUG create_agent_scan] Creating agent scan named: '{name}'")
        print(f"[DEBUG create_agent_scan] Using Policy ID: {current_policy_id} (type: {type(current_policy_id)})")
        print(f"[DEBUG create_agent_scan] Using Scanner UUID: {current_scanner_uuid} (type: {type(current_scanner_uuid)})")
        print(f"[DEBUG create_agent_scan] Using Agent Group IDs: {[current_agent_group_id]} (type: {type([current_agent_group_id])}, element type: {type(current_agent_group_id)})")
        print(f"[DEBUG create_agent_scan] Final 'scan_settings_for_api' payload: {scan_settings_for_api}")

        creation_response = tio.scans.create(**scan_settings_for_api)
        print(f"[DEBUG create_agent_scan] Raw creation response: {creation_response}")

        # --- Process response (your existing logic) ---
        if isinstance(creation_response, dict):
            # Prioritize 'scan'.'id' if present, as per some pyTenable versions/contexts
            if 'scan' in creation_response and isinstance(creation_response['scan'], dict) and 'id' in creation_response['scan']:
                 new_scan_id = creation_response['scan'].get('id')
            elif 'id' in creation_response: # Fallback to top-level 'id'
                new_scan_id = creation_response.get('id')

        if not isinstance(new_scan_id, int): # Check if it's a valid integer ID
            logger.error(f"Failed to extract valid integer scan ID from create response for '{name}'. Response: {creation_response}")
            print(f"[DEBUG create_agent_scan] Failed to get integer ID from create response: {creation_response}")
            return None, None # Important to return here if ID is not valid

        print(f"[DEBUG create_agent_scan] Scan created with ID: {new_scan_id}. Fetching details for UUID...")

        scan_details_response = tio.scans.details(scan_id=new_scan_id) # Use integer scan_id
        actual_scan_uuid = scan_details_response.get('info', {}).get('uuid')

        if actual_scan_uuid:
            logger.info(f"Successfully created Tenable agent scan '{name}' (ID: {new_scan_id}, UUID: {actual_scan_uuid}) targeting Agent Group {current_agent_group_id}")
            print(f"[DEBUG create_agent_scan] Scan created and confirmed. ID: {new_scan_id}, UUID: {actual_scan_uuid}")
            return new_scan_id, str(actual_scan_uuid) # Ensure UUID is string
        else:
            logger.error(f"Failed to retrieve UUID for newly created scan ID {new_scan_id} ('{name}'). Details response missing UUID: {scan_details_response}")
            print(f"[DEBUG create_agent_scan] Failed to get UUID from details response for ID {new_scan_id}")
            return new_scan_id, None # Return ID even if UUID fetch failed, indicates partial success

    except APIError as e:
        logger.exception(f"Tenable API Error creating scan '{name}': {e}. Payload: {scan_settings_for_api}")
        print(f"[DEBUG create_agent_scan] API Error during create: {e}")
        print(f"[DEBUG create_agent_scan] Settings used (at time of error): {scan_settings_for_api}")
        return None, None
    except Exception as e:
        logger.exception(f"Unexpected error creating scan '{name}': {e}. Payload: {scan_settings_for_api}")
        print(f"[DEBUG create_agent_scan] Unexpected Error during create: {e}")
        print(f"[DEBUG create_agent_scan] Settings used (at time of error): {scan_settings_for_api}")
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
        tio.scans.launch(scan_uuid) # scan_uuid can be numeric ID or UUID string
        logger.info(f"Successfully launched Tenable scan with UUID: {scan_uuid}")
        print(f"[DEBUG launch_scan] Scan launch command sent successfully for UUID: {scan_uuid}") # DEBUG
        return True
    except APIError as e:
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
# def apply_tag_to_agent(agent_uuid: str, tag_uuid: str) -> bool: ...# def get_tag_by_name(tag_name: str) -> dict | None: ...
# # def check_agent_tags(agent_uuid: str, required_tag_uuid: str) -> bool: ...
# # def apply_tag_to_agent(agent_uuid: str, tag_uuid: str) -> bool: ...
# # def get_agent_by_name(agent_name: str) -> dict | None: ...
# # def get_agent_group_by_name(group_name: str) -> dict | None: ...
# # def list_agents_in_group(group_id: int) -> list: ...


def find_scan_by_name(scan_name: str) -> tuple[int | None, str | None]:
    # ... (your existing find_scan_by_name function - seems okay)
    logger.debug(f"[find_scan_by_name] Searching for scan named: '{scan_name}'")
    tio = get_tenable_io_client()
    if not tio:
        return None, None
    try:
        scans = tio.scans.list()
        for scan in scans:
            if scan['name'] == scan_name:
                logger.info(
                    f"[find_scan_by_name] Found existing scan: ID={scan['id']}, UUID={scan['uuid']}, Name='{scan_name}'")
                return scan['id'], scan['uuid']
        logger.info(f"[find_scan_by_name] No scan found matching name '{scan_name}'.")
        return None, None
    except Exception as e:
        logger.error(f"[find_scan_by_name] Error searching for scan '{scan_name}': {e}", exc_info=True)
        return None, None


def get_agent_group_details_by_name(group_name: str) -> dict | None:
    """
    Finds details (including ID and UUID) of a Tenable.io agent group by its name.
    Returns a dictionary like {'id': 123, 'uuid': 'xyz...', 'name': '...'} or None.
    """
    logger.debug(f"[get_agent_group_details_by_name] Searching for agent group named: '{group_name}'")
    tio = get_tenable_io_client()
    if not tio:
        logger.error("[get_agent_group_details_by_name] Failed to initialize Tenable.io client.")
        return None

    try:
        groups = tio.agent_groups.list()  # Fetches all agent groups
        for group in groups:
            if group.get('name') == group_name:
                group_id = group.get('id')
                group_uuid = group.get('uuid')
                if isinstance(group_id, int) and isinstance(group_uuid, str):
                    logger.info(
                        f"[get_agent_group_details_by_name] Found agent group: ID={group_id}, UUID='{group_uuid}', Name='{group_name}'")
                    return {'id': group_id, 'uuid': group_uuid, 'name': group_name}
                else:
                    logger.error(
                        f"[get_agent_group_details_by_name] Found agent group '{group_name}' but its ID or UUID is invalid. ID: {group_id}, UUID: {group_uuid}")
                    return None  # Or handle more gracefully
        logger.warning(f"[get_agent_group_details_by_name] No agent group found with name '{group_name}'.")
        return None
    except Exception as e:
        logger.error(f"[get_agent_group_details_by_name] Error finding agent group by name '{group_name}': {e}",
                     exc_info=True)
        return None


def create_agent_scan(name: str, policy_id_val: any, scanner_uuid_val: any, agent_group_identifier: any) -> tuple[int | None, str | None]:
    """
    Creates an agent scan in Tenable.io.
    agent_group_identifier can be an integer ID or a UUID string.
    The API seems to prefer a list of these identifiers.
    """
    logger.debug(f"[create_agent_scan] Creating agent scan named: '{name}'")
    tio = get_tenable_io_client()
    if not tio:
        return None, None

    # Validate policy_id
    _policy_id = None
    if isinstance(policy_id_val, str) and policy_id_val.isdigit():
        _policy_id = int(policy_id_val)
    elif isinstance(policy_id_val, int):
        _policy_id = policy_id_val
    else:
        logger.error(
            f"[create_agent_scan] Invalid policy_id_val: {policy_id_val}. Must be an int or string representation of an int.")
        return None, None
    logger.debug(f"[create_agent_scan] Using Policy ID: {_policy_id} (type: {type(_policy_id)})")

    # Validate scanner_uuid
    _scanner_uuid = None
    if isinstance(scanner_uuid_val, str) and scanner_uuid_val:  # Assuming UUIDs are non-empty strings
        _scanner_uuid = scanner_uuid_val
    else:
        logger.error(f"[create_agent_scan] Invalid scanner_uuid_val: {scanner_uuid_val}. Must be a non-empty string.")
        return None, None
    logger.debug(f"[create_agent_scan] Using Scanner UUID: {_scanner_uuid} (type: {type(_scanner_uuid)})")

    # Prepare agent_group_id list (using UUIDs as per standalone script success)
    _agent_group_identifiers_for_api = []
    if isinstance(agent_group_identifier, str):  # Expecting a UUID string
        _agent_group_identifiers_for_api = [agent_group_identifier]
    elif isinstance(agent_group_identifier, int):  # Fallback to integer ID if provided
        _agent_group_identifiers_for_api = [agent_group_identifier]
    elif isinstance(agent_group_identifier, list) and agent_group_identifier:
        # If it's already a list, use as is (assuming it's a list of UUIDs or IDs)
        _agent_group_identifiers_for_api = agent_group_identifier
    else:
        logger.error(
            f"[create_agent_scan] Invalid agent_group_identifier: {agent_group_identifier}. Expected UUID string, int ID, or list.")
        return None, None

    logger.debug(
        f"[create_agent_scan] Using Agent Group Identifiers: {_agent_group_identifiers_for_api} (type: {type(_agent_group_identifiers_for_api)}, element type: {type(_agent_group_identifiers_for_api[0]) if _agent_group_identifiers_for_api else 'N/A'})")

    # Construct the settings for the scan API call
    # Base template for scan settings
    scan_template_uuid = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"  # Basic Agent Scan template UUID (example)
    # You might need to fetch available templates if this isn't always the right one
    # For agent scans, 'policy_id' is generally preferred over 'template_uuid' directly in settings for basic agent scan.
    # The 'uuid' in the overall payload is for the new scan object being created.

    scan_settings_for_api = {
        'name': name,
        'description': 'Automated CE+ agent scan created by Assessment Tracker.',
        'policy_id': _policy_id,  # Integer Policy ID
        'scanner_id': _scanner_uuid,  # This is the UUID of the CLOUD SCANNER where agents are linked.
        # For agent scans, this points to the scanner managing the agents.
        'agent_group_id': _agent_group_identifiers_for_api,  # List of agent group UUIDs or IDs
        'enabled': True,
        # Add other necessary fields if your policy or scan type requires them
        # e.g., 'launch_now', 'schedule', etc. if not launching separately.
    }

    # The pyTenable library wraps `scan_settings_for_api` inside a "settings" key
    # and adds a top-level "uuid" for the scan creation request.
    # We just need to pass the settings dictionary to `tio.scans.create()`.

    logger.debug(f"[create_agent_scan] Final 'scan_settings_for_api' payload for pyTenable: {scan_settings_for_api}")

    try:
        # The tio.scans.create() method expects keyword arguments for the settings.
        # It will internally structure it as {"uuid": "...", "settings": scan_settings_for_api}
        creation_response = tio.scans.create(**scan_settings_for_api)

        if creation_response and 'id' in creation_response and 'uuid' in creation_response:  # Or however pyTenable returns it
            created_scan_id = creation_response['id']
            created_scan_uuid = creation_response['uuid']
            logger.info(f"Successfully created Tenable scan '{name}'. ID: {created_scan_id}, UUID: {created_scan_uuid}")
            return created_scan_id, created_scan_uuid
        else:
            logger.error(
                f"Tenable API did not return expected response for scan creation '{name}'. Response: {creation_response}")
            return None, None
    except Exception as e:
        logger.error(f"Tenable API Error creating scan '{name}': {e}. Payload: {scan_settings_for_api}", exc_info=True)
        return None, None


def launch_scan_on_tenable(scan_uuid: str) -> bool:
    # ... (your existing launch_scan_on_tenable function - seems okay)
    logger.debug(f"[launch_scan_on_tenable] Attempting to launch scan with UUID: {scan_uuid}")
    tio = get_tenable_io_client()
    if not tio:
        return False
    try:
        # Ensure scan_uuid is for a scan, not a policy or template.
        # The scans.launch() method takes the integer scan_id, not the UUID.
        # We need to get the integer ID from the UUID if we don't have it.
        # However, if find_scan_by_name OR create_agent_scan returns the integer ID, use that.
        # Let's assume the task has the correct scan_id to pass here.
        # The pyTenable library's scans.launch() takes scan_id (int)

        # First, let's clarify: tio.scans.launch(scan_id, targets=None)
        # The task launch_tenable_scan_task should be getting the scan_id (integer)
        # If it only has UUID, it needs to fetch the scan details to get the ID.
        # For simplicity, if scan_uuid is actually scan_id (int), this will work.
        # Let's assume the caller provides the integer scan_id.
        # This function might need renaming or clarification if it only gets UUID.

        # For now, let's assume scan_uuid is actually the scan_id (integer)
        # This is a common point of confusion. Let's fix create_agent_scan to return ID
        # And ensure task uses ID for launch.

        # If scan_uuid is truly a UUID, we need to get the scan's integer ID first.
        # This is inefficient if we just created/found it.
        # The launch_tenable_scan_task should have access to the integer scan_id.

        # For now, let's assume scan_uuid IS the integer ID for launch.
        # If not, the calling task needs to provide the correct integer ID.

        # The `pytenable` function `tio.scans.launch()` expects the *integer ID* of the scan.
        # If `scan_uuid` parameter here is indeed the UUID string, we need to convert it.
        # However, `create_agent_scan` returns `created_id` which is the integer.
        # `find_scan_by_name` also returns `scan_id` which is the integer.
        # So, the calling task should already have the integer ID.
        # Let's rename the parameter for clarity IF this function is only called with the integer ID.

        # Assuming `scan_uuid` is actually the integer `scan_id` passed by the task:
        scan_id_to_launch = int(scan_uuid)  # Ensure it's an int if it might be passed as string

        tio.scans.launch(scan_id_to_launch)
        logger.info(f"Successfully launched Tenable scan with ID: {scan_id_to_launch}")
        return True
    except Exception as e:
        logger.error(f"Tenable API Error launching scan ID '{scan_uuid}': {e}", exc_info=True)
        return False