import logging
from constance import config
from tenable.io import TenableIO
from tenable.errors import APIError, NotFoundError, ForbiddenError
import logging
from tenable.io import TenableIO # Ensure TenableIO is imported
from django.conf import settings # If using Django settings for keys
from constance import config as constance_config # If using constance

logger = logging.getLogger(__name__)

_tio_client = None

def get_tenable_io_client():
    """Initializes and returns a TenableIO client."""
    try:
        # Prioritize Constance if available
        access_key = getattr(constance_config, 'TENABLE_ACCESS_KEY', None)
        secret_key = getattr(constance_config, 'TENABLE_SECRET_KEY', None)
        url = getattr(constance_config, 'TENABLE_URL', 'https://cloud.tenable.com')

        if not access_key or not secret_key: # Fallback to Django settings if Constance not set
            logger.debug("Tenable keys not found in Constance, trying Django settings.")
            access_key = getattr(settings, 'TENABLE_ACCESS_KEY', None)
            secret_key = getattr(settings, 'TENABLE_SECRET_KEY', None)
            url = getattr(settings, 'TENABLE_IO_URL', 'https://cloud.tenable.com')


        if access_key and secret_key:
            logger.debug(f"Attempting to connect to Tenable.io at {url}")
            tio = TenableIO(access_key, secret_key, vendor='CyberASK', product='AssessmentTracker', build='0.1') # Added identifiers
            logger.info("Successfully initialized Tenable.io client.")
            return tio
        else:
            logger.error("Tenable.io API keys (Access Key or Secret Key) are not configured.")
            return None
    except Exception as e:
        logger.error(f"Error initializing Tenable.io client: {e}", exc_info=True)
        return None
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
    Returns (scan_definition_id, scan_definition_uuid_str) or (None, None)
    The scan_definition_uuid_str can be like "template-..."
    """
    logger.debug(f"[create_agent_scan] Creating agent scan named: '{name}'")
    tio = get_tenable_io_client()
    if not tio:
        return None, None

    _policy_id = None
    if isinstance(policy_id_val, str) and policy_id_val.isdigit():
        _policy_id = int(policy_id_val)
    elif isinstance(policy_id_val, int):
        _policy_id = policy_id_val
    else:
        logger.error(f"[create_agent_scan] Invalid policy_id_val: {policy_id_val}.")
        return None, None

    _scanner_uuid = str(scanner_uuid_val) if scanner_uuid_val else None
    if not _scanner_uuid:
        logger.error(f"[create_agent_scan] Invalid scanner_uuid_val: {scanner_uuid_val}.")
        return None, None

    _agent_group_identifiers_for_api = []
    if isinstance(agent_group_identifier, str):
        _agent_group_identifiers_for_api = [agent_group_identifier]
    elif isinstance(agent_group_identifier, int):
        _agent_group_identifiers_for_api = [str(agent_group_identifier)]  # API might expect list of strings
    elif isinstance(agent_group_identifier, list) and agent_group_identifier:
        _agent_group_identifiers_for_api = [str(item) for item in agent_group_identifier]
    else:
        logger.error(f"[create_agent_scan] Invalid agent_group_identifier: {agent_group_identifier}.")
        return None, None

    scan_settings_for_api = {
        'name': name,
        'description': 'Automated CE+ agent scan created by Assessment Tracker.',
        'policy_id': _policy_id,
        'scanner_id': _scanner_uuid,  # This is the UUID of the CLOUD SCANNER or linked scanner
        'agent_group_id': _agent_group_identifiers_for_api,
        'enabled': True,
    }
    # Default scan template UUID for creation if not using policy_id directly for settings.
    # This UUID is for the *new scan definition object being created*.
    # pyTenable's create method handles the structure.
    # The 'uuid' field in the payload to Tenable API's POST /scans is for the *template* to base the scan on.
    # The response from POST /scans will contain the 'id' (numeric) and 'uuid' (string, possibly template-prefixed) of the *newly created scan definition*.

    # Example: Using a specific template UUID for creation
    # This is the UUID of the template you want the new scan to be based on.
    base_template_uuid = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"  # Basic Agent Scan template

    logger.debug(
        f"[create_agent_scan] Final 'scan_settings_for_api': {scan_settings_for_api}, Base Template UUID for creation: {base_template_uuid}")

    try:
        # tio.scans.create() takes the base_template_uuid as the first arg, then settings.
        creation_response = tio.scans.create(**scan_settings_for_api)

        if creation_response and 'id' in creation_response and 'uuid' in creation_response:
            created_scan_def_id = int(creation_response['id'])
            created_scan_def_uuid_str = str(creation_response['uuid'])  # This can be "template-..."
            logger.info(
                f"Successfully created Tenable scan definition '{name}'. ID: {created_scan_def_id}, Definition UUID: {created_scan_def_uuid_str}")
            return created_scan_def_id, created_scan_def_uuid_str
        else:
            logger.error(
                f"Tenable API did not return expected response for scan definition creation '{name}'. Response: {creation_response}")
            return None, None
    except Exception as e:
        logger.error(f"Tenable API Error creating scan definition '{name}': {e}. Settings: {scan_settings_for_api}",
                     exc_info=True)
        return None, None
def launch_scan_on_tenable(scan_definition_id_str: str, alt_targets: list = None) -> str | None:
    """
    Launches a scan in Tenable.io using its scan definition's numeric ID.
    Returns the scan_run_uuid (string) if successful, None otherwise.
    """
    tio = get_tenable_io_client()
    if not tio:
        logger.error("[launch_scan_on_tenable] Tenable client not available.")
        return None

    try:
        scan_def_id = int(scan_definition_id_str) # pytenable expects int for scan_id
        logger.info(f"[launch_scan_on_tenable] Attempting to launch scan definition ID: {scan_def_id} with targets: {alt_targets}")

        # The tio.scans.launch() method returns the scan_run_uuid (string) for the launched instance
        # For Tenable.io, this is typically a standard UUID string.
        scan_run_uuid_from_api = tio.scans.launch(scan_id=scan_def_id, targets=alt_targets if alt_targets else None)

        # CHANGES BEGIN — 2025-05-16 12:15:00
        # Add explicit logging for type and value
        logger.info(f"[launch_scan_on_tenable] API returned for launch: '{scan_run_uuid_from_api}', type: {type(scan_run_uuid_from_api)}")

        if isinstance(scan_run_uuid_from_api, str) and scan_run_uuid_from_api:
            # Validate if it looks like a UUID (optional, but good for sanity)
            # import uuid
            # try:
            #     uuid.UUID(scan_run_uuid_from_api)
            # except ValueError:
            #     logger.error(f"[launch_scan_on_tenable] API returned a string but it's not a valid UUID: {scan_run_uuid_from_api}")
            #     return None
            logger.info(f"[launch_scan_on_tenable] Successfully launched scan. Definition ID: {scan_def_id}, Scan Run UUID: {scan_run_uuid_from_api}")
            return str(scan_run_uuid_from_api) # Ensure it's a string
        else:
            logger.error(f"[launch_scan_on_tenable] Scan launch for definition ID {scan_def_id} did NOT return a valid UUID string. Received: '{scan_run_uuid_from_api}'")
            return None
        # CHANGES END — 2025-05-16 12:15:00

    except Exception as e:
        logger.error(f"[launch_scan_on_tenable] Error launching Tenable scan ID {scan_definition_id_str}: {e}", exc_info=True)
        return None