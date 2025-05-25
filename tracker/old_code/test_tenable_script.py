# File: test_tenable_scan.py
import os
import logging
import uuid
import requests
from tenable.io import TenableIO
from tenable.errors import APIError, ForbiddenError

# --- Configuration ---
# Load environment variables from .env file



ACCESS_KEY = "1b328bd0d6706bef7c3ce087d6c16e8e17c19f59d703e968d8d193605e5aeb3a"
SECRET_KEY = "08b8b578b50c61e5aaca26e5205eefcceacc78a335a4698fa38ebd59f35c8c56"
TENABLE_URL = "https://cloud.tenable.com" # Or your specific Tenable URL

# --- Parameters for the test scan ---
# !! Replace with the actual values you are using !!
POLICY_ID = 71 # The integer ID of the policy
SCANNER_UUID = "2e7d8b44-7b38-733c-2ff3-15cc4956d494f632d534fffed23c" # UUID of the Cloud Scanner (or appropriate scanner)
AGENT_GROUP_ID = 335107 # The integer ID of the Agent Group ("TEST WE")

TARGET_AGENT_GROUP_ID = 335107
TARGET_AGENT_GROUP_NAME = "TEST WE" # Optional: For logging verification

SCAN_NAME = f"Standalone API Test Scan - Auto AG {TARGET_AGENT_GROUP_ID}" # Unique name

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger()

# --- Main Script Logic ---
def run_test():
    log.info("--- Starting Tenable Scan Creation Test (fetching Agent Group UUID) ---")

    if not ACCESS_KEY or not SECRET_KEY:
        log.error("TENABLE_ACCESS_KEY or TENABLE_SECRET_KEY not found in environment/.env file.")
        return

    tio = None
    agent_group_uuid_to_use = None
    new_scan_id = None
    new_scan_uuid = None

    try:
        # 1. Initialize Tenable Client
        log.info(f"Connecting to Tenable at {TENABLE_URL}...")
        tio = TenableIO(ACCESS_KEY, SECRET_KEY, url=TENABLE_URL)
        log.info("Successfully connected to Tenable.")

        # --- ADDED: List Agent Groups for Verification ---
        log.info("--- Fetching Available Agent Groups ---")
        try:
            agent_groups = tio.agent_groups.list()
            if not agent_groups:
                log.warning("No agent groups found or API key cannot list them.")
            else:
                log.info(f"Found {len(agent_groups)} Agent Group(s):")
                print("-" * 40) # Separator for readability
                for group in agent_groups:
                    group_id = group.get('id')
                    group_uuid = group.get('uuid')
                    group_name = group.get('name')
                    print(f"  ID: {group_id:<10} UUID: {group_uuid:<38} Name: {group_name}")
                print("-" * 40) # Separator
        except APIError as e:
            log.error(f"API Error listing agent groups: {e}")
            # Continue if possible, but finding the target group will likely fail
        except Exception as e:
            log.exception(f"Unexpected error listing agent groups: {e}")
            # Continue if possible
        log.info("--- Finished Listing Agent Groups ---")
        # --- END ADDED SECTION ---


        # 2. Find Agent Group UUID using the Integer ID
        log.info(f"Attempting to find UUID for Agent Group ID: {TARGET_AGENT_GROUP_ID} (Expected Name: '{TARGET_AGENT_GROUP_NAME}')")
        # Re-fetch or use the already fetched list if needed, but simple lookup is fine
        try:
            # Using list() again is simple, though slightly redundant if list above succeeded
            agent_groups = tio.agent_groups.list()
            found_group = None
            for group in agent_groups:
                if group.get('id') == TARGET_AGENT_GROUP_ID:
                    found_group = group
                    break

            if found_group:
                agent_group_uuid_to_use = found_group.get('uuid')
                fetched_name = found_group.get('name')
                if agent_group_uuid_to_use:
                    log.info(f"Target Group Found: ID={TARGET_AGENT_GROUP_ID}, Name='{fetched_name}', UUID='{agent_group_uuid_to_use}'")
                    if TARGET_AGENT_GROUP_NAME and fetched_name != TARGET_AGENT_GROUP_NAME:
                        log.warning(f"Fetched group name '{fetched_name}' does not match expected name '{TARGET_AGENT_GROUP_NAME}'.")
                else:
                    log.error(f"Found Agent Group ID {TARGET_AGENT_GROUP_ID} but it is missing a UUID: {found_group}")
                    return
            else:
                log.error(f"Could not find Agent Group with ID: {TARGET_AGENT_GROUP_ID} in the fetched list.")
                log.error("Please verify the TARGET_AGENT_GROUP_ID is correct based on the list above.")
                return

        except APIError as e:
            log.error(f"API Error fetching agent groups during target lookup: {e}")
            return
        except Exception as e:
            log.exception(f"Unexpected error fetching agent groups during target lookup: {e}")
            return

        # 3. Define Scan Settings (using fetched Agent Group UUID string)
        # ...(Scan settings definition remains the same)...
        try:
            policy_id_int = int(POLICY_ID)
            uuid.UUID(agent_group_uuid_to_use) # Validate fetched UUID format
            agent_group_uuid_str = str(agent_group_uuid_to_use)
        except (ValueError, TypeError) as e:
            log.error(f"Invalid integer Policy ID ({POLICY_ID}) or invalid fetched Agent Group UUID format ({agent_group_uuid_to_use}): {e}")
            return

        scan_settings = {
            'name': SCAN_NAME,
            'description': "Standalone script test using fetched agent group UUID.",
            'policy_id': policy_id_int,
            'scanner_id': SCANNER_UUID,
            'agent_group_id': [agent_group_uuid_str],
            'enabled': True,
        }
        log.info(f"Scan Settings Prepared: {scan_settings}")


        # 4. Attempt to Create Scan
        # ...(Scan creation attempt remains the same)...
        log.info("Attempting to create scan via API...")
        creation_response = tio.scans.create(**scan_settings)
        log.info(f"Raw API Response: {creation_response}")

        # 5. Extract Scan ID and UUID
        # ...(Extraction logic remains the same)...
        if isinstance(creation_response, dict):
             if 'id' in creation_response:
                 new_scan_id = creation_response.get('id')
             elif 'scan' in creation_response and isinstance(creation_response['scan'], dict):
                  new_scan_id = creation_response['scan'].get('id')

        if not isinstance(new_scan_id, int):
             log.error(f"Failed to extract valid integer scan ID from response.")
        else:
             log.info(f"Successfully created scan! Scan ID: {new_scan_id}. Fetching details...")
             try:
                 scan_details = tio.scans.details(scan_id=new_scan_id)
                 new_scan_uuid = scan_details.get('info', {}).get('uuid')
                 log.info(f"Fetched Scan UUID: {new_scan_uuid}")
             except Exception as details_err:
                  log.warning(f"Scan created (ID: {new_scan_id}) but failed to fetch details/UUID: {details_err}")

        log.info("--- Test Scan Creation SUCCESSFUL ---")

    except ForbiddenError as e:
        # ...(Error handling remains the same)...
        log.error(f"!!! PERMISSION ERROR !!! Failed to create scan: {e}")
        log.error(f"Settings used: {scan_settings}")
        if "permission to use all of the selected agent groups" in str(e):
             log.error(f"This occurred using the fetched AGENT GROUP UUID ('{agent_group_uuid_to_use}') for Group ID {TARGET_AGENT_GROUP_ID}.")
             log.error(f"Please meticulously check the API key user's 'Can Use' permission on Agent Group ID {TARGET_AGENT_GROUP_ID} ('{TARGET_AGENT_GROUP_NAME}') in Tenable.io.")
        else:
             log.error("Check other permissions related to scan creation or policy/scanner usage.")
        log.info("--- Test Scan Creation FAILED (Permissions) ---")
    # ...(Other error handling remains the same)...
    except APIError as e:
         log.error(f"!!! API ERROR !!! Failed to create scan: {e}")
         log.error(f"Settings used: {scan_settings}")
         log.info("--- Test Scan Creation FAILED (API Error) ---")
    except Exception as e:
         log.exception(f"!!! UNEXPECTED ERROR !!! An error occurred: {e}")
         log.info("--- Test Scan Creation FAILED (Unexpected Error) ---")

    finally:
        # 6. Optional Cleanup
        # ...(Cleanup logic remains the same)...
        if new_scan_id and tio:
            try:
                log.warning(f"Attempting to clean up by deleting test scan ID: {new_scan_id}")
               # tio.scans.delete(new_scan_id)
                log.info(f"SKIPPED -Successfully deleted test scan ID: {new_scan_id}")
            except Exception as del_e:
                log.error(f"Failed to delete test scan ID {new_scan_id}: {del_e}")
        url = "https://cloud.tenable.com/vulns/export"

        for vuls in tio.exports.vulns():
            print(vuls)

        log.info("--- Test Script Finished ---")


if __name__ == "__main__":
    run_test()

