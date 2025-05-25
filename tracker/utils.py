
import logging
import traceback
from datetime import date
from .models import *


try:
    from .views import log_assessment_event
    USE_LOG_ASSESSMENT_EVENT = True
except ImportError:
    USE_LOG_ASSESSMENT_EVENT = False
    # Define a placeholder if the import fails, so the util doesn't crash
    def log_assessment_event(assessment, user, event):
        print(f"Placeholder Log for Assessment {assessment.id if assessment else 'N/A'}: {event}")
        pass


logger = logging.getLogger(__name__)


def check_and_fail_assessment_for_eol(assessment_id):
    """
    Checks if an assessment contains unsupported/EOL OS in scope.
    If found AND assessment is not complete, sets final_outcome to 'Fail'.
    If not found AND assessment is not complete AND outcome was 'Fail', sets final_outcome to None.

    Args:
        assessment_id: The ID of the Assessment to check.
    """
    # --- DEBUG PRINT ---
    print(f"\n>>> DEBUG: UTIL FUNCTION 'check_and_fail_assessment_for_eol' ENTERED - Assessment ID: {assessment_id} <<<")
    # --- End DEBUG PRINT ---

    try:
        assessment = Assessment.objects.get(pk=assessment_id)
        print(f"--- DEBUG: Found Assessment: {assessment.id}, Current Status: {assessment.status}, Current Outcome: {assessment.final_outcome} ---")
        logger.debug(f"Found Assessment: {assessment}, Current Status: {assessment.status}, Current Outcome: {assessment.final_outcome}")

        # --- Exit check: Don't modify completed assessments ---
        if assessment.status.startswith('Complete_'):
             print(f"--- DEBUG: Assessment {assessment_id} already complete. Skipping EOL check and outcome modification. ---")
             logger.debug(f"Assessment {assessment_id} already complete. Skipping EOL check.")
             # Ensure finally block still runs to print exit message
             return

        # --- Check Scope Items ---
        today = date.today()
        has_unsupported = False
        scoped_items = assessment.scoped_items.select_related('operating_system').all()
        print(f"--- DEBUG: Checking {scoped_items.count()} scoped items for Assessment {assessment_id}. ---")
        logger.debug(f"Checking {scoped_items.count()} scoped items for Assessment {assessment_id}.")

        if not scoped_items.exists() and assessment.status not in ['Draft']:
             print(f"--- DEBUG: Assessment {assessment_id} has no scope items and is not Draft. Skipping EOL check. ---")
             # Fall through to potentially clear a fail if items were just deleted

        for item in scoped_items:
            item_unsupported = False
            os_details_str = "No OS Assigned"
            is_supported = True
            is_eol = False

            if item.operating_system:
                os_obj = item.operating_system
                os_details_str = f"OS: {os_obj.name} v{os_obj.version or '?'} (ID: {os_obj.id})"
                is_supported = os_obj.is_supported
                # EOL check includes date comparison
                is_eol = os_obj.end_of_life_date and os_obj.end_of_life_date < today
                print(f"--- DEBUG CHECK: Item {item.id} ({os_details_str}): DB is_supported={is_supported}, DB EOL Date={os_obj.end_of_life_date}, Calculated is_eol={is_eol} ---")
                if not is_supported or is_eol:
                    item_unsupported = True
            else:
                # Check if OS is expected but missing (adjust if needed)
                if item.item_type in ['Laptop', 'Desktop', 'Server', 'Mobile']:
                    print(f"--- DEBUG CHECK: Item {item.id} ({item.item_type}) is missing required OS. ---")
                    # item_unsupported = True # Uncomment if missing OS should cause auto-fail
                else:
                    print(f"--- DEBUG CHECK: Item {item.id} ({item.item_type}) has no OS assigned (not required type). ---")

            if item_unsupported:
                print(f"--- DEBUG: Item {item.id} MARKED AS UNSUPPORTED/EOL in Assessment {assessment_id} ---")
                logger.warning(f"  Unsupported/EOL item found: Item ID {item.id} in Assessment {assessment_id}")
                has_unsupported = True
                break # Found one, no need to check further

        # --- Update Assessment Outcome based on check ---
        if has_unsupported:
            # Found unsupported/EOL item(s)
            print(f"--- DEBUG: Assessment {assessment_id} contains unsupported/EOL OS. Checking if outcome needs update... ---")
            logger.info(f"Assessment {assessment_id} contains unsupported/EOL OS.")
            # Only set to Fail if it's not already Fail
            if assessment.final_outcome != 'Fail':
                print(f"--- DEBUG: Current outcome is '{assessment.final_outcome}'. Setting outcome to Fail for Assessment {assessment.id} ---")
                assessment.final_outcome = 'Fail'
                assessment.save(update_fields=['final_outcome']) # Save only outcome
                print(f"--- DEBUG: Assessment {assessment_id} outcome SAVE executed. Status remains '{assessment.status}'. ---")
                logger.warning(f"Assessment {assessment_id} outcome automatically set to FAIL.")
                if USE_LOG_ASSESSMENT_EVENT:
                    log_event_message = "Assessment outcome automatically set to Fail due to unsupported/EOL OS detected in scope."
                    try:
                        log_assessment_event(assessment, None, log_event_message)
                        print(f"--- DEBUG: Called log_assessment_event for Assessment {assessment.id} (set fail) ---")
                    except Exception as log_e:
                         print(f"--- ERROR: Failed to log automatic failure event for assessment {assessment_id}: {log_e} ---")
            else:
                print(f"--- DEBUG: Assessment {assessment_id} outcome was already Fail. No change made. ---")
        else:
            # No unsupported items found
            print(f"--- DEBUG: Assessment {assessment_id} passed EOL/support check. No unsupported items found. ---")
            logger.info(f"Assessment {assessment_id} passed EOL/support check.")
            # Check if the outcome needs to be cleared (was Fail, but now compliant and not complete)
            if assessment.final_outcome == 'Fail': # Removed the check for status here as the initial check ensures not complete
                 print(f"--- DEBUG: Clearing previous 'Fail' outcome for Assessment {assessment.id} as no unsupported items remain. Status is '{assessment.status}'. ---")
                 assessment.final_outcome = None # Set back to Null/None
                 assessment.save(update_fields=['final_outcome']) # Save only outcome
                 logger.info(f"Cleared automatic Fail outcome for Assessment {assessment_id} as scope is now compliant.")
                 if USE_LOG_ASSESSMENT_EVENT:
                     log_event_message = "Cleared automatic 'Fail' outcome as no unsupported/EOL items remain in scope."
                     try:
                         log_assessment_event(assessment, None, log_event_message)
                         print(f"--- DEBUG: Called log_assessment_event for Assessment {assessment.id} (cleared fail) ---")
                     except Exception as log_e:
                         print(f"--- ERROR: Failed to log clear failure event for assessment {assessment_id}: {log_e} ---")

    except Assessment.DoesNotExist:
        print(f"--- ERROR: Assessment {assessment_id} not found for EOL check. ---")
        logger.error(f"Assessment {assessment_id} not found for EOL check.")
    except Exception as e:
        # Log unexpected errors during the check
        print(f"--- ERROR: Unexpected exception during EOL check for assessment {assessment_id}: {e} ---")
        traceback.print_exc() # Print full traceback to console for debugging
        logger.exception(f"Error during EOL check for assessment {assessment_id}: {e}")

    finally:
        # --- DEBUG PRINT ---
        print(f">>> DEBUG: UTIL FUNCTION 'check_and_fail_assessment_for_eol' EXITED - Assessment ID: {assessment_id} <<<")
        # --- End DEBUG PRINT ---
def check_os_match(scoped_item_os, agent_platform_string):
    """
    Compares an OperatingSystem model instance with a Tenable platform string.
    Returns True if they likely match (or cannot be determined), False if they likely mismatch.
    """
    if not scoped_item_os or not agent_platform_string:
        return True # Cannot determine mismatch if data is missing

    agent_platform = agent_platform_string.lower()
    os_category = scoped_item_os.category.lower() if scoped_item_os.category else ""

    # Basic Mapping (Expand as needed based on Tenable platform strings)
    platform_map = {
        'windows': ['win', 'windows'],
        'linux': ['linux', 'ubu', 'centos', 'deb', 'fed', 'amzn', 'suse', 'rhel'], # Add more Linux distros
        'macos': ['mac', 'macos', 'osx', 'darwin'],
    }

    likely_match = False
    if os_category in platform_map:
        if any(p_str in agent_platform for p_str in platform_map[os_category]):
            likely_match = True
    # Add elif for other categories like 'Mobile', 'Network' if needed,
    # although agents typically aren't installed there.

    # If the category is known but doesn't match any agent platform category, it's likely a mismatch.
    # If the category is unknown or doesn't map, we assume it might be okay (return True).
    if not likely_match and os_category in platform_map:
        # We have a known OS category, but the agent platform doesn't match known strings for it.
         logger.debug(f"OS Mismatch Check: Scope Item OS Category '{os_category}' vs Agent Platform '{agent_platform_string}' -> Mismatch")
         return False
    else:
         # Either a likely match, or we couldn't determine (e.g., unknown OS category)
         logger.debug(f"OS Mismatch Check: Scope Item OS Category '{os_category}' vs Agent Platform '{agent_platform_string}' -> OK/Undetermined")
         return True
def calculate_sample_size(count):
    """Calculates required sample size based on the provided table."""
    if count <= 0:
        return 0
    elif count == 1:
        return 1
    elif 2 <= count <= 5:
        return 2
    elif 6 <= count <= 19:
        return 3
    elif 20 <= count <= 60:
        return 4
    else: # 61+
        return 5
def is_admin(user):
    # Basic check, assuming UserProfile relationship works
    if not user.is_authenticated: return False
    try:
        # Check profile relation explicitly
        profile = getattr(user, 'userprofile', None)
        return profile is not None and profile.role == 'Admin'
    except Exception as e: # Catch potential related object errors
        logger.error(f"Error checking is_admin for user {user.username}: {e}", exc_info=True)
        return False
def is_assessor(user):
    if not user.is_authenticated: return False
    try:
        profile = getattr(user, 'userprofile', None)
        return profile is not None and profile.role == 'Assessor'
    except Exception as e:
        logger.error(f"Error checking is_assessor for user {user.username}: {e}", exc_info=True)
        return False
def is_client(user):
    # Add detailed logging
    if not user.is_authenticated:
        logger.debug(f"[is_client check] User '{user.username}' NOT authenticated.")
        return False

    logger.debug(f"[is_client check] Checking user '{user.username}'.")
    profile = None # Initialize profile variable
    has_profile_attr = hasattr(user, 'userprofile')
    logger.debug(f"[is_client check] hasattr(user, 'userprofile') = {has_profile_attr}")

    if has_profile_attr:
        try:
            # Attempt to access the related profile object
            profile = user.userprofile
            logger.debug(f"[is_client check] Accessed user.userprofile. Profile object: {profile}")
            if profile is None:
                 logger.debug(f"[is_client check] user.userprofile is None.")
                 return False # Explicitly handle None case

            # Check the role on the profile object
            profile_role = getattr(profile, 'role', 'AttributeError') # Safely get role
            is_role_client = profile_role == 'Client'
            logger.debug(f"[is_client check] Profile role: '{profile_role}'. Is role 'Client'? {is_role_client}")
            return is_role_client # Return based only on role check now

        except UserProfile.DoesNotExist:
            # This handles the case where the relationship exists but the profile record doesn't
            logger.warning(f"[is_client check] UserProfile.DoesNotExist for user '{user.username}'.")
            return False
        except Exception as e:
            # Catch any other unexpected errors during profile access
            logger.error(f"[is_client check] Error accessing profile or role for user '{user.username}': {e}", exc_info=True)
            return False
    else:
        # If the 'userprofile' related manager doesn't even exist on the user object
        logger.warning(f"[is_client check] User '{user.username}' does not have 'userprofile' attribute.")
        return False
def user_can_manage_assessment_networks(user, assessment):
    """Checks if a user can manage networks for a given assessment."""
    if not user.is_authenticated:
        return False
    if is_admin(user):
        return True # Admins can manage any
    if is_assessor(user) and assessment.assessor == user:
        return True # Assigned assessor can manage
    if is_client(user) and assessment.client == user.userprofile.client:
        # Allow client management if assessment is not yet completed
        if not assessment.status.startswith('Complete_'):
            return True
    return False
def user_can_manage_assessment_external_ips(user, assessment):
    """
    Checks if a user can VIEW the External IPs list for a given assessment.
    Allows Admins, assigned Assessors, and associated Clients (regardless of assessment status).
    Editing permissions are checked separately.
    """
    if not user.is_authenticated:
        return False
    if is_admin(user):
        return True # Admins can always view

    # Assessors can view their assigned assessments
    if is_assessor(user) and assessment.assessor == user:
        return True

    # Clients can VIEW if it's their assessment (status doesn't restrict viewing list)
    if is_client(user) and hasattr(user, 'userprofile') and assessment.client == user.userprofile.client:
        return True # Allow client to view their list always

    # Default deny if none of the above match
    return False
def is_admin_or_assessor(user):
    return is_admin(user) or is_assessor(user)
def user_can_edit_assessment_external_ips(user, assessment):
    """
    Checks if a user can ADD, EDIT, or DELETE External IPs for an assessment.
    Allows Admins and Assessors (unless assessment is complete).
    Allows Clients only if the 'Define External IPs' workflow step (Order 3)
    is not marked as 'Complete' and the assessment is not fully complete.
    """
    if not user.is_authenticated:
        return False

    # --- Prevent edits on completed assessments for ALL roles ---
    # Uses the string prefix check for simplicity
    if assessment.status.startswith('Complete_'):
        return False

    # --- Admin/Assessor Permissions ---
    # Allow Admin/Assessor edits unless assessment is complete (checked above)
    if is_admin(user):
        return True
    if is_assessor(user) and assessment.assessor == user:
        return True

    # --- Client Permissions Tied to Workflow Step 3 ---
    if is_client(user) and hasattr(user, 'userprofile') and assessment.client == user.userprofile.client:
        try:
            # Find the workflow step for defining external IPs (assuming order 3)
            # Use .select_related('step_definition') for efficiency if needed elsewhere
            external_ip_workflow_step = AssessmentWorkflowStep.objects.get(
                assessment=assessment,
                step_definition__step_order=3 # Step 3 = Define External IPs
            )

            # Allow editing only if this specific step is NOT 'Complete'
            # Uses the Status choices enum defined in the AssessmentWorkflowStep model
            return external_ip_workflow_step.status != AssessmentWorkflowStep.Status.COMPLETE

        except AssessmentWorkflowStep.DoesNotExist:
            # If the workflow step wasn't created for some reason, deny permission
            print(f"Warning: Workflow Step 3 not found for Assessment {assessment.id}. Denying external IP edit permission.")
            return False
        except Exception as e:
            # Log unexpected errors and deny permission
            print(f"Error checking workflow step 3 status for assessment {assessment.id}: {e}")
            return False # Fail safe

    # Default deny if user is not admin, assigned assessor, or associated client
    return False
def user_can_manage_assessment_cloud_services(user, assessment):
    """Checks if a user can view/manage cloud services for a given assessment."""
    if not user.is_authenticated: return False
    if is_admin(user): return True
    # Assessors can always view/manage their assigned assessments
    if is_assessor(user) and assessment.assessor == user: return True
    # Clients can view/manage if it's their assessment AND not completed
    if is_client(user) and assessment.client == user.userprofile.client:
        # Decide if clients can manage even when complete (e.g. view proof)
        # For now, allow view/manage unless explicitly forbidden by status if needed
        # return not assessment.status.startswith('Complete_')
        return True # Let clients view even if complete, editing controlled by view logic
    return False