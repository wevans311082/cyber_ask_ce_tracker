
import logging
import traceback # Import traceback for detailed error printing
from datetime import date
from .models import Assessment, ScopedItem, OperatingSystem

# Import log function carefully or define locally
# (Ensures this util function can still work even if views.py has issues)
try:
    from .views import log_assessment_event
    USE_LOG_ASSESSMENT_EVENT = True
except ImportError:
    USE_LOG_ASSESSMENT_EVENT = False
    # Define a placeholder if the import fails, so the util doesn't crash
    def log_assessment_event(assessment, user, event):
        print(f"Placeholder Log for Assessment {assessment.id if assessment else 'N/A'}: {event}")
        pass

# Get an instance of a logger
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