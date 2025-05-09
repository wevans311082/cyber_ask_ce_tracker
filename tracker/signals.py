from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import ScopedItem, OperatingSystem
from .utils import check_and_fail_assessment_for_eol
from .models import Assessment, WorkflowStepDefinition, AssessmentWorkflowStep
from django.db import transaction
from .tasks import task_create_tenable_scan

import logging

logger = logging.getLogger(__name__)

# Import the check function

@receiver(post_save, sender=Assessment)
def create_assessment_workflow_steps(sender, instance, created, **kwargs):
    """
    Automatically create AssessmentWorkflowStep instances for a newly created Assessment.
    """
    if created: # Only run when an Assessment record is first created
        print(f"--- SIGNAL: New Assessment created (ID: {instance.id}). Creating workflow steps... ---")
        try:
            # Get all active standard workflow steps
            standard_steps = WorkflowStepDefinition.objects.filter(is_active=True)

            if not standard_steps.exists():
                print("--- WARNING: No active WorkflowStepDefinitions found. Cannot create assessment steps. ---")
                return

            steps_to_create = []
            for step_def in standard_steps:
                steps_to_create.append(
                    AssessmentWorkflowStep(
                        assessment=instance,
                        step_definition=step_def
                        # status defaults to 'Not Started' in the model
                    )
                )

            # Use bulk_create for efficiency
            with transaction.atomic(): # Ensure all steps are created or none are
                AssessmentWorkflowStep.objects.bulk_create(steps_to_create)
            print(f"--- SIGNAL: Successfully created {len(steps_to_create)} workflow steps for Assessment {instance.id}. ---")

        except Exception as e:
            # Log error if step creation fails
            print(f"--- ERROR: Failed to create workflow steps for Assessment {instance.id}: {e} ---")
            # Consider using Python's logging module for more robust error handling
            # import logging
            # logger = logging.getLogger(__name__)
            # logger.error(f"Failed to create workflow steps for Assessment {instance.id}", exc_info=True)

@receiver(post_save, sender=ScopedItem)
def scoped_item_saved(sender, instance, created, **kwargs):
    """
    After a ScopedItem is saved (created or updated),
    check its assessment for EOL/unsupported OS.
    """
    # --- ADD THIS PRINT ---
    print(f"\n>>> DEBUG: SIGNAL HANDLER 'scoped_item_saved' ENTERED - Item ID: {instance.id}, Created: {created} <<<")
    # --- END ADD ---

    print(f"Signal received: ScopedItem {instance.id} saved. Checking assessment {instance.assessment_id}.") # Existing
    check_and_fail_assessment_for_eol(instance.assessment_id)

    # --- ADD THIS PRINT ---
    print(f">>> DEBUG: SIGNAL HANDLER 'scoped_item_saved' EXITED - Item ID: {instance.id} <<<")
    # --- END ADD ---

@receiver(post_save, sender=OperatingSystem)
def operating_system_saved(sender, instance, created, **kwargs):
    """
    After an OperatingSystem is saved (created or updated),
    check all assessments that use this OS.
    """
    # --- ADD THIS PRINT ---
    print(f"\n>>> DEBUG: SIGNAL HANDLER 'operating_system_saved' ENTERED - OS ID: {instance.id}, Created: {created} <<<")
    # --- END ADD ---

    print(f"Signal received: OperatingSystem {instance.id} ({instance}) saved. Checking related assessments.") # Existing
    # Find all ScopedItems using this OS
    items_using_os = ScopedItem.objects.filter(operating_system=instance).select_related('assessment')
    # Get unique assessment IDs
    assessment_ids = set(item.assessment_id for item in items_using_os)

    print(f"Found {len(assessment_ids)} assessments potentially affected by OS update.")
    for assessment_id in assessment_ids:
        check_and_fail_assessment_for_eol(assessment_id)

    # --- ADD THIS PRINT ---
    print(f">>> DEBUG: SIGNAL HANDLER 'operating_system_saved' EXITED - OS ID: {instance.id} <<<")
    # --- END ADD ---

@receiver(post_delete, sender=ScopedItem)
def scoped_item_deleted(sender, instance, **kwargs):
    """
    After a ScopedItem is deleted, re-check its assessment for EOL/unsupported OS
    to potentially clear a 'Fail' outcome.
    """
    # --- ADD THIS PRINT ---
    print(f"\n>>> DEBUG: SIGNAL HANDLER 'scoped_item_deleted' ENTERED - Deleted Item ID: {instance.id}, Assessment ID: {instance.assessment_id} <<<")
    # --- END ADD ---

    # Call the same check function
    check_and_fail_assessment_for_eol(instance.assessment_id)

    # --- ADD THIS PRINT ---
    print(f">>> DEBUG: SIGNAL HANDLER 'scoped_item_deleted' EXITED - Assessment ID: {instance.assessment_id} <<<")
    # --- END ADD ---

@receiver(post_save, sender=Assessment)
def trigger_tenable_scan_creation(sender, instance, created, **kwargs):
    if created and not instance.tenable_scan_uuid: # Only on creation and if no scan UUID yet
        client = instance.client
        if client.tenable_agent_group_id:
            print(f"Signal: Assessment {instance.id} created. Triggering Celery task to create Tenable scan.")
            logger.info(f"Signal: Assessment {instance.id} created. Triggering Celery task to create Tenable scan.")
            task_create_tenable_scan.delay(instance.id) # Call the Celery task asynchronously
        else:
            print(f"Signal: Client {client.name} for Assessment {instance.id} does not have a Tenable Agent Group ID. Scan creation task not triggered.")
            logger.info(f"Signal: Client {client.name} for Assessment {instance.id} does not have a Tenable Agent Group ID. Scan creation task not triggered.")

@receiver(post_save, sender=Assessment)
def trigger_tenable_scan_creation_on_assessment_save(sender, instance, created, **kwargs):
    # We use 'instance' which is the Assessment object that was saved.
    # 'created' is a boolean indicating if a new record was created.
    if created: # Only act if a new Assessment record was created
        if not instance.tenable_scan_uuid: # And if no scan UUID is already set
            client = instance.client
            if client and client.tenable_agent_group_id: # Check if client exists and has agent group ID
                logger.info(f"Signal: Assessment {instance.id} created for client {client.id} with agent group ID. Triggering Celery task to create Tenable scan.")
                task_create_tenable_scan.delay(instance.id) # Call the Celery task asynchronously
            elif not client:
                logger.warning(f"Signal: Assessment {instance.id} has no associated client. Cannot trigger Tenable scan creation.")
            else: # Client exists but no agent group ID
                logger.info(f"Signal: Client {client.name} for Assessment {instance.id} does not have a Tenable Agent Group ID. Scan creation task not triggered.")
        else:
            logger.info(f"Signal: Assessment {instance.id} created, but already has a tenable_scan_uuid or meets other exclusion criteria. Scan creation task not triggered.")
    # If not 'created', it's an update to an existing Assessment.
    # You might have other logic here for updates if needed in the future.