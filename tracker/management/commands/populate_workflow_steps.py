import datetime
from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction
# Ensure the correct import path for your models
# If your app is named 'tracker', this should be correct.
from tracker.models import WorkflowStepDefinition

class Command(BaseCommand):
    """
    Django management command to populate the WorkflowStepDefinition model
    with the standard steps for a Cyber Essentials Plus assessment based
    on the provided workflow/spreadsheet.
    """
    help = 'Populates the WorkflowStepDefinition model with standard CE+ assessment steps.'

    # --- Workflow Steps Data ---
    # Define steps based on "Steps required.csv" or your defined workflow.
    # Adjust descriptions and assignee types as needed.
    # 'order' defines the sequence.
    # 'name' is a short identifier.
    # 'description' is the full requirement text.
    # 'assignee' maps to the assignee_type field choices in the model.
    WORKFLOW_STEPS_DATA = [
        {'order': 1, 'name': 'Agree Date', 'description': 'Agree date of assessment', 'assignee': 'Both'},
        {'order': 2, 'name': 'Define User Devices', 'description': "List all users, roles, computer OS versions, mobile device versions in 'User Devices'.", 'assignee': 'Applicant'},
        {'order': 3, 'name': 'Define External IPs', 'description': "List external IPs/hostnames of internet-facing devices in 'External IPs'.", 'assignee': 'Applicant'},
        {'order': 4, 'name': 'Define Servers', 'description': "List all managed servers (OS/version/role) in 'Servers'.", 'assignee': 'Applicant'},
        {'order': 5, 'name': 'Provide MFA Proof', 'description': "Provide admin and user MFA screenshots for each required cloud service in 'MFA'.", 'assignee': 'Applicant'},
        {'order': 6, 'name': 'Select Sample', 'description': 'Assessor selects list of users/devices to sample.', 'assignee': 'Assessor'},
        {'order': 7, 'name': 'Confirm Availability', 'description': 'Applicant confirms selected users are available for approx. 30 mins each on assessment date.', 'assignee': 'Applicant'},
        {'order': 8, 'name': 'Finalise Sample List', 'description': 'Both agree final list of users for assessment; Assessor provides list.', 'assignee': 'Both'},
        {'order': 9, 'name': 'Install Nessus Agents', 'description': 'Applicant installs Nessus agents on selected computers (details provided by Assessor).', 'assignee': 'Applicant'},
        {'order': 10, 'name': 'Book User Slots', 'description': 'Applicant books selected users for sequential 1-hour slots with assessor on agreed date.', 'assignee': 'Applicant'},
        {'order': 11, 'name': 'Inform Users', 'description': 'Applicant informs selected users about the assessment process (screen sharing, malware tests, etc.).', 'assignee': 'Applicant'},
        {'order': 12, 'name': 'Install Mobile App', 'description': 'Applicant ensures necessary app (e.g., Teams) is installed on selected mobile devices.', 'assignee': 'Applicant'},
        {'order': 13, 'name': 'Update Devices', 'description': 'Applicant updates all computer & mobile device OS and installed apps.', 'assignee': 'Applicant'},
        {'order': 14, 'name': 'Agent Test Scans', 'description': 'Assessor runs test scans of selected computers via Nessus agents.', 'assignee': 'Assessor'},
        {'order': 15, 'name': 'Remediate Agent Scans', 'description': 'Applicant updates apps/OS if scans show vulnerabilities.', 'assignee': 'Applicant'},
        {'order': 16, 'name': 'External Scan', 'description': 'Assessor scans external IP addresses/hostnames.', 'assignee': 'Assessor'},
        {'order': 17, 'name': 'Remediate External Scan', 'description': 'Applicant remediates identified issues, if any, from external scan.', 'assignee': 'Applicant'},
        {'order': 18, 'name': 'Send Test Emails', 'description': 'Assessor sends selected users test emails with fake malware.', 'assignee': 'Assessor'},
        {'order': 19, 'name': 'Assessment Day Execution', 'description': 'Assessment Day: Nessus scans run, checks on user computers and mobiles performed.', 'assignee': 'Both'},
        {'order': 20, 'name': 'Generate Report', 'description': 'Assessor generates the final assessment report.', 'assignee': 'Assessor'},
        {'order': 21, 'name': 'Issue Certificate', 'description': 'Certification Body issues certificate upon successful assessment.', 'assignee': 'Assessor'}, # Or a different role like 'CB' if needed
    ]

    @transaction.atomic  # Ensures all steps are created or none are, maintaining consistency
    def handle(self, *args, **options):
        """
        Executes the command to populate or update WorkflowStepDefinition entries.
        Uses update_or_create to avoid duplicates and allow rerunning the command.
        """
        self.stdout.write(self.style.SUCCESS('Starting Workflow Step Definition population...'))
        created_count = 0
        updated_count = 0
        skipped_count = 0 # Count steps that already existed and didn't need updating

        for step_data in self.WORKFLOW_STEPS_DATA:
            try:
                # Prepare the data for defaults in update_or_create
                defaults = {
                    'name': step_data['name'],
                    'description': step_data['description'],
                    'assignee_type': step_data['assignee'],
                    'is_active': True # Assume all steps defined here are active
                }

                # Use step_order as the unique key to find existing records
                # update_or_create returns the object and a boolean indicating if it was created
                obj, created = WorkflowStepDefinition.objects.update_or_create(
                    step_order=step_data['order'],
                    defaults=defaults
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"  Created: Step {obj.step_order} - {obj.name}")
                else:
                    # Check if any field actually changed before counting as updated
                    # This requires comparing each field in 'defaults' with the existing object 'obj'
                    is_updated = False
                    for key, value in defaults.items():
                        if getattr(obj, key) != value:
                            is_updated = True
                            break # Found a difference, no need to check further

                    if is_updated:
                        updated_count += 1
                        self.stdout.write(f"  Updated: Step {obj.step_order} - {obj.name}")
                    else:
                        skipped_count += 1
                        # Optional: uncomment for more verbose output
                        # self.stdout.write(f"  Skipped (no change): Step {obj.step_order} - {obj.name}")


            except IntegrityError as e:
                # This might happen if step_order wasn't unique, though update_or_create handles it.
                # More likely if other constraints fail.
                self.stderr.write(self.style.ERROR(f"  Integrity Error processing step {step_data.get('order', 'N/A')}: {e}"))
            except Exception as e:
                 # Catch any other unexpected errors during processing
                 self.stderr.write(self.style.ERROR(f"  Unexpected error processing step {step_data.get('order', 'N/A')}: {e}"))


        # Final summary output
        self.stdout.write(self.style.SUCCESS(f'\nWorkflow Step Definition population complete.'))
        self.stdout.write(self.style.SUCCESS(f'  {created_count} created.'))
        self.stdout.write(self.style.WARNING(f'  {updated_count} updated.'))
        self.stdout.write(f'  {skipped_count} skipped (already up-to-date).')