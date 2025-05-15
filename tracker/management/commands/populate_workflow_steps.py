import datetime
from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction
from django.utils.text import slugify
from tracker.models import WorkflowStepDefinition # Ensure this path is correct

class Command(BaseCommand):
    help = 'Populates the WorkflowStepDefinition model with standard CE+ assessment steps.'

    WORKFLOW_STEPS_DATA = [
        {'order': 1, 'name': 'Agree Date', 'description': 'Agree date of assessment', 'assignee': 'Both', 'template_name': 'step_agree_date.html', 'skippable': False},
        {'order': 2, 'name': 'Define User Devices', 'description': "List all users, roles, computer OS versions, mobile device versions in 'User Devices'.", 'assignee': 'Applicant', 'template_name': 'step_define_user_devices.html', 'skippable': False},
        {'order': 3, 'name': 'Define External IPs', 'description': "List external IPs/hostnames of internet-facing devices in 'External IPs'.", 'assignee': 'Applicant', 'template_name': 'step_define_external_ips.html', 'skippable': False},
        {'order': 4, 'name': 'Define Servers', 'description': "List all managed servers (OS/version/role) in 'Servers'.", 'assignee': 'Applicant', 'template_name': 'step_define_servers.html', 'skippable': False},
        {'order': 5, 'name': 'Provide MFA Proof', 'description': "Provide admin and user MFA screenshots for each required cloud service in 'MFA'.", 'assignee': 'Applicant', 'template_name': 'step_provide_mfa_proof.html', 'skippable': False},
        {'order': 6, 'name': 'Select Sample', 'description': 'Assessor selects list of users/devices to sample.', 'assignee': 'Assessor', 'template_name': 'step_select_sample.html', 'skippable': False},
        {'order': 7, 'name': 'Confirm Availability', 'description': 'Applicant confirms selected users are available for approx. 30 mins each on assessment date.', 'assignee': 'Applicant', 'template_name': 'step_confirm_availability.html', 'skippable': False},
        {'order': 8, 'name': 'Finalise Sample List', 'description': 'Both agree final list of users for assessment; Assessor provides list.', 'assignee': 'Both', 'template_name': 'step_finalise_sample_list.html', 'skippable': False},
        {'order': 9, 'name': 'Install Nessus Agents', 'description': 'Applicant installs Nessus agents on selected computers (details provided by Assessor).', 'assignee': 'Applicant', 'template_name': 'step_install_nessus_agents.html', 'skippable': False},
        {'order': 10, 'name': 'Book User Slots', 'description': 'Applicant books selected users for sequential 1-hour slots with assessor on agreed date.', 'assignee': 'Applicant', 'template_name': 'step_book_user_slots.html', 'skippable': False},
        {'order': 11, 'name': 'Inform Users', 'description': 'Applicant informs selected users about the assessment process (screen sharing, malware tests, etc.).', 'assignee': 'Applicant', 'template_name': 'step_inform_users.html', 'skippable': False},
        {'order': 12, 'name': 'Install Mobile App', 'description': 'Applicant ensures necessary app (e.g., Teams) is installed on selected mobile devices.', 'assignee': 'Applicant', 'template_name': 'step_install_mobile_app.html', 'skippable': False},
        {'order': 13, 'name': 'Update Devices', 'description': 'Applicant updates all computer & mobile device OS and installed apps.', 'assignee': 'Applicant', 'template_name': 'step_update_devices.html', 'skippable': False},
        {'order': 14, 'name': 'Agent Test Scans', 'description': 'Assessor runs test scans of selected computers via Nessus agents.', 'assignee': 'Assessor', 'template_name': 'step_agent_test_scans.html', 'skippable': False},
        {'order': 15, 'name': 'Remediate Agent Scans', 'description': 'Applicant updates apps/OS if scans show vulnerabilities.', 'assignee': 'Applicant', 'template_name': 'step_remediate_agent_scans.html', 'skippable': False},
        {'order': 16, 'name': 'External Scan', 'description': 'Assessor scans external IP addresses/hostnames.', 'assignee': 'Assessor', 'template_name': 'step_external_scan.html', 'skippable': False},
        {'order': 17, 'name': 'Remediate External Scan', 'description': 'Applicant remediates identified issues, if any, from external scan.', 'assignee': 'Applicant', 'template_name': 'step_remediate_external_scan.html', 'skippable': False},
        {'order': 18, 'name': 'Send Test Emails', 'description': 'Assessor sends selected users test emails with fake malware.', 'assignee': 'Assessor', 'template_name': 'step_send_test_emails.html', 'skippable': False},
        {'order': 19, 'name': 'Assessment Day Execution', 'description': 'Assessment Day: Nessus scans run, checks on user computers and mobiles performed.', 'assignee': 'Both', 'template_name': 'step_assessment_day_execution.html', 'skippable': False},
        {'order': 20, 'name': 'Generate Report', 'description': 'Assessor generates the final assessment report.', 'assignee': 'Assessor', 'template_name': 'step_generate_report.html', 'skippable': False},
        {'order': 21, 'name': 'Issue Certificate', 'description': 'Certification Body issues certificate upon successful assessment.', 'assignee': 'Assessor', 'template_name': 'step_issue_certificate.html', 'skippable': False},
    ]

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting Workflow Step Definition population...'))
        created_count = 0
        updated_count = 0
        skipped_count = 0

        for step_data in self.WORKFLOW_STEPS_DATA:
            try:
                default_template_name_if_missing = f"step_{slugify(step_data['name'])}.html"
                defaults = {
                    'name': step_data['name'],
                    'description': step_data['description'],
                    'assignee_type': step_data['assignee'],
                    'template_name': step_data.get('template_name', default_template_name_if_missing),
                    'skippable': step_data.get('skippable', False),
                    'is_active': step_data.get('is_active', True)
                }

                # Check current state BEFORE update_or_create to correctly log updates
                needs_update_check = False
                try:
                    existing_obj = WorkflowStepDefinition.objects.get(step_order=step_data['order'])
                    for key, value in defaults.items():
                        if getattr(existing_obj, key) != value:
                            # self.stdout.write(f"DEBUG: Order {existing_obj.step_order}, Field '{key}' differs. DB: '{getattr(existing_obj, key)}', New: '{value}'")
                            needs_update_check = True
                            break
                except WorkflowStepDefinition.DoesNotExist:
                    # Object doesn't exist, so it will be created, not updated.
                    # needs_update_check remains False, which is fine as 'created' path handles it.
                    pass

                # Perform the create or update operation
                obj, created = WorkflowStepDefinition.objects.update_or_create(
                    step_order=step_data['order'],
                    defaults=defaults
                )

                if created:
                    created_count += 1
                    self.stdout.write(self.style.SUCCESS(f"  Created: Step {obj.step_order} - {obj.name} (Template: '{obj.template_name}', Skippable: {obj.skippable})"))
                else:
                    # Not created, so it was either updated or skipped
                    if needs_update_check:
                        updated_count += 1
                        self.stdout.write(self.style.WARNING(f"  Updated: Step {obj.step_order} - {obj.name} (Template: '{obj.template_name}', Skippable: {obj.skippable})"))
                    else:
                        skipped_count += 1
                        # self.stdout.write(f"  Skipped (no change): Step {obj.step_order} - {obj.name}")


            except IntegrityError as e:
                self.stderr.write(self.style.ERROR(f"  Integrity Error processing step {step_data.get('order', 'N/A')}: {e}"))
            except Exception as e:
                 self.stderr.write(self.style.ERROR(f"  Unexpected error processing step {step_data.get('order', 'N/A')}: {e}"))

        self.stdout.write(self.style.SUCCESS(f'\nWorkflow Step Definition population complete.'))
        self.stdout.write(self.style.SUCCESS(f'  {created_count} created.'))
        self.stdout.write(self.style.WARNING(f'  {updated_count} updated.'))
        if skipped_count > 0:
             self.stdout.write(f'  {skipped_count} skipped (already up-to-date).')