# tracker/management/commands/populate_cloud_services.py

from django.core.management.base import BaseCommand
from django.db import IntegrityError
from tracker.models import CloudServiceDefinition # Adjust path if needed

class Command(BaseCommand):
    help = 'Populates the CloudServiceDefinition model with a list of common services.'

    # --- Cloud Service Data ---
    # Add more entries as needed. Set is_globally_approved=True for these defaults.
    # requires_mfa_for_ce is generally True for CE compliance.
    CLOUD_SERVICE_DATA = [
        # Microsoft
        {'name': 'Microsoft 365 Business Basic/Standard/Premium', 'vendor': 'Microsoft', 'service_url': 'https://login.microsoftonline.com/', 'description': 'Cloud-based productivity suite including Exchange Online, SharePoint, Teams.', 'requires_mfa_for_ce': True},
        {'name': 'Microsoft 365 E3/E5', 'vendor': 'Microsoft', 'service_url': 'https://login.microsoftonline.com/', 'description': 'Enterprise cloud productivity suite.', 'requires_mfa_for_ce': True},
        {'name': 'Microsoft Entra ID (Azure AD)', 'vendor': 'Microsoft', 'service_url': 'https://portal.azure.com/', 'description': 'Cloud-based identity and access management service.', 'requires_mfa_for_ce': True},
        {'name': 'Microsoft Azure Portal', 'vendor': 'Microsoft', 'service_url': 'https://portal.azure.com/', 'description': 'Management portal for Azure cloud services.', 'requires_mfa_for_ce': True},
        {'name': 'Microsoft Intune', 'vendor': 'Microsoft', 'service_url': 'https://endpoint.microsoft.com/', 'description': 'Cloud-based endpoint management (MDM/MAM).', 'requires_mfa_for_ce': True},
        {'name': 'Microsoft Defender for Cloud Apps', 'vendor': 'Microsoft', 'service_url': 'https://portal.cloudappsecurity.com/', 'description': 'Cloud Access Security Broker (CASB).', 'requires_mfa_for_ce': True},
        {'name': 'GitHub (Organization Accounts)', 'vendor': 'Microsoft', 'service_url': 'https://github.com/', 'description': 'Source code hosting and collaboration platform.', 'requires_mfa_for_ce': True},

        # Google
        {'name': 'Google Workspace Business Starter/Standard/Plus', 'vendor': 'Google', 'service_url': 'https://accounts.google.com/', 'description': 'Cloud-based productivity and collaboration suite.', 'requires_mfa_for_ce': True},
        {'name': 'Google Workspace Enterprise', 'vendor': 'Google', 'service_url': 'https://accounts.google.com/', 'description': 'Enterprise cloud productivity suite.', 'requires_mfa_for_ce': True},
        {'name': 'Google Cloud Platform (GCP) Console', 'vendor': 'Google', 'service_url': 'https://console.cloud.google.com/', 'description': 'Management portal for GCP services.', 'requires_mfa_for_ce': True},

        # AWS
        {'name': 'AWS Management Console', 'vendor': 'Amazon Web Services', 'service_url': 'https://signin.aws.amazon.com/console', 'description': 'Management portal for AWS services.', 'requires_mfa_for_ce': True},

        # Salesforce
        {'name': 'Salesforce Sales Cloud/Service Cloud', 'vendor': 'Salesforce', 'service_url': 'https://login.salesforce.com/', 'description': 'Cloud-based CRM platform.', 'requires_mfa_for_ce': True},

        # Collaboration & Communication
        {'name': 'Slack (Workspace)', 'vendor': 'Salesforce', 'service_url': 'https://slack.com/signin', 'description': 'Team collaboration and messaging platform.', 'requires_mfa_for_ce': True},
        {'name': 'Zoom (Licensed Accounts)', 'vendor': 'Zoom Video Communications', 'service_url': 'https://zoom.us/signin', 'description': 'Video conferencing and communication platform.', 'requires_mfa_for_ce': True},
        {'name': 'Atlassian Cloud (Jira/Confluence)', 'vendor': 'Atlassian', 'service_url': 'https://id.atlassian.com/', 'description': 'Project management and team collaboration tools.', 'requires_mfa_for_ce': True},
        {'name': 'Trello (Business/Enterprise)', 'vendor': 'Atlassian', 'service_url': 'https://trello.com/login', 'description': 'Web-based Kanban-style list-making application.', 'requires_mfa_for_ce': True},

        # Accounting & Finance
        {'name': 'Xero', 'vendor': 'Xero', 'service_url': 'https://login.xero.com/', 'description': 'Cloud-based accounting software.', 'requires_mfa_for_ce': True},
        {'name': 'QuickBooks Online', 'vendor': 'Intuit', 'service_url': 'https://quickbooks.intuit.com/', 'description': 'Cloud-based accounting software.', 'requires_mfa_for_ce': True},
        {'name': 'Sage Accounting / Intacct', 'vendor': 'Sage Group', 'service_url': '', 'description': 'Cloud-based accounting and financial management.', 'requires_mfa_for_ce': True}, # URL varies

        # Other Common SaaS
        {'name': 'Dropbox Business', 'vendor': 'Dropbox', 'service_url': 'https://www.dropbox.com/login', 'description': 'Cloud storage and file synchronization service.', 'requires_mfa_for_ce': True},
        {'name': 'DocuSign', 'vendor': 'DocuSign', 'service_url': 'https://account.docusign.com/', 'description': 'Electronic signature service.', 'requires_mfa_for_ce': True},
        {'name': 'Mailchimp', 'vendor': 'Intuit', 'service_url': 'https://login.mailchimp.com/', 'description': 'Email marketing and automation platform.', 'requires_mfa_for_ce': True},
        {'name': 'HubSpot', 'vendor': 'HubSpot', 'service_url': 'https://app.hubspot.com/login', 'description': 'CRM, marketing, sales, and service platform.', 'requires_mfa_for_ce': True},
        {'name': 'Shopify', 'vendor': 'Shopify', 'service_url': 'https://accounts.shopify.com/', 'description': 'E-commerce platform.', 'requires_mfa_for_ce': True},
        {'name': 'Zendesk', 'vendor': 'Zendesk', 'service_url': '', 'description': 'Customer service and support platform.', 'requires_mfa_for_ce': True}, # URL varies

        # Add more as needed...
    ]

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting Cloud Service Definition population...'))
        created_count = 0
        updated_count = 0
        skipped_count = 0

        for service_entry in self.CLOUD_SERVICE_DATA:
            try:
                # Defaults for update_or_create
                defaults = {
                    'vendor': service_entry.get('vendor', ''),
                    'service_url': service_entry.get('service_url', ''),
                    'description': service_entry.get('description', ''),
                    # Default to True for pre-populated known services
                    'requires_mfa_for_ce': service_entry.get('requires_mfa_for_ce', True),
                    # Mark these pre-populated ones as globally approved
                    'is_globally_approved': True,
                    # approved_by could be set to a specific admin user if desired
                }
                # Use 'name' as the key to find existing records
                obj, created = CloudServiceDefinition.objects.update_or_create(
                    name=service_entry['name'],
                    defaults=defaults
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"  Created: {obj}")
                else:
                    # Check if any field actually changed before counting as updated
                    updated = False
                    for key, value in defaults.items():
                        if getattr(obj, key) != value:
                            # Need to update the object if we want to track updates accurately
                            # setattr(obj, key, value) # This is done by update_or_create already
                            updated = True
                            # break # No need to check further if one field changed

                    if updated:
                         updated_count += 1
                         self.stdout.write(f"  Updated: {obj}")
                    else:
                         skipped_count +=1
                         # self.stdout.write(f"  Skipped (no change): {obj}") # Optional verbose output

            except IntegrityError as e:
                self.stderr.write(self.style.ERROR(f"  Error processing {service_entry.get('name')}: {e} - Possibly duplicate name if matching logic changed."))
            except Exception as e:
                 self.stderr.write(self.style.ERROR(f"  Unexpected error processing {service_entry.get('name')}: {e}"))


        self.stdout.write(self.style.SUCCESS(f'\nCloud Service Definition population complete.'))
        self.stdout.write(self.style.SUCCESS(f'  {created_count} created.'))
        self.stdout.write(self.style.WARNING(f'  {updated_count} updated.'))
        self.stdout.write(f'  {skipped_count} skipped (already up-to-date).')