# tracker/management/commands/populate_os.py

import datetime
from django.core.management.base import BaseCommand
from django.db import IntegrityError
# Ensure correct import path and model name
from tracker.models import OperatingSystem

class Command(BaseCommand):
    help = 'Populates the OperatingSystem model with common OS versions and categories.'

    # --- OS Data with Categories ---
    OS_DATA = [
        # === Windows Client ===
        {'vendor': 'Microsoft', 'name': 'Windows 11 Pro', 'version': '24H2', 'eol': None, 'supported': True, 'url': 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information', 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Enterprise', 'version': '24H2', 'eol': None, 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Education', 'version': '24H2', 'eol': None, 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Home', 'version': '24H2', 'eol': None, 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Pro', 'version': '23H2', 'eol': datetime.date(2025, 11, 11), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Enterprise', 'version': '23H2', 'eol': datetime.date(2026, 11, 10), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Education', 'version': '23H2', 'eol': datetime.date(2026, 11, 10), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Home', 'version': '23H2', 'eol': datetime.date(2025, 11, 11), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Pro', 'version': '22H2', 'eol': datetime.date(2024, 10, 8), 'supported': False, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Enterprise', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Education', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Home', 'version': '22H2', 'eol': datetime.date(2024, 10, 8), 'supported': False, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Pro', 'version': '21H2', 'eol': datetime.date(2023, 10, 10), 'supported': False, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 11 Enterprise', 'version': '21H2', 'eol': datetime.date(2024, 10, 8), 'supported': False, 'category': 'Desktop'},

        {'vendor': 'Microsoft', 'name': 'Windows 10 Pro', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 10 Enterprise', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 10 Education', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 10 Home', 'version': '22H2', 'eol': datetime.date(2025, 10, 14), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 10 Enterprise LTSC', 'version': '2021', 'eol': datetime.date(2027, 1, 12), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Microsoft', 'name': 'Windows 10 Enterprise LTSC', 'version': '2019', 'eol': datetime.date(2029, 1, 9), 'supported': True, 'category': 'Desktop'},

        # === Windows Server ===
        {'vendor': 'Microsoft', 'name': 'Windows Server 2025', 'version': 'Standard', 'eol': None, 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2025', 'version': 'Datacenter', 'eol': None, 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2022', 'version': 'Standard', 'eol': datetime.date(2031, 10, 14), 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2022', 'version': 'Datacenter', 'eol': datetime.date(2031, 10, 14), 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2019', 'version': 'Standard', 'eol': datetime.date(2029, 1, 9), 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2019', 'version': 'Datacenter', 'eol': datetime.date(2029, 1, 9), 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2016', 'version': 'Standard', 'eol': datetime.date(2027, 1, 12), 'supported': True, 'category': 'Server'},
        {'vendor': 'Microsoft', 'name': 'Windows Server 2016', 'version': 'Datacenter', 'eol': datetime.date(2027, 1, 12), 'supported': True, 'category': 'Server'},

        # === macOS ===
        {'vendor': 'Apple', 'name': 'macOS', 'version': 'Sonoma 14', 'eol': None, 'supported': True, 'url': 'https://support.apple.com/en-us/HT201222', 'category': 'Desktop'},
        {'vendor': 'Apple', 'name': 'macOS', 'version': 'Ventura 13', 'eol': None, 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Apple', 'name': 'macOS', 'version': 'Monterey 12', 'eol': None, 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Apple', 'name': 'macOS', 'version': 'Big Sur 11', 'eol': datetime.date(2023, 11, 30), 'supported': False, 'category': 'Desktop'},

        # === Linux (Common LTS) ===
        {'vendor': 'Canonical', 'name': 'Ubuntu Desktop', 'version': '24.04 LTS', 'eol': datetime.date(2029, 4, 25), 'supported': True, 'url': 'https://ubuntu.com/about/release-cycle', 'category': 'Desktop'},
        {'vendor': 'Canonical', 'name': 'Ubuntu Server', 'version': '24.04 LTS', 'eol': datetime.date(2029, 4, 25), 'supported': True, 'category': 'Server'},
        {'vendor': 'Canonical', 'name': 'Ubuntu Desktop', 'version': '22.04 LTS', 'eol': datetime.date(2027, 4, 25), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Canonical', 'name': 'Ubuntu Server', 'version': '22.04 LTS', 'eol': datetime.date(2027, 4, 25), 'supported': True, 'category': 'Server'},
        {'vendor': 'Canonical', 'name': 'Ubuntu Desktop', 'version': '20.04 LTS', 'eol': datetime.date(2025, 4, 25), 'supported': True, 'category': 'Desktop'},
        {'vendor': 'Canonical', 'name': 'Ubuntu Server', 'version': '20.04 LTS', 'eol': datetime.date(2025, 4, 25), 'supported': True, 'category': 'Server'},

        {'vendor': 'Debian', 'name': 'Debian', 'version': '12 (Bookworm)', 'eol': datetime.date(2028, 6, 30), 'supported': True, 'url': 'https://wiki.debian.org/LTS', 'category': 'Server'}, # Assuming Server mostly
        {'vendor': 'Debian', 'name': 'Debian', 'version': '11 (Bullseye)', 'eol': datetime.date(2026, 6, 30), 'supported': True, 'category': 'Server'},

        {'vendor': 'Red Hat', 'name': 'RHEL', 'version': '9', 'eol': datetime.date(2032, 5, 31), 'supported': True, 'url': 'https://access.redhat.com/support/policy/updates/errata', 'category': 'Server'},
        {'vendor': 'Red Hat', 'name': 'RHEL', 'version': '8', 'eol': datetime.date(2029, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'AlmaLinux', 'name': 'AlmaLinux OS', 'version': '9', 'eol': datetime.date(2032, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'AlmaLinux', 'name': 'AlmaLinux OS', 'version': '8', 'eol': datetime.date(2029, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'Rocky Linux', 'name': 'Rocky Linux', 'version': '9', 'eol': datetime.date(2032, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'Rocky Linux', 'name': 'Rocky Linux', 'version': '8', 'eol': datetime.date(2029, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'CentOS', 'name': 'CentOS Stream', 'version': '9', 'eol': datetime.date(2027, 5, 31), 'supported': True, 'category': 'Server'},
        {'vendor': 'CentOS', 'name': 'CentOS Stream', 'version': '8', 'eol': datetime.date(2024, 5, 31), 'supported': False, 'category': 'Server'},

        # === Mobile ===
        {'vendor': 'Apple', 'name': 'iOS', 'version': '18', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Apple', 'name': 'iOS', 'version': '17', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Apple', 'name': 'iOS', 'version': '16', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Apple', 'name': 'iOS', 'version': '15', 'eol': None, 'supported': False, 'category': 'Mobile'},

        {'vendor': 'Apple', 'name': 'iPadOS', 'version': '18', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Apple', 'name': 'iPadOS', 'version': '17', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Apple', 'name': 'iPadOS', 'version': '16', 'eol': None, 'supported': True, 'category': 'Mobile'},

        {'vendor': 'Google', 'name': 'Android', 'version': '15', 'eol': None, 'supported': True, 'url': 'https://support.google.com/pixelphone/answer/4457705', 'category': 'Mobile'},
        {'vendor': 'Google', 'name': 'Android', 'version': '14', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Google', 'name': 'Android', 'version': '13', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Google', 'name': 'Android', 'version': '12', 'eol': None, 'supported': True, 'category': 'Mobile'},
        {'vendor': 'Google', 'name': 'Android', 'version': '11', 'eol': None, 'supported': False, 'category': 'Mobile'},

        # === Other Common ===
        {'vendor': 'VMware', 'name': 'ESXi', 'version': '8.0', 'eol': datetime.date(2029, 11, 11), 'supported': True, 'category': 'Server'}, # Or 'Other'? Let's use Server for now
        {'vendor': 'VMware', 'name': 'ESXi', 'version': '7.0', 'eol': datetime.date(2027, 4, 2), 'supported': True, 'category': 'Server'},
    ]

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting OS population (with categories)...')) # Updated message
        created_count = 0
        updated_count = 0
        skipped_count = 0

        for os_entry in self.OS_DATA:
            try:
                # Prepare defaults for update_or_create
                defaults = {
                    'vendor': os_entry.get('vendor', ''),
                    'vendor_website': os_entry.get('url', ''),
                    'end_of_life_date': os_entry.get('eol'),
                    'is_supported': os_entry.get('supported', True),
                    'notes': os_entry.get('notes', ''),
                    # --- ADD CATEGORY TO DEFAULTS ---
                    'category': os_entry.get('category', None), # Get category, default to None if missing
                    # --- END ADD ---
                }
                # Use name and version as the key for finding existing records
                obj, created = OperatingSystem.objects.update_or_create(
                    name=os_entry['name'],
                    version=os_entry.get('version', ''), # Use empty string if version is missing
                    defaults=defaults
                )

                if created:
                    created_count += 1
                    self.stdout.write(f"  Created: {obj} [Category: {obj.category or 'Not Set'}]") # Added category to output
                else:
                    # Check if any field actually changed before counting as updated
                    if any(getattr(obj, k, None) != v for k, v in defaults.items()): # Added check for None attribute
                         updated_count += 1
                         self.stdout.write(f"  Updated: {obj} [Category: {obj.category or 'Not Set'}]") # Added category to output
                    else:
                         skipped_count +=1
                         # self.stdout.write(f"  Skipped (no change): {obj}")

            except IntegrityError as e:
                self.stderr.write(self.style.ERROR(f"  Integrity Error processing {os_entry.get('name')} {os_entry.get('version', '')}: {e}"))
            except Exception as e:
                 self.stderr.write(self.style.ERROR(f"  Unexpected error processing {os_entry.get('name')} {os_entry.get('version', '')}: {e}"))


        self.stdout.write(self.style.SUCCESS(f'\nOS population complete.'))
        self.stdout.write(self.style.SUCCESS(f'  {created_count} created.'))
        self.stdout.write(self.style.WARNING(f'  {updated_count} updated.'))
        self.stdout.write(f'  {skipped_count} skipped (already up-to-date).')