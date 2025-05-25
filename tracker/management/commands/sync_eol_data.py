# CHANGES BEGIN — 2025-05-25 23:50:00
import requests  # For making HTTP requests
from datetime import datetime, date, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction

# Import your EOL models
from tracker.models import *

# API Endpoints
API_BASE_URL = "https://endoflife.date/api"
ALL_PRODUCTS_URL = f"{API_BASE_URL}/all.json"
PRODUCT_DETAILS_URL_TEMPLATE = f"{API_BASE_URL}/{{product_slug}}.json"


# Helper function to parse date strings or booleans from API
def parse_api_date(api_date_value):
    if isinstance(api_date_value, str):
        try:
            return datetime.strptime(api_date_value, '%Y-%m-%d').date()
        except ValueError:
            return None  # Or log an error if format is unexpected
    # The API might return True/False for EOL status if no specific date.
    # For our DateField, we'll store None if it's a boolean or unparseable.
    # Specific boolean handling can be added if we introduce boolean EOL fields.
    return None


class Command(BaseCommand):
    help = 'Fetches product and cycle EOL data from endoflife.date API and updates the local database.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--products',
            nargs='*',
            type=str,
            help='Optional: Specific product slugs to fetch/update (e.g., python ubuntu). Fetches all if not specified.',
        )
        parser.add_argument(
            '--force-refresh-cycles',
            action='store_true',
            help='Force refresh of cycle data for selected products, even if recently fetched.',
        )
        parser.add_argument(
            '--refresh-cycle-older-than-days',
            type=int,
            default=30,  # Default to refresh if older than 30 days
            help='Refresh cycle data for products if last fetched more than X days ago. Used if --products is not set or --force-refresh-cycles is not set for specific products.',
        )

    @transaction.atomic  # Ensure all DB operations in handle are atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting EOL data synchronization..."))

        specific_products_to_fetch = options['products']
        force_refresh_cycles = options['force_refresh_cycles']
        refresh_cycle_older_than_days = options['refresh_cycle_older_than_days']

        # --- Step 1: Fetch and update the list of all products ---
        self.stdout.write("Fetching all product slugs from API...")
        try:
            response = requests.get(ALL_PRODUCTS_URL, timeout=30)  # 30-second timeout
            response.raise_for_status()  # Raise an exception for HTTP errors (4XX, 5XX)
            all_product_slugs_from_api = response.json()  # Expects a list of strings
            self.stdout.write(f"Successfully fetched {len(all_product_slugs_from_api)} product slugs.")
        except requests.exceptions.RequestException as e:
            raise CommandError(f"Error fetching all products list: {e}")
        except ValueError as e:  # Includes JSONDecodeError
            raise CommandError(f"Error parsing JSON from all products list: {e}")

        updated_product_count = 0
        new_product_count = 0

        for slug in all_product_slugs_from_api:
            product, created = EOLProduct.objects.update_or_create(
                slug=slug,
                defaults={'last_seen_in_api_all_list': timezone.now()}
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"  New product added: {product.name} (slug: {slug})"))
                new_product_count += 1
            else:
                # Product already existed, just updated its last_seen_in_api_all_list
                updated_product_count += 1

        self.stdout.write(f"Product list sync complete. New: {new_product_count}, Updated: {updated_product_count}.")

        # --- Step 2: Fetch cycle details for products ---
        if specific_products_to_fetch:
            products_to_process = EOLProduct.objects.filter(slug__in=specific_products_to_fetch)
            if not products_to_process.exists() and specific_products_to_fetch:
                self.stdout.write(
                    self.style.WARNING(f"Specified products not found: {', '.join(specific_products_to_fetch)}"))
                return
            self.stdout.write(
                f"Processing cycle data for specified products: {', '.join(p.slug for p in products_to_process)}")
        else:
            # If no specific products, fetch for all or those needing refresh
            # For now, let's fetch for all products. We can add filtering by 'last_cycle_data_fetched' later.
            products_to_process = EOLProduct.objects.all()
            self.stdout.write(f"Processing cycle data for all {products_to_process.count()} known products.")

        for product in products_to_process:
            # Determine if we should refresh cycles for this product
            should_refresh = False
            if force_refresh_cycles and (not specific_products_to_fetch or product.slug in specific_products_to_fetch):
                should_refresh = True
                self.stdout.write(f"  Force refreshing cycles for {product.slug}.")
            elif not product.last_cycle_data_fetched or \
                    (timezone.now() - product.last_cycle_data_fetched > timedelta(days=refresh_cycle_older_than_days)):
                should_refresh = True
                self.stdout.write(f"  Last cycle data for {product.slug} is old or missing. Refreshing.")

            if not should_refresh and specific_products_to_fetch and product.slug not in specific_products_to_fetch:
                # If we are processing specific products, but this one doesn't meet force/age criteria, skip only if it wasn't explicitly named.
                # This logic might need refinement based on desired behavior.
                # For now, if a product is named, it will be processed.
                pass

            if not should_refresh and not specific_products_to_fetch:
                self.stdout.write(f"  Cycle data for {product.slug} is recent. Skipping full refresh unless specified.")
                # Even if not doing a full refresh, consider fetching if there are NO cycles at all.
                if not product.cycles.exists():
                    self.stdout.write(f"    No cycles found for {product.slug}. Attempting initial fetch.")
                    should_refresh = True
                else:
                    continue  # Skip to next product

            if not should_refresh and specific_products_to_fetch and product.slug in specific_products_to_fetch and not force_refresh_cycles:
                self.stdout.write(
                    f" Cycle data for specified product {product.slug} is recent and not forced. Skipping.")
                continue

            self.stdout.write(f"  Fetching cycle details for product: {product.name} (slug: {product.slug})")
            product_api_url = PRODUCT_DETAILS_URL_TEMPLATE.format(product_slug=product.slug)
            try:
                response = requests.get(product_api_url, timeout=30)
                response.raise_for_status()
                cycles_data = response.json()  # Expects a list of cycle objects
            except requests.exceptions.RequestException as e:
                self.stderr.write(self.style.ERROR(f"  Error fetching cycle details for {product.slug}: {e}"))
                continue  # Skip to the next product
            except ValueError as e:  # Includes JSONDecodeError
                self.stderr.write(self.style.ERROR(f"  Error parsing JSON for {product.slug} cycles: {e}"))
                continue

            if not isinstance(cycles_data, list):
                self.stderr.write(self.style.ERROR(
                    f"  Unexpected data format for {product.slug} cycles. Expected a list, got {type(cycles_data)}. Skipping."))
                continue

            updated_cycles_count = 0
            new_cycles_count = 0

            for cycle_data in cycles_data:
                if not isinstance(cycle_data, dict) or 'cycle' not in cycle_data:
                    self.stderr.write(
                        self.style.WARNING(f"    Skipping invalid cycle data item for {product.slug}: {cycle_data}"))
                    continue

                cycle_slug = cycle_data.get('cycle')

                # Prepare data for EOLProductCycle model
                # The API uses 'eol', 'support', 'discontinued' which can be boolean or date string
                # The API uses 'lts' which can be boolean or absent
                cycle_defaults = {
                    'release_date': parse_api_date(cycle_data.get('releaseDate')),
                    'eol_date': parse_api_date(cycle_data.get('eol')),
                    'support_until_date': parse_api_date(cycle_data.get('support')),
                    'discontinued_date': parse_api_date(cycle_data.get('discontinued')),
                    'latest_version_in_cycle': cycle_data.get('latest', ''),
                    'link_to_source': cycle_data.get('link', ''),
                    'lts_status': cycle_data.get('lts') if isinstance(cycle_data.get('lts'), bool) else None,
                    'raw_cycle_data_json': cycle_data,  # Store the whole cycle object
                }

                try:
                    cycle_obj, created = EOLProductCycle.objects.update_or_create(
                        product=product,
                        cycle_slug=cycle_slug,
                        defaults=cycle_defaults
                    )
                    if created:
                        new_cycles_count += 1
                    else:
                        updated_cycles_count += 1
                except Exception as e_cycle_save:
                    self.stderr.write(
                        self.style.ERROR(f"    Error saving cycle {cycle_slug} for {product.slug}: {e_cycle_save}"))

            self.stdout.write(self.style.SUCCESS(
                f"    Processed cycles for {product.slug}. New: {new_cycles_count}, Updated: {updated_cycles_count}"))
            product.last_cycle_data_fetched = timezone.now()
            product.save(update_fields=['last_cycle_data_fetched'])

        self.stdout.write(self.style.SUCCESS("EOL data synchronization finished successfully."))

# CHANGES END — 2025-05-25 23:50:00