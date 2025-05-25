from django.core.management.base import BaseCommand, CommandError
from tracker.tasks import update_browser_versions
from tracker.models import Browser
from datetime import date
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Triggers the browser update task and displays before/after differences.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--sync',
            action='store_true',
            help='Run the browser update task synchronously (in foreground).',
        )

    def handle(self, *args, **options):
        run_sync = options['sync']

        self.stdout.write(self.style.HTTP_INFO("Fetching current browser data..."))
        before_data = {b.name: {
            "version": b.version,
            "release_date": b.release_date,
            "engine": b.engine,
            "engine_version": b.engine_version
        } for b in Browser.objects.all()}

        self.stdout.write(self.style.HTTP_INFO("Running browser update task..."))

        try:
            if run_sync:
                self.stdout.write(self.style.WARNING("Running task synchronously..."))
                update_browser_versions()
                self.stdout.write(self.style.SUCCESS("Browser update finished (synchronous)."))
            else:
                update_browser_versions.delay()
                self.stdout.write(self.style.SUCCESS("Browser update task sent to Celery queue."))
                self.stdout.write(self.style.NOTICE("NOTE: Changes won't be shown unless run with --sync."))
                return
        except Exception as e:
            logger.error(f"Browser update failed: {e}", exc_info=True)
            raise CommandError(f"Task failed: {e}")

        self.stdout.write(self.style.HTTP_INFO("Comparing before/after browser data..."))
        after_data = {b.name: {
            "version": b.version,
            "release_date": b.release_date,
            "engine": b.engine,
            "engine_version": b.engine_version
        } for b in Browser.objects.all()}

        for name in sorted(after_data.keys()):
            before = before_data.get(name)
            after = after_data[name]

            if not before:
                self.stdout.write(self.style.SUCCESS(f"[+] New browser added: {name} v{after['version']}"))
                continue

            changes = []
            for field in ['version', 'release_date', 'engine', 'engine_version']:
                if str(before[field]) != str(after[field]):
                    changes.append(f"{field}: {before[field]} → {after[field]}")

            if changes:
                self.stdout.write(self.style.WARNING(f"[~] {name} updated:\n  " + "\n  ".join(changes)))
            else:
                self.stdout.write(self.style.SUCCESS(f"[=] {name} unchanged."))

        self.stdout.write(self.style.SUCCESS("Browser version update check complete."))
