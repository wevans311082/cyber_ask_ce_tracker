from django.core.management.base import BaseCommand, CommandError
from tracker.tasks import scrape_nessus_agent_urls, validate_agent_urls
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Manually triggers Celery tasks for scraping and validating Nessus Agent download URLs.'

    def add_arguments(self, parser):
        # Argument to run only the scraping task
        parser.add_argument(
            '--scrape',
            action='store_true',
            help='Run only the Nessus Agent URL scraping task.',
        )
        # Argument to run only the validation task
        parser.add_argument(
            '--validate',
            action='store_true',
            help='Run only the Nessus Agent URL validation task.',
        )
        # Argument to run tasks synchronously (useful for debugging, requires worker NOT running)
        # Note: Running synchronously might block if tasks are long.
        # Generally, triggering via .delay() is preferred for actual use.
        parser.add_argument(
            '--sync',
            action='store_true',
            help='Run tasks synchronously in the foreground (for debugging, bypasses Celery queue).',
        )


    def handle(self, *args, **options):
        run_scrape = options['scrape']
        run_validate = options['validate']
        run_sync = options['sync']

        # If no specific task is chosen, run both
        if not run_scrape and not run_validate:
            run_scrape = True
            run_validate = True
            self.stdout.write(self.style.NOTICE("No specific task specified, running both scrape and validate."))

        if run_scrape:
            self.stdout.write(self.style.HTTP_INFO("Triggering Nessus Agent URL scraping task..."))
            try:
                if run_sync:
                     self.stdout.write(self.style.WARNING("Running scrape task synchronously..."))
                     scrape_nessus_agent_urls() # Call directly
                     self.stdout.write(self.style.SUCCESS("Scrape task finished (synchronous)."))
                else:
                    scrape_nessus_agent_urls.delay() # Send to Celery worker
                    self.stdout.write(self.style.SUCCESS("Scrape task sent to Celery queue."))
            except Exception as e:
                logger.error(f"Failed to trigger scrape task: {e}", exc_info=True)
                raise CommandError(f"Failed to trigger scrape task: {e}")


        if run_validate:
            self.stdout.write(self.style.HTTP_INFO("Triggering Nessus Agent URL validation task..."))
            try:
                if run_sync:
                    self.stdout.write(self.style.WARNING("Running validate task synchronously..."))
                    validate_agent_urls() # Call directly
                    self.stdout.write(self.style.SUCCESS("Validate task finished (synchronous)."))
                else:
                    validate_agent_urls.delay() # Send to Celery worker
                    self.stdout.write(self.style.SUCCESS("Validation task sent to Celery queue."))
            except Exception as e:
                logger.error(f"Failed to trigger validate task: {e}", exc_info=True)
                raise CommandError(f"Failed to trigger validate task: {e}")

        self.stdout.write(self.style.SUCCESS("Management command finished."))