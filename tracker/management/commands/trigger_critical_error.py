import logging
from django.core.management.base import BaseCommand
from django.utils import timezone # For timestamping the test error message

class Command(BaseCommand):
    help = 'Triggers a test critical error to check logging handlers, including database logging.'

    def handle(self, *args, **options):
        # Get the logger for your 'tracker' app, as defined in your LOGGING settings
        # This ensures it uses the handlers configured for 'tracker', including 'db_critical_errors'
        logger = logging.getLogger('tracker')

        timestamp_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S %Z")

        self.stdout.write(self.style.WARNING(f"Attempting to log a CRITICAL message via 'tracker' logger at {timestamp_str}..."))

        # Log a simple critical message
        critical_message = f"This is a test CRITICAL message triggered by management command at {timestamp_str}."
        logger.critical(critical_message)
        self.stdout.write(self.style.SUCCESS(f"Successfully sent CRITICAL message: '{critical_message}'"))
        self.stdout.write(self.style.NOTICE("Check your CriticalErrorLog table and admin dashboard."))

        self.stdout.write(self.style.WARNING(f"\nAttempting to log a CRITICAL message with an exception via 'tracker' logger..."))
        try:
            # Simulate an error that might occur in your application
            x = 1 / 0
        except ZeroDivisionError as e:
            # Log critical with exception information.
            # The 'exc_info=True' will cause the traceback to be captured.
            # Our custom handler `DatabaseLogHandler` is designed to pick up `record.exc_info`.
            error_message_with_exception = f"Test CRITICAL error with exception (ZeroDivisionError) at {timestamp_str}."
            logger.critical(error_message_with_exception, exc_info=True)
            self.stdout.write(self.style.SUCCESS(f"Successfully sent CRITICAL message with exception: '{error_message_with_exception}'"))
            self.stdout.write(self.style.NOTICE("Check your CriticalErrorLog table for traceback information."))

        self.stdout.write(self.style.SUCCESS("\nTest critical error logging attempts complete."))
        self.stdout.write(self.style.NOTICE("Please verify the logs in the database and on the admin dashboard."))