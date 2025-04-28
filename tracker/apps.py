# tracker/apps.py
from django.apps import AppConfig
import sys
print("--- DEBUG: tracker/apps.py execution started (module imported) ---")
# --- NEW: Top-level print statement ---
print("--- tracker/apps.py file is being imported ---")
# --- END NEW ---

# --- Define a simple test handler function ---
def manual_test_handler(sender, instance, **kwargs):
    print(f"--- MANUAL TEST HANDLER triggered for {sender.__name__} ID: {instance.pk} ---")
# --- End test handler ---

class TrackerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'tracker'

    # Add a print statement inside __init__ as well
    def __init__(self, *args, **kwargs):
        print(f"--- TrackerConfig.__init__ called for app {self.name} ---")
        super().__init__(*args, **kwargs)


    def ready(self):
        print(f"--- TrackerConfig.ready() called for app {self.name} ---") # Added app name
        is_running_server = any(cmd in sys.argv for cmd in ['runserver', 'wsgi'])

        if is_running_server or 'pytest' in sys.modules:
            try:
                print("--- Attempting to import tracker.signals in apps.ready() ---")
                import tracker.signals  # Import signals module via decorator
                print("--- Tracker signals imported successfully from apps.py ---")

                # --- Explicitly connect the test handler ---
                print("--- Attempting to manually connect test_handler ---")
                from django.db.models.signals import post_save
                from .models import ScopedItem # Import model here
                post_save.connect(manual_test_handler, sender=ScopedItem, dispatch_uid="manual_scoped_item_save_test")
                print("--- Manual test_handler connected for ScopedItem post_save ---")
                # --- End explicit connection ---

            except ImportError as e:
                print(f"--- ERROR: Could not import tracker.signals in apps.py: {e} ---")
            except Exception as e:
                print(f"--- ERROR: Unexpected error during signal setup in apps.py: {e} ---")
        else:
             print("--- Skipping signal import/connection in apps.ready() (not running server/wsgi/pytest) ---")

