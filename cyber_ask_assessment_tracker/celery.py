import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyber_ask_assessment_tracker.settings')

app = Celery('cyber_ask_assessment_tracker')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


app.conf.beat_schedule = {
    'update-browser-daily': {
        'task': 'yourapp.tasks.update_browser_versions',
        'schedule': crontab(hour=0, minute=0),  # Daily at midnight
    },
}


@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Calls scrape_nessus_agent_urls every day at midnight.
    sender.add_periodic_task(
        crontab(hour=0, minute=0),  # Midnight
        # Ensure the task name matches what's in tracker/tasks.py
        app.signature('tracker.tasks.scrape_nessus_agent_urls_task'),
        name='scrape-nessus-agent-urls-daily'
    )

    # Validates agent URLs every hour
    sender.add_periodic_task(
        crontab(minute=0),  # Every hour at minute 0
        app.signature('tracker.tasks.validate_agent_urls_task'),
        name='validate-agent-urls-hourly'
    )

    # Updates browser versions daily at 1 AM
    sender.add_periodic_task(
        crontab(hour=1, minute=0),  # 1 AM
        app.signature('tracker.tasks.update_browser_versions_task'),
        name='update-browser-versions-daily'
    )

    # New task: Sync EndOfLife.date data daily at 2 AM (or your preferred time)
    sender.add_periodic_task(
        crontab(hour=0, minute=35),  # Run daily at 2:00 AM
        # Ensure this task name matches the @shared_task name in tracker/tasks.py
        app.signature('tracker.tasks.sync_endoflife_data_task'),
        name='sync-endoflife-date-data-daily'
    )