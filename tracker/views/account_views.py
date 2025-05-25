# Standard library
import json
import os
import pprint
import random
import logging
from collections import defaultdict
from datetime import date, datetime, timezone, time
from urllib.parse import quote

# Third-party
import requests
import pytz
from requests.auth import HTTPBasicAuth
from tenable.errors import APIError, NotFoundError, ForbiddenError
from tracker.tenable_client import get_tenable_io_client
from tracker.tenable_client import get_tenable_io_client # Your TenableClient

from constance import config
from tracker.pdf_extractor import extract_ce_data_from_pdf
from django_celery_results.models import TaskResult # UNCOMMENTED
from celery import states as celery_states

# Django core
from django.conf import settings
from django.contrib import messages
from django.contrib import admin
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.core.serializers.json import DjangoJSONEncoder
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from django.db.models import Count, Min, ProtectedError, Value, CharField, Q, BooleanField
from django.db.models import Exists, OuterRef, Q
from django.db.models.functions import Coalesce, Concat
from django.forms import modelformset_factory
from django.http import FileResponse, Http404, HttpResponseForbidden, HttpResponseRedirect, JsonResponse, HttpRequest, \
    HttpResponse, HttpResponseBadRequest
from django.utils.html import escape

from django.utils.translation import gettext_lazy as _
from django.utils import timezone as django_timezone
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy, NoReverseMatch
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, UpdateView, TemplateView


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse_lazy
from django.utils import timezone
from django.contrib import messages
from django.http import Http404 # Make sure this is imported

from tracker.models import CriticalErrorLog, TenableScanLog

# Local app imports
from tracker.forms import *
from tracker.models import *

from tracker.tasks import *

from tracker.utils import *

logger = logging.getLogger(__name__)


from tracker.mixin import *


@login_required
def account_settings_view(request):
    """
    View for users to update their account settings.
    """
    # CHANGES BEGIN
    try:
        user_profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        # This case should ideally not happen for an existing, logged-in user
        # if UserProfile is created upon user registration (e.g., via a signal).
        # If it can happen, create a UserProfile instance.
        user_profile = UserProfile.objects.create(user=request.user)
        messages.info(request, _("Your user profile was just created. Please review your settings."))

    if request.method == 'POST':
        # Pass the current user instance and their profile instance to the form
        form = AccountSettingsForm(request.POST, instance=user_profile, user_instance=request.user)
        if form.is_valid():
            try:
                form.save() # The form's save method handles both User and UserProfile
                # Provide UTC timestamp for debug log
                from django.utils import timezone
                now_utc = timezone.now()
                print(f"[DEBUG] Account settings saved for {request.user.username} at {now_utc.isoformat()} UTC")
                messages.success(request, _("Your account settings have been updated successfully."))
                return redirect('account_settings') # Redirect to the same page to show changes
            except Exception as e:
                # Log the exception e for debugging
                print(f"[ERROR] Error saving account settings for {request.user.username}: {e}")
                messages.error(request, _("An unexpected error occurred while saving your settings. Please try again."))
        else:
            messages.error(request, _("Please correct the errors below."))
    else:
        # For a GET request, initialize the form with the user's current UserProfile instance
        # and also pass the User instance for populating User model fields.
        form = AccountSettingsForm(instance=user_profile, user_instance=request.user)

    context = {
        'form': form,
        'page_title': _("Account Settings") # For use in the template's title tag or header
    }
    # We'll create 'tracker/account_settings.html' in the next step
    return render(request, 'tracker/account_settings.html', context)
    # CHANGES END

@login_required
def dashboard(request):
    user = request.user
    if not hasattr(user, 'userprofile') or user.userprofile is None:
         messages.error(request, "Your user profile is not configured. Please contact support.")
         return redirect('logout')
    if is_admin(user):
        return redirect('tracker:admin_dashboard')
    elif is_assessor(user):
        return redirect('tracker:assessor_dashboard')
    elif is_client(user):
         if user.userprofile.client:
             return redirect('tracker:client_dashboard')
         else:
             messages.warning(request, "Your client account is not yet linked to a company. Please contact an administrator.")
             return redirect('logout')
    else:
        messages.error(request, "Your user role is not configured correctly. Please contact support.")
        return redirect('logout')

@login_required
@user_passes_test(is_admin, login_url=reverse_lazy('login')) # Redirect to login if test fails
def admin_dashboard(request):

    pending_approval_count = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()
    assessments_awaiting_scheduling_count = 0
    agree_date_step_definition_object = None  # Initialize

    try:
        # Try to get the 'Agree Date' WorkflowStepDefinition
        expected_step_name = 'Agree Date'
        logger.debug(f"Attempting to fetch WorkflowStepDefinition with name: '{expected_step_name}'")
        print(f"[DEBUG] Attempting to fetch WorkflowStepDefinition with name: '{expected_step_name}'")
        agree_date_step_definition_object = WorkflowStepDefinition.objects.get(
            name=expected_step_name)  # Store the object
        logger.debug(f"Successfully fetched WorkflowStepDefinition: {agree_date_step_definition_object}")
        print(f"[DEBUG] Successfully fetched WorkflowStepDefinition: {agree_date_step_definition_object}")

        # Subquery to check for a completed 'Agree Date' workflow step
        # This uses 'Complete' (title case) as identified from your logs.
        agree_date_step_complete_subquery = Exists(
            AssessmentWorkflowStep.objects.filter(
                assessment=OuterRef('pk'),
                step_definition=agree_date_step_definition_object,  # Use the fetched object
                status='Complete'
            )
        )

        # Annotate all assessments ONLY with the workflow step status
        all_assessments_annotated = Assessment.objects.annotate(
            has_completed_agree_date_step=agree_date_step_complete_subquery
        )

        logger.info("--- Assessments Status for Awaiting Scheduling Count (Simplified Logic) ---")
        print("[DEBUG] --- Assessments Status for Awaiting Scheduling Count (Simplified Logic) ---")
        for assessment_obj in all_assessments_annotated:
            log_message = (
                f"Assessment ID: {assessment_obj.id}, "
                f"Has Completed 'Agree Date' Step (Annotation): {assessment_obj.has_completed_agree_date_step}"
            )
            logger.info(log_message)
            print(f"[DEBUG] {log_message}")

            # Detailed check for AssessmentWorkflowStep if agree_date_step_definition_object is available
            if agree_date_step_definition_object:
                all_agree_date_workflow_steps = AssessmentWorkflowStep.objects.filter(
                    assessment=assessment_obj,
                    step_definition=agree_date_step_definition_object
                )
                if not all_agree_date_workflow_steps.exists():
                    print(f"[DEBUG]   Assessment ID {assessment_obj.id}: No 'Agree Date' WorkflowSteps found at all.")
                else:
                    found_complete_step = False
                    for step in all_agree_date_workflow_steps:
                        print(
                            f"[DEBUG]   Assessment ID {assessment_obj.id}: 'Agree Date' WorkflowStep ID {step.id}, Status '{step.status}'")
                        if step.status == 'Complete':  # Check against 'Complete'
                            found_complete_step = True
                    if not found_complete_step:
                        print(
                            f"[DEBUG]   Assessment ID {assessment_obj.id}: No 'Agree Date' WorkflowStep with status 'Complete' among existing steps.")
            else:
                print(
                    f"[DEBUG]   Assessment ID {assessment_obj.id}: 'Agree Date' WorkflowStepDefinition not available for detailed check.")
            print(f"[DEBUG]   -----------------------------------------------------")

        # Filter and count based ONLY on the workflow step being not complete
        assessments_awaiting_scheduling = all_assessments_annotated.filter(
            has_completed_agree_date_step=False
        )
        assessments_awaiting_scheduling_count = assessments_awaiting_scheduling.count()

        logger.info(
            f"Assessments IDs counted as awaiting scheduling (Simplified): {[a.id for a in assessments_awaiting_scheduling]}")
        print(
            f"[DEBUG] Assessments IDs counted as awaiting scheduling (Simplified): {[a.id for a in assessments_awaiting_scheduling]}")
        logger.info(
            f"Final count for assessments_awaiting_scheduling_count (Simplified): {assessments_awaiting_scheduling_count}")
        print(
            f"[DEBUG] Final count for assessments_awaiting_scheduling_count (Simplified): {assessments_awaiting_scheduling_count}")


    except WorkflowStepDefinition.DoesNotExist:
        error_message = (
            f"[CRITICAL-ERROR] WorkflowStepDefinition '{expected_step_name}' not found while calculating "
            "count for admin_dashboard. The 'Assessments Awaiting Scheduling' count will be 0. "
            "Please ensure this WorkflowStepDefinition exists with the exact name."
        )
        logger.error(error_message)
        print(f"[ERROR] {error_message}")

        available_steps = list(WorkflowStepDefinition.objects.values_list('name', flat=True))
        logger.info(f"Available WorkflowStepDefinition names in DB: {available_steps}")
        print(f"[DEBUG] Available WorkflowStepDefinition names in DB: {available_steps}")

        # If the crucial step definition is missing, the count is unreliable, so set to 0.
        assessments_awaiting_scheduling_count = 0
        logger.warning(
            f"Due to missing '{expected_step_name}' WorkflowStepDefinition, "
            f"assessments_awaiting_scheduling_count is set to 0."
        )
        print(
            f"[WARNING] Due to missing '{expected_step_name}' WorkflowStepDefinition, "
            f"assessments_awaiting_scheduling_count is set to 0."
        )

    # --- Tenable.io API Status Check ---
    tenable_api_status = "Not Configured"  # Default status
    tenable_access_key = getattr(config, 'TENABLE_ACCESS_KEY', None)
    tenable_secret_key = getattr(config, 'TENABLE_SECRET_KEY', None)
    tenable_url = getattr(config, 'TENABLE_URL', None)

    if tenable_access_key and tenable_secret_key and tenable_url:
        logger.debug("AdminDashboard: Tenable API settings found. Attempting to get client.")
        print("[DEBUG] AdminDashboard: Tenable API settings found. Attempting to get client.")
        tio_client = get_tenable_io_client()  # This function already has logging
        if tio_client:
            # To confirm connection, we can try a lightweight API call.
            # The get_tenable_io_client itself might attempt one implicitly or explicitly.
            # If get_tenable_io_client returns a client, we assume basic connectivity.
            # For a more definitive check, you could add a specific health check API call here.
            # For now, if client is not None, assume 'Connected'.
            try:
                # Example lightweight call to confirm the client is truly working
                tio_client.scanners.list()  # Fetch just one page of users
                tenable_api_status = "Connected"
                logger.info("AdminDashboard: Tenable.io API status: Connected (verified with users.list).")
                print("[DEBUG] AdminDashboard: Tenable.io API status: Connected (verified with users.list).")
            except Exception as e:  # Catch APIError or other exceptions from the test call
                tenable_api_status = "Connection Error"
                logger.error(
                    f"AdminDashboard: Tenable.io API client obtained, but test call (users.list) failed: {e}")
                print(
                    f"[ERROR] AdminDashboard: Tenable.io API client obtained, but test call (users.list) failed: {e}")
        else:
            tenable_api_status = "Connection Error"  # get_tenable_io_client failed
            logger.warning(
                "AdminDashboard: Tenable.io API settings present, but failed to get client (check tenable_client logs). Status: Connection Error.")
            print(
                "[WARNING] AdminDashboard: Tenable.io API settings present, but failed to get client. Status: Connection Error.")
    else:
        logger.warning(
            "AdminDashboard: Tenable API settings (Access Key, Secret Key, or URL) are missing. Status: Not Configured.")
        print(
            "[WARNING] AdminDashboard: Tenable API settings (Access Key, Secret Key, or URL) are missing. Status: Not Configured.")

    celery_pending_tasks_count = 0
    celery_failed_tasks_count = 0
    failed_celery_tasks_details = []  # NEW: To store details of failed tasks

    try:
        pending_states = [
            celery_states.PENDING, celery_states.RECEIVED,
            celery_states.STARTED, celery_states.RETRY
        ]
        celery_pending_tasks_count = TaskResult.objects.filter(status__in=pending_states).count()

        failed_tasks_qs = TaskResult.objects.filter(status=celery_states.FAILURE).order_by(
            '-date_done')  # Get most recent first
        celery_failed_tasks_count = failed_tasks_qs.count()

        # Fetch details for a limited number of recent failed tasks for the modal
        # Adjust 'limit' as needed
        limit_failed_tasks_display = 10
        for task in failed_tasks_qs[:limit_failed_tasks_display]:
            task_args_str = ""
            task_kwargs_str = ""
            try:
                # Task args and kwargs can be complex; attempt to pretty print JSON
                if task.task_args:
                    task_args_str = json.dumps(json.loads(task.task_args), indent=2)
                if task.task_kwargs:
                    task_kwargs_str = json.dumps(json.loads(task.task_kwargs), indent=2)
            except (json.JSONDecodeError, TypeError):
                task_args_str = str(task.task_args)  # Fallback to string representation
                task_kwargs_str = str(task.task_kwargs)

            failed_celery_tasks_details.append({
                'task_id': task.task_id,
                'task_name': task.task_name,
                'date_done': task.date_done,
                'traceback': task.traceback,
                'args': task_args_str,
                'kwargs': task_kwargs_str,
            })

        logger.info(
            f"AdminDashboard: Celery tasks - Pending: {celery_pending_tasks_count}, Failed: {celery_failed_tasks_count}")
        print(
            f"[DEBUG] AdminDashboard: Celery tasks - Pending: {celery_pending_tasks_count}, Failed: {celery_failed_tasks_count}")
        if failed_celery_tasks_details:
            print(f"[DEBUG] AdminDashboard: Fetched details for {len(failed_celery_tasks_details)} failed tasks.")

    except Exception as e:
        logger.error(f"AdminDashboard: Error fetching Celery task counts or details: {e}")
        print(f"[ERROR] AdminDashboard: Error fetching Celery task counts or details: {e}")

    latest_critical_error = CriticalErrorLog.objects.filter(is_acknowledged=False).order_by('-timestamp').first()
    if latest_critical_error and latest_critical_error.timestamp:
        # Ensure timestamp is UTC for debug printing
        # The model's default=timezone.now should handle UTC storage if settings.TIME_ZONE is UTC.
        # For explicit conversion to UTC for printing:
        error_timestamp_utc = latest_critical_error.timestamp.astimezone(pytz.utc)
        print(
            f"[DEBUG] admin_dashboard: Latest critical error timestamp (UTC): {error_timestamp_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    else:
        print(f"[DEBUG] admin_dashboard: No critical errors found or timestamp missing.")

    context = {
            'user_count': User.objects.count(),
            'client_count': Client.objects.count(),
            'assessment_count': Assessment.objects.count(),
            'assessments_pending_review': Assessment.objects.filter(status='Scoping_Review').count(),
            'pending_approval_count': pending_approval_count,
            'unlinked_ce_reports_count': UploadedReport.objects.filter(assessment__isnull=True).count(),
            'assessments_awaiting_scheduling_count': assessments_awaiting_scheduling_count,
            'tenable_api_status': tenable_api_status,
            'celery_pending_tasks_count': celery_pending_tasks_count,
            'celery_failed_tasks_count': celery_failed_tasks_count,
            'failed_celery_tasks_details': failed_celery_tasks_details,
            'latest_critical_error': latest_critical_error,
        }
    return render(request, 'tracker/admin/admin_dashboard.html', context)

@login_required
def dashboard_redirect_view(request: HttpRequest) -> HttpResponse:
    """
    Redirects authenticated users to their role-specific dashboard.
    """
    user = request.user
    print(f"[DEBUG] dashboard_redirect_view called for user: {user.username}")
    try:
        if hasattr(user, 'userprofile') and user.userprofile:
            role = user.userprofile.role
            print(f"[DEBUG] User role: {role}")
            if role == 'admin':
                return redirect(reverse('tracker:admin_dashboard'))
            elif role == 'assessor':
                return redirect(reverse('tracker:assessor_dashboard'))
            elif role == 'client':
                return redirect(reverse('tracker:client_dashboard'))
            else:
                # Fallback for authenticated users with an unknown role
                print(f"[DEBUG] Unknown role '{role}' for user {user.username}. Redirecting to client dashboard as a default.")
                messages.warning(request, ("Your user role is not properly configured. Please contact support."))
                return redirect(reverse('tracker:client_dashboard')) # Or a more generic page or error
        else:
            # Fallback for authenticated users without a UserProfile
            print(f"[DEBUG] User {user.username} has no userprofile. Redirecting to login.")
            messages.error(request, ("User profile not found. Please contact support."))
            return redirect(reverse('login')) # Or a page to create a profile
    except Exception as e:
        print(f"[DEBUG] Error in dashboard_redirect_view: {e}")
        messages.error(request, ("An error occurred while redirecting you to your dashboard."))
        return redirect(reverse('login')) # Fallback in case of any unexpected error

@login_required
@user_passes_test(is_assessor, login_url=reverse_lazy('login'))
def assessor_dashboard(request):
    # Existing queries
    assigned_assessments = Assessment.objects.filter(assessor=request.user).select_related(
        'client',
        'client__user_profile__user'  # To efficiently fetch the client's user object
    ).order_by('status', 'date_target_end')
    assessments_requiring_review = Assessment.objects.filter(status='Scoping_Review', assessor=request.user).count()
    pending_approval_count = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()

    # CHANGES BEGIN — 2025-05-22 22:30:00
    # Ensure a Conversation exists for each assessment and prepare for context
    assessment_conversations_map = {}
    for assessment_item in assigned_assessments:
        client_user = None
        if assessment_item.client and hasattr(assessment_item.client,
                                              'user_profile') and assessment_item.client.user_profile:
            client_user = assessment_item.client.user_profile.user

        # Only proceed if we have a valid client_user associated with the assessment's client company
        if client_user:
            conversation, created = Conversation.objects.get_or_create(
                assessment=assessment_item,
                defaults={
                    'client': client_user,
                    'assessor': request.user,  # The logged-in assessor
                }
            )
            # If the conversation already existed, check if participants need an update
            if not created:
                needs_save = False
                if conversation.client != client_user:
                    conversation.client = client_user
                    needs_save = True
                if conversation.assessor != request.user:  # Check against current assessor
                    conversation.assessor = request.user
                    needs_save = True

                if needs_save:
                    conversation.updated_at = timezone.now()
                    conversation.save(update_fields=['client', 'assessor', 'updated_at'])

            assessment_conversations_map[assessment_item.pk] = conversation
        else:
            logger.warning(
                f"Could not determine client user for assessment ID {assessment_item.pk} to create/update conversation.")
            assessment_conversations_map[assessment_item.pk] = None  # Ensure key exists even if no convo
    # CHANGES END — 2025-05-22 22:30:00

    context = {
        'assessments': assigned_assessments,
        'assessment_count': assigned_assessments.count(),
        'assessments_pending_review': assessments_requiring_review,
        'pending_approval_count': pending_approval_count,
        'assessment_conversations_map': assessment_conversations_map,  # Add to context
    }
    return render(request, 'tracker/assessor/assessor_dashboard.html', context)