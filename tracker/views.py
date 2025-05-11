# Standard library
import json
import os
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
from .tenable_client import get_tenable_io_client
from constance import config
from .pdf_extractor import extract_ce_data_from_pdf
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
    HttpResponse

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

from .models import CriticalErrorLog


# Local app imports
from .forms import (
    AssessmentCloudServiceAssessorForm,
    AssessmentCloudServiceForm,
    AssessmentCloudServiceUpdateForm,
    AssessmentCreateForm,
    AssessmentStatusUpdateForm,
    ClientForm,
    CustomUserChangeForm,
    CustomUserCreationForm,
    EvidenceForm,
    ExternalIPForm,
    ExternalIPScanUpdateForm,
    NetworkForm,
    OperatingSystemForm,
    ScopedItemForm,
    ScopedItemUpdateForm,
    UploadReportForm,
    CloudServiceDefinitionForm,
    AssessmentDateOptionForm,
    AssessorAvailabilityForm,
    AssessorAvailability,
    AssessmentDateOption,
    AssessmentCloudService,
    OperatingSystem,
    AccountSettingsForm

)
from .models import (
    Assessment,
    AssessmentCloudService,
    AssessmentLog,
    AssessmentWorkflowStep,
    Client,
    CloudServiceDefinition,
    Evidence,
    ExternalIP,
    Network,
    OperatingSystem,
    ScopedItem,
    UploadedReport,
    UserProfile,
    NessusAgentURL,
    AssessorAvailability,
    AssessmentDateOption,
    WorkflowStepDefinition,
    CriticalErrorLog
)

from .tasks import (
    sync_client_with_tenable,
    apply_tenable_tag_to_assets,
    scrape_nessus_agent_urls,
    validate_agent_urls,
    create_or_update_tenable_client_tag,
    launch_tenable_scan_task
)


from .utils import (
check_and_fail_assessment_for_eol,
check_os_match,
is_admin_or_assessor,
is_client,
is_assessor,
is_admin,
calculate_sample_size,
user_can_edit_assessment_external_ips,
user_can_manage_assessment_external_ips,
user_can_manage_assessment_networks,
log_assessment_event,
user_can_manage_assessment_cloud_services
)


from .client_view import (
ClientUpdateView,
ClientListView,
ClientCreateView,
ClientDeleteView,
client_dashboard,
ClientAssessmentDetailView,
ClientAssessmentDetailView,
ClientAssessmentListView

)


from .assessment_view import (
AssessmentCloudServiceListView,
AssessmentUpdateStatusView,
AssessmentCloudServiceAddView,
AssessmentCloudServiceDeleteView,
AssessmentCloudServiceUpdateView,
AssessmentCreateView,
AssessmentDeleteView,
AdminAssessmentListView

)


from .cloud_services_view import (
CloudServiceDefinitionListView,
CloudServiceDefinitionUpdateView,
CloudServiceDefinitionCreateView,
CloudServiceDefinitionDeleteView,
CloudServiceDefinition

)


from .mixin import (
ClientRequiredMixin,
AdminRequiredMixin,
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin,

)

from .tenable_client import get_tenable_io_client



logger = logging.getLogger(__name__)

User = get_user_model()


class AssessmentAwaitingSchedulingListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """
    Displays a list of Assessment objects that are considered "awaiting scheduling".
    An assessment is awaiting scheduling if its 'Agree Date' workflow step is not 'Complete'.
    Requires user to be logged in and to be a staff member.
    """
    model = Assessment
    template_name = 'tracker/admin/assessment_awaiting_scheduling_list.html'
    context_object_name = 'assessments_awaiting_scheduling'
    paginate_by = 20

    # For LoginRequiredMixin
    login_url = settings.LOGIN_URL

    # For UserPassesTestMixin
    def test_func(self):
        return self.request.user.is_active and self.request.user.is_staff

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return redirect(self.get_login_url())
        return redirect('tracker:dashboard')

    def get_queryset(self):
        """
        Returns assessments awaiting scheduling based ONLY on the 'Agree Date'
        AssessmentWorkflowStep not being 'Complete'.
        """
        queryset = Assessment.objects.all()  # Start with all assessments

        try:
            expected_step_name = 'Agree Date'
            logger.debug(
                f"AssessmentAwaitingSchedulingListView: Attempting to fetch WorkflowStepDefinition with name: '{expected_step_name}'")
            print(
                f"[DEBUG] AssessmentAwaitingSchedulingListView: Attempting to fetch WorkflowStepDefinition with name: '{expected_step_name}'")

            agree_date_step_definition = WorkflowStepDefinition.objects.get(name=expected_step_name)

            logger.debug(
                f"AssessmentAwaitingSchedulingListView: Successfully fetched WorkflowStepDefinition: {agree_date_step_definition}")
            print(
                f"[DEBUG] AssessmentAwaitingSchedulingListView: Successfully fetched WorkflowStepDefinition: {agree_date_step_definition}")

            # Subquery to check for a completed 'Agree Date' workflow step
            # Uses 'Complete' (title case) as identified from your logs.
            agree_date_step_complete_subquery = Exists(
                AssessmentWorkflowStep.objects.filter(
                    assessment=OuterRef('pk'),
                    step_definition=agree_date_step_definition,
                    status='Complete'
                )
            )

            queryset = queryset.annotate(
                has_completed_agree_date_step=agree_date_step_complete_subquery
            ).filter(
                has_completed_agree_date_step=False  # Only include if the step is NOT complete
            )

        except WorkflowStepDefinition.DoesNotExist:
            logger.error(
                f"[CRITICAL-ERROR] WorkflowStepDefinition '{expected_step_name}' not found in AssessmentAwaitingSchedulingListView. "
                "This view cannot accurately determine assessments awaiting scheduling. "
                "Returning an empty list. Please ensure this WorkflowStepDefinition exists."
            )
            print(
                f"[ERROR] [CRITICAL-ERROR] WorkflowStepDefinition '{expected_step_name}' not found in AssessmentAwaitingSchedulingListView. "
                "Returning an empty list."
            )
            return Assessment.objects.none()  # Return an empty queryset

        # Add select_related and order_by after filtering
        queryset = queryset.select_related('client', 'assessor').order_by('client__name', 'date_start', 'id')

        logger.debug(f"AssessmentAwaitingSchedulingListView: Final queryset count: {queryset.count()}")
        print(f"[DEBUG] AssessmentAwaitingSchedulingListView: Final queryset count: {queryset.count()}")
        # You can also print the SQL query if needed for very detailed debugging:
        # print(f"[DEBUG] AssessmentAwaitingSchedulingListView: Query SQL: {str(queryset.query)}")
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Assessments Awaiting Scheduling"
        # from django.utils import timezone
        # print(f"[DEBUG] AssessmentAwaitingSchedulingListView context generated at UTC: {timezone.now()}")
        return context









class UnlinkedReportListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """
    Displays a list of UploadedReport objects that are not linked to any Assessment.
    Requires user to be logged in and to be a staff member.
    """
    model = UploadedReport
    template_name = 'tracker/admin/unlinked_report_list.html'  # New template to be created
    context_object_name = 'unlinked_reports_list'
    paginate_by = 20

    # For LoginRequiredMixin
    login_url = settings.LOGIN_URL

    # For UserPassesTestMixin
    def test_func(self):
        """
        Checks if the user is active and is a staff member.
        """
        return self.request.user.is_active and self.request.user.is_staff

    def handle_no_permission(self):
        """
        Called when test_func returns False.
        """
        if not self.request.user.is_authenticated:
            return redirect(self.get_login_url())
        return redirect('tracker:dashboard')  # Or an appropriate 'permission denied' page

    def get_queryset(self):
        """
        Returns the queryset of UploadedReport objects that are not linked
        to an assessment, ordered by upload date, with related uploader pre-fetched.
        """
        # print("[DEBUG] UnlinkedReportListView get_queryset called.")
        return UploadedReport.objects.filter(assessment__isnull=True).select_related(
            'uploaded_by'
        ).order_by('-uploaded_at')

    def get_context_data(self, **kwargs):
        """
        Adds 'title' to the context and file existence status for each report.
        """
        context = super().get_context_data(**kwargs)
        context['title'] = "Unlinked Uploaded Reports"

        reports_with_status = []
        report_objects = context.get(self.context_object_name)
        if report_objects is not None:
            for report in report_objects:
                file_exists_on_storage = False
                if report.report_file and report.report_file.name:
                    try:
                        file_exists_on_storage = report.report_file.storage.exists(report.report_file.name)
                    except Exception as e:
                        print(
                            f"[ERROR] Could not check existence for {report.report_file.name} in UnlinkedReportListView: {e}")
                        file_exists_on_storage = False

                reports_with_status.append({
                    'object': report,
                    'file_exists': file_exists_on_storage
                })

            context[self.context_object_name] = reports_with_status
        else:
            context[self.context_object_name] = []

        # from django.utils import timezone
        # print(f"[DEBUG] UnlinkedReportListView get_context_data. UTC: {timezone.now()}")
        return context
class UploadedReportListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    """
    Displays a list of all uploaded reports.
    Requires user to be logged in and to be a staff member.
    Includes checks for file existence.
    """
    model = UploadedReport
    template_name = 'tracker/admin/uploaded_report_list.html'
    context_object_name = 'reports_list'
    paginate_by = 20

    # For LoginRequiredMixin
    login_url = settings.LOGIN_URL

    # For UserPassesTestMixin
    def test_func(self):
        """
        Checks if the user is active and is a staff member.
        """
        return self.request.user.is_active and self.request.user.is_staff

    def handle_no_permission(self):
        """
        Called when test_func returns False.
        """
        if not self.request.user.is_authenticated:
            return redirect(self.get_login_url())
        # Consider redirecting to a 'permission_denied' page or a specific dashboard
        return redirect('tracker:dashboard')  # Ensure 'tracker:dashboard' is a valid URL name

    def get_queryset(self):
        """
        Returns the queryset of UploadedReport objects, ordered by upload date,
        with related objects pre-fetched using the correct field names.
        """
        # print("[DEBUG] UploadedReportListView get_queryset called.")
        return UploadedReport.objects.select_related(
            'uploaded_by',  # Corrected from 'uploader' based on FieldError
            'assessment',  # This was correct
            'assessment__client'  # Access client through the assessment
        ).all().order_by('-uploaded_at')

    def get_context_data(self, **kwargs):
        """
        Adds 'title' to the context and file existence status for each report.
        Uses the correct FileField name 'report_file'.
        """
        context = super().get_context_data(**kwargs)
        context['title'] = "All Uploaded Reports"

        reports_with_status = []
        report_objects = context.get(self.context_object_name)
        if report_objects is not None:
            for report in report_objects:
                file_exists_on_storage = False
                # Use 'report_file' instead of 'file'
                if report.report_file and report.report_file.name:
                    try:
                        # Use 'report_file' here as well
                        file_exists_on_storage = report.report_file.storage.exists(report.report_file.name)
                    except Exception as e:
                        # And here
                        print(f"[ERROR] Could not check existence for {report.report_file.name}: {e}")
                        file_exists_on_storage = False

                reports_with_status.append({
                    'object': report,
                    'file_exists': file_exists_on_storage
                })

            context[self.context_object_name] = reports_with_status
        else:
            context[self.context_object_name] = []

        # from django.utils import timezone
        # print(f"[DEBUG] UploadedReportListView get_context_data. UTC: {timezone.now()}")
        return context




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


@staff_member_required(login_url=reverse_lazy('login'))
def critical_error_detail_view(request, pk):
    print(f"--- [DEBUG] critical_error_detail_view entered. Request method: {request.method}, PK: {pk} ---")

    try:
        # Instead of get_object_or_404, we'll do it manually for more debug output
        error_log = CriticalErrorLog.objects.get(pk=pk)
        print(f"--- [DEBUG] Successfully fetched CriticalErrorLog with pk: {pk}. Object: {error_log} ---")
    except CriticalErrorLog.DoesNotExist:
        print(f"--- [DEBUG] CriticalErrorLog with pk: {pk} DOES NOT EXIST in the database. Raising Http404. ---")
        raise Http404(f"CriticalErrorLog matching query does not exist for pk: {pk}")
    except Exception as e:
        # Catch any other potential errors during fetch
        print(f"--- [DEBUG] An unexpected error occurred while fetching CriticalErrorLog with pk: {pk}. Error: {e} ---")
        raise  # Re-raise the exception to see the full traceback

    if request.method == 'POST':
        print(f"--- [DEBUG] POST request received for error_log pk: {pk} ---")
        if 'acknowledge_error' in request.POST and not error_log.is_acknowledged:
            print(f"--- [DEBUG] 'acknowledge_error' action detected. ---")
            error_log.is_acknowledged = True
            error_log.acknowledged_at = timezone.now()
            error_log.acknowledged_by = request.user
            error_log.save()
            messages.success(request, f"Error log (ID: {error_log.pk}) has been acknowledged.")
            print(f"--- [DEBUG] Error log pk: {pk} acknowledged. Redirecting to 'tracker:admin_dashboard'. ---")
            return redirect('tracker:admin_dashboard')  # Ensure 'tracker:admin_dashboard' is a valid URL name
        elif 'unacknowledge_error' in request.POST and error_log.is_acknowledged:
            print(f"--- [DEBUG] 'unacknowledge_error' action detected. ---")
            # Optional: Allow unacknowledging if needed
            error_log.is_acknowledged = False
            error_log.acknowledged_at = None
            error_log.acknowledged_by = None
            error_log.save()
            messages.info(request, f"Error log (ID: {error_log.pk}) has been marked as unacknowledged.")
            print(f"--- [DEBUG] Error log pk: {pk} unacknowledged. Redirecting to its detail page. ---")
            return redirect('tracker:critical_error_detail', pk=error_log.pk)
        else:
            print(
                f"--- [DEBUG] POST request received but no matching action ('acknowledge_error' or 'unacknowledge_error') found or conditions not met. ---")
            print(f"--- [DEBUG] request.POST content: {request.POST} ---")
            print(f"--- [DEBUG] error_log.is_acknowledged: {error_log.is_acknowledged} ---")

    # Note: You define 'context' here but don't use it in the render call.
    # context_data_for_template = {
    # 'error_log': error_log,
    # 'active_nav': 'admin_dashboard', # Or a more specific active_nav if you have one
    # }
    # For consistency, let's use what you had, but be aware.

    print(f"--- [DEBUG] Rendering template 'tracker/admin/critical_error_detail.html' for error_log pk: {pk} ---")
    return render(request, 'tracker/admin/critical_error_detail.html', {
        'error_log': error_log,
        # If you intend to use 'active_nav', it should be in this dictionary too:
        # 'active_nav': 'admin_dashboard',
    })







class UserListView(AdminRequiredMixin, ListView):
    model = User
    template_name = 'tracker/admin/user_list.html'
    context_object_name = 'users'
    queryset = User.objects.select_related('userprofile', 'userprofile__client').order_by('username') # Optimize query
class UserCreateView(AdminRequiredMixin, CreateView):
    model = User
    form_class = CustomUserCreationForm
    template_name = 'tracker/admin/user_form.html'
    success_url = reverse_lazy('tracker:user_list')

    def form_valid(self, form):
        user = form.save() # Form's save method handles User and UserProfile
        messages.success(self.request, f"User '{user.username}' created successfully.")
        return redirect(self.success_url)

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the errors below.")
        return super().form_invalid(form)
class UserUpdateView(AdminRequiredMixin, UpdateView):
    model = User
    form_class = CustomUserChangeForm
    template_name = 'tracker/admin/user_form.html'
    success_url = reverse_lazy('tracker:user_list')

    def get_queryset(self):
         # Ensure we can edit any user, including those without profiles (though forms expect profile)
         return User.objects.select_related('userprofile').all()

    # get_form_kwargs is automatically handled by UpdateView to pass instance

    def form_valid(self, form):
        user = form.save() # Form's save method handles User and UserProfile update
        messages.success(self.request, f"User '{user.username}' updated successfully.")
        return redirect(self.success_url)

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the errors below.")
        return super().form_invalid(form)

@login_required
@user_passes_test(is_admin_or_assessor) # Allow Admins or Assessors
def validate_client_companies_house(request, client_pk):
    """
    Step 1: Fetches data from Companies House based *only* on client's number
    and renders a confirmation page showing differences.
    """
    client = get_object_or_404(Client, pk=client_pk)
    api_key = getattr(settings, 'COMPANIES_HOUSE_API_KEY', None)
    redirect_url = reverse('tracker:client_list') # Fallback redirect

    if not api_key:
        messages.error(request, "Companies House API Key is not configured. Validation cannot proceed.")
        return redirect(redirect_url)

    search_term = client.organization_number
    if not search_term:
        messages.error(request, f"Client '{client.name}' has no Organization Number set. Cannot validate with Companies House.")
        return redirect(redirect_url)

    api_url = f"https://api.company-information.service.gov.uk/company/{search_term}"
    headers = {'Accept': 'application/json'}
    auth = HTTPBasicAuth(api_key, '')
    error_message = None
    fetched_data = None

    # --- Debug Prints (Keep for now) ---
    print("-" * 30)
    print(f"DEBUG: CH Validation Step 1 for Client ID: {client.pk}")
    print(f"DEBUG: Search Term (Org Number): '{search_term}'")
    print(f"DEBUG: API URL: {api_url}")
    masked_key = f"{api_key[:4]}...{api_key[-4:]}" if api_key and len(api_key) > 8 else "Key Invalid/Too Short"
    print(f"DEBUG: Auth: Basic Auth with User (API Key): '{masked_key}'")
    print("-" * 30)
    # --- END Debug Prints ---

    try:
        response = requests.get(api_url, headers=headers, auth=auth, timeout=10)
        print(f"DEBUG: CH API Response Status Code: {response.status_code}")
        response.raise_for_status() # Raise HTTPError for bad responses

        data = response.json()
        print(f"DEBUG: CH API Response Data Received: {json.dumps(data, indent=2)}")

        registered_office = data.get('registered_office_address', {})
        address_parts = [
            registered_office.get('address_line_1'),
            registered_office.get('address_line_2'),
            registered_office.get('locality'),
            registered_office.get('region'),
            registered_office.get('postal_code')
        ]
        full_address = ", ".join(part for part in address_parts if part)

        # --- Store fetched data ---
        fetched_data = {
            'company_number': data.get('company_number'),
            'company_name': data.get('company_name'),
            'address': full_address,
            'website_url': data.get('links', {}).get('website'), # Still fetch it
            'company_status': data.get('company_status'),
        }
        print(f"DEBUG: Prepared fetched_data for template: {fetched_data}")

    except requests.exceptions.Timeout:
        error_message = "Companies House API request timed out."
        print(f"ERROR: CH API Timeout")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            error_message = f"No company found on Companies House for number '{search_term}'."
        else:
            error_message = f"Companies House API returned an error: {e.response.status_code} - {e.response.reason}"
            print(f"ERROR: CH API HTTPError: {e.response.status_code}")
            print(f"ERROR: CH API Response Body: {e.response.text}")
    except requests.exceptions.RequestException as e:
        error_message = f"Could not connect to Companies House API: {e}"
        print(f"ERROR: CH API RequestException: {e}")
    except Exception as e:
        error_message = f"An unexpected error occurred during validation: {e}"
        print(f"ERROR: Unexpected CH Validation Error: {e}")

    if error_message:
        messages.error(request, error_message)
        client.companies_house_validated = False
        client.last_companies_house_validation = None
        client.validated_name = None
        client.validated_number = None
        client.save()
        return redirect(redirect_url)

    if fetched_data:
        context = {
            'client': client,
            'fetched_data': fetched_data,
            'page_title': f"Confirm Companies House Update for {client.name}"
        }
        return render(request, 'tracker/admin/client_ch_confirm_update.html', context)
    else:
        messages.error(request, "Could not retrieve data from Companies House.")
        return redirect(redirect_url)

@login_required
@user_passes_test(is_admin_or_assessor)
@require_http_methods(["POST"])
@csrf_protect
def confirm_update_from_companies_house(request, client_pk):
    """
    Step 2: Handles the POST request from the confirmation page.
    Updates the client record if confirmed by the user, preserving website if not provided by API.
    """
    client = get_object_or_404(Client, pk=client_pk)
    redirect_url = reverse('tracker:client_list')

    confirmed_number = request.POST.get('confirmed_number')
    confirmed_name = request.POST.get('confirmed_name')
    confirmed_address = request.POST.get('confirmed_address')
    # Get website from POST, might be empty string if CH didn't provide it
    confirmed_website = request.POST.get('confirmed_website')

    if not all([confirmed_number, confirmed_name, confirmed_address is not None]):
        messages.error(request, "Confirmation data was missing. Update aborted.")
        return redirect(redirect_url)

    try:
        # Perform the update
        client.organization_number = confirmed_number
        client.name = confirmed_name
        client.address = confirmed_address

        # --- MODIFIED WEBSITE LOGIC ---
        # Only update website_address if confirmed_website is not empty
        if confirmed_website:
            client.website_address = confirmed_website
            print(f"DEBUG: Updating website address for client {client.pk} to '{confirmed_website}'")
        else:
            # If confirmed_website is empty, DO NOTHING to client.website_address
            print(f"DEBUG: No website provided by CH for client {client.pk}. Existing website '{client.website_address}' preserved.")
        # --- END MODIFIED WEBSITE LOGIC ---

        client.companies_house_validated = True
        client.last_companies_house_validation = timezone.now()
        client.validated_name = confirmed_name
        client.validated_number = confirmed_number
        client.save()

        messages.success(request, f"Client '{client.name}' successfully updated and validated with Companies House data.")
        # Find first assessment to log against (or handle if none exist)
        first_assessment = client.assessments.first()
        if first_assessment:
             log_assessment_event(first_assessment, request.user, f"Client details updated and validated via Companies House lookup (Number: {confirmed_number}).")
        else:
             print(f"Warning: Could not log CH validation event for Client {client.pk} as they have no assessments.")


    except Exception as e:
        messages.error(request, f"An error occurred while updating the client: {e}")
        client.companies_house_validated = False
        client.last_companies_house_validation = None
        client.validated_name = None
        client.validated_number = None
        client.save()

    return redirect(redirect_url)

@login_required
@user_passes_test(is_assessor, login_url=reverse_lazy('login'))
def assessor_dashboard(request):
    assigned_assessments = Assessment.objects.filter(assessor=request.user).select_related('client').order_by('status', 'date_target_end')
    assessments_requiring_review = Assessment.objects.filter(status='Scoping_Review', assessor=request.user).count()
    # --- ADD THIS QUERY ---
    pending_approval_count = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()
    # --- END ADD ---
    context = {
        'assessments': assigned_assessments,
        'assessment_count': assigned_assessments.count(),
        'assessments_pending_review': assessments_requiring_review,
        'pending_approval_count': pending_approval_count, # <-- Add to context
    }
    return render(request, 'tracker/assessor/assessor_dashboard.html', context)
class AssessorAssessmentListView(AssessorRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/assessor/assessment_list.html'
    context_object_name = 'assessments'

    def get_queryset(self):
        return Assessment.objects.filter(assessor=self.request.user).select_related('client').order_by('status', 'date_target_end')
class AssessorAssessmentDetailView(AssessorOrAdminRequiredMixin, DetailView):
    model = Assessment
    template_name = 'tracker/assessor/assessment_detail.html'
    context_object_name = 'assessment'

    def get_queryset(self):
        """ Prefetches related data for efficiency """
        user = self.request.user
        base_qs = Assessment.objects.select_related(
            'client', 'assessor__userprofile'
        ).prefetch_related(
            'scoped_items__operating_system', # For sample display
            'scoped_items__network',          # For sample display
            'evidence_files__uploaded_by',    # For evidence list
            'logs__user',                     # For assessment log
            'external_ips',                   # For external IP summary (if added)
            'networks',                       # For network summary (if added)
            'assessment_cloud_services__cloud_service_definition', # For cloud summary (if added)
            'workflow_steps__step_definition', # *** Crucial for workflow ***
            'workflow_steps__completed_by',    # *** Crucial for workflow ***
            'date_options__proposed_by'        # For date scheduling
        )
        if is_admin(user):
            return base_qs # Admin sees all
        elif is_assessor(user):
            return base_qs.filter(assessor=user) # Assessor sees assigned
        else:
            return Assessment.objects.none() # Should not happen

    def get_context_data(self, **kwargs):
        """ Adds workflow steps and other necessary context """
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()
        user = self.request.user
        today = date.today()

        # --- Standard Context ---
        context['evidence_form'] = EvidenceForm()
        context['status_update_form'] = AssessmentStatusUpdateForm(instance=assessment)
        context['needs_scope_review'] = assessment.status == 'Scoping_Review'
        context['downloadable_evidence'] = assessment.evidence_files.all() # Uses prefetch
        context['logs'] = assessment.logs.all()[:20] # Uses prefetch and model ordering
        context['user_role'] = user.userprofile.role if hasattr(user, 'userprofile') else None

        # --- CE+ Sample Items & EOL Status ---
        # Fetch all items once using prefetched relations
        all_scope_items = list(assessment.scoped_items.all())
        stored_sample_items = [item for item in all_scope_items if item.is_in_ce_plus_sample]
        context['stored_sample_items'] = stored_sample_items
        context['sample_summary'] = { 'total_selected_items': len(stored_sample_items) }
        sample_items_with_status = []
        if assessment.assessment_type == 'CE+':
            for item in stored_sample_items:
                item.eol_status = 'ok'
                if item.operating_system:
                    if not item.operating_system.is_supported: item.eol_status = 'unsupported'
                    if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today: item.eol_status = 'eol'
                elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other', 'IP']: item.eol_status = 'unknown'
                sample_items_with_status.append(item)
        context['ce_plus_sample_items'] = sorted(sample_items_with_status, key=lambda x: (x.item_type, x.identifier or ''))

        # --- Workflow Context ---
        logger.debug(f"[Assessor View {assessment.pk}] Populating workflow context...")
        # Use prefetched data directly from assessment object
        workflow_steps_qs = assessment.workflow_steps.all()
        workflow_steps_list = list(workflow_steps_qs) # Evaluate queryset now

        current_step = None
        steps_with_permission = []
        if workflow_steps_list: # Check if the list is not empty
            for step in workflow_steps_list:
                # Calculate permission using the model method and current user
                step.can_update = step.is_update_allowed(user)
                steps_with_permission.append(step)
                # Determine the current step (first non-complete, non-skipped one)
                if step.status not in [AssessmentWorkflowStep.Status.COMPLETE, AssessmentWorkflowStep.Status.SKIPPED] and current_step is None:
                    current_step = step
            # Ensure steps are ordered correctly for display
            context['workflow_steps'] = sorted(steps_with_permission, key=lambda s: s.step_definition.step_order)
            context['current_step'] = current_step
            logger.debug(f"[Assessor View {assessment.pk}] Found {len(context['workflow_steps'])} workflow steps. Current step: {current_step.step_definition.name if current_step else 'None'}")
        else:
            # Explicitly set to empty list/None if no steps found
            context['workflow_steps'] = []
            context['current_step'] = None
            logger.warning(f"[Assessor View {assessment.pk}] No workflow steps found for this assessment!")
        # --- END Workflow Context ---


        # === Assessment Date Scheduling Context ===
        date_options = list(assessment.date_options.all()) # Use prefetch
        context['assessment_date_options'] = date_options

        confirmed_date_option = next((opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
        context['display_confirmed_assessment_date'] = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start
        has_explicitly_confirmed_option = confirmed_date_option is not None

        is_before_testing = assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
        context['assessment_allows_date_management'] = is_before_testing and not has_explicitly_confirmed_option

        context['propose_date_form'] = AssessmentDateOptionForm(assessment=assessment)

        unavailable_dates_json = "[]"
        target_assessor = assessment.assessor or (user if is_assessor(user) else None)
        if target_assessor:
            unavailable_dates = AssessorAvailability.objects.filter(assessor=target_assessor).values_list('unavailable_date', flat=True)
            unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
            unavailable_dates_json = json.dumps(unavailable_dates_str)
        context['assessor_unavailable_dates_json'] = unavailable_dates_json
        context['availability_shown_for'] = target_assessor

        context['ce_plus_window_start_date'] = assessment.date_ce_passed
        context['ce_plus_window_end_date'] = assessment.ce_plus_window_end_date
        context['confirmed_assessment_date'] = context['display_confirmed_assessment_date']
        context['scan_launch_status'] = assessment.can_launch_ce_plus_scan()


        # --- Timer Date (for countdown JS using Assessment.date_target_end) ---
        context['assessment_end_date_iso'] = None
        if assessment.date_target_end:
             try:
                 end_datetime_utc = django_timezone.make_aware(datetime.combine(assessment.date_target_end, time.max), pytz.utc)
                 context['assessment_end_date_iso'] = end_datetime_utc.isoformat()
             except ValueError:
                 logger.warning(f"Could not create datetime for countdown timer from date_target_end: {assessment.date_target_end}")

        return context
class EvidenceUploadView(AssessorOrAdminRequiredMixin, FormView): # Allow Admin too
    form_class = EvidenceForm
    # Typically part of detail view, needs context if rendered standalone
    template_name = 'tracker/assessor/assessment_detail.html'

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.assessment = self.get_assessment()

    def get_assessment(self):
         assessment_pk = self.kwargs.get('assessment_pk')
         qs = Assessment.objects.all()
         assessment = get_object_or_404(qs, pk=assessment_pk)

         # Check permission: Admin or assigned Assessor
         user = self.request.user
         if not (is_admin(user) or (is_assessor(user) and assessment.assessor == user)):
              raise PermissionDenied("You do not have permission to upload evidence for this assessment.")
         return assessment

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            evidence = form.save(commit=False)
            evidence.assessment = self.assessment
            evidence.uploaded_by = request.user
            evidence.save()
            log_assessment_event(self.assessment, request.user, f"Evidence uploaded: '{evidence.description}' ({evidence.filename}).")
            messages.success(request, f"Evidence '{evidence.description}' uploaded successfully.")
            return redirect(self.get_success_url())
        else:
            messages.error(request, "Failed to upload evidence. Please check the form.")
            # Redirect back to detail page, errors won't show unless handled in detail template
            return redirect(self.get_success_url())

    def get_success_url(self):
         # Redirect back to the detail view based on user role
         user = self.request.user
         if is_admin(user):
              # Admin might want to go back to the Admin detail view if one exists, or list
              return reverse('tracker:admin_assessment_list') # Adjust if admin detail view exists
         else: # Assessor
              return reverse('tracker:assessor_assessment_detail', kwargs={'pk': self.assessment.pk})

class ScopeItemManageView(ClientRequiredMixin, View):
    """
    Handles GET and POST requests for the client scope management page.
    GET: Displays categorized scope items and the add item form.
    POST: Handles adding new scope items.
    """
    template_name = 'tracker/client/scope_manage.html'
    # Pagination removed for now, handled per category if needed later

    def setup(self, request, *args, **kwargs):
        """Get assessment object early."""
        super().setup(request, *args, **kwargs)
        self.assessment = self.get_assessment_object(kwargs.get('assessment_pk'))

    def get_assessment_object(self, assessment_pk):
        """Helper to get assessment and check client ownership."""
        # Ensure user profile and client link exist (handled by ClientRequiredMixin)
        profile = self.request.user.userprofile
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if assessment.client != profile.client:
            raise PermissionDenied("You do not have permission to view this assessment's scope.")
        return assessment

    def get_context_data(self, form=None, **kwargs):
        """Prepares context: categorized items, OS data for JS, form, permissions."""
        # Fetch all items efficiently, including related OS and Network
        all_items = list(
            self.assessment.scoped_items.select_related('operating_system', 'network')
                                          .order_by('item_type', 'operating_system__name', 'identifier', 'id')
        )

        # --- Categorize Items ---
        categorized_items = {
            'user_devices': [], # Laptops, Desktops, Mobiles
            'servers': [],      # Servers
            'network_devices': [], # Firewalls, Routers, Switches, IPs
            'cloud_services': [], # SaaS, PaaS, IaaS
            'other_items': []    # Other
        }
        for item in all_items:
            if item.item_type in ['Laptop', 'Desktop', 'Mobile']:
                categorized_items['user_devices'].append(item)
            elif item.item_type == 'Server':
                categorized_items['servers'].append(item)
            elif item.item_type in ['Firewall', 'Router', 'Switch', 'IP']:
                categorized_items['network_devices'].append(item)
            elif item.item_type in ['SaaS', 'PaaS', 'IaaS']:
                categorized_items['cloud_services'].append(item)
            else: # 'Other' type
                categorized_items['other_items'].append(item)
        # --- End Categorization ---

        # --- Fetch OS Data for JS Filtering ---
        all_operating_systems = OperatingSystem.objects.filter(
             # is_supported=True # Optional: Only show supported OS in dropdown?
        ).order_by('name', 'version')
        os_data_for_js = []
        for os in all_operating_systems:
            os_data_for_js.append({
                'id': os.pk,
                'name': str(os),
                'category': os.category or ''
            })
        # --- End Fetch OS Data ---

        # Prepare form if not passed in (e.g., on GET request or POST failure)
        if form is None:
            form = ScopedItemForm(assessment=self.assessment) # Pass assessment for network filtering

        # Determine editing permissions based *only* on assessment status for clients
        can_edit = self.assessment.status == 'Scoping_Client'
        has_any_items = bool(all_items)

        # --- Prepare Context ---
        context = {
            'assessment': self.assessment,
            'form': form,
            'can_edit': can_edit,
            'can_submit': has_any_items and can_edit, # Can only submit if items exist and editing allowed
             # Pass categorized lists directly
            'user_devices_list': categorized_items['user_devices'],
            'servers_list': categorized_items['servers'],
            'network_devices_list': categorized_items['network_devices'],
            'cloud_services_list': categorized_items['cloud_services'],
            'other_items_list': categorized_items['other_items'],
             # Pass counts for display
            'counts': {
                'user_devices': len(categorized_items['user_devices']),
                'servers': len(categorized_items['servers']),
                'network_devices': len(categorized_items['network_devices']),
                'cloud_services': len(categorized_items['cloud_services']),
                'other_items': len(categorized_items['other_items']),
                'total': len(all_items)
            },
            # Pass OS data to template as JSON
            'os_data_json': json.dumps(os_data_for_js, cls=DjangoJSONEncoder)
        }
        context.update(kwargs)
        return context

    def get(self, request, *args, **kwargs):
        """Handles GET requests, displaying the scope management page."""
        context = self.get_context_data()
        # Display messages based on ability to edit and item existence
        if not context['can_edit'] and context['counts']['total'] == 0:
             messages.info(self.request, "No scope items have been added yet.")
        elif not context['can_edit']:
             messages.warning(self.request, f"Scope editing is locked (Assessment Status: {self.assessment.get_status_display()}).")
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        """Handles POST requests for adding new scope items."""
        # Double-check permission before processing POST
        if self.assessment.status != 'Scoping_Client':
            messages.error(request, f"Cannot add scope items now. Status is '{self.assessment.get_status_display()}'.")
            return redirect('tracker:client_scope_manage', assessment_pk=self.assessment.pk)

        form = ScopedItemForm(request.POST, assessment=self.assessment) # Pass assessment for network choices

        if form.is_valid():
            number_to_add = form.cleaned_data.get('number_to_add', 1)
            if number_to_add < 1: number_to_add = 1 # Ensure at least 1
            items_created_count = 0
            try:
                with transaction.atomic(): # Use a transaction for bulk creation
                    items_to_create = []
                    # Use validated & cleaned data from the form
                    base_data = {
                        'assessment': self.assessment,
                        'item_type': form.cleaned_data.get('item_type'),
                        'identifier': form.cleaned_data.get('identifier'),
                        'operating_system': form.cleaned_data.get('operating_system'),
                        'make_model': form.cleaned_data.get('make_model'),
                        'role_function': form.cleaned_data.get('role_function'),
                        'location': form.cleaned_data.get('location'),
                        'owner': form.cleaned_data.get('owner'),
                        'network': form.cleaned_data.get('network'),
                        'notes': form.cleaned_data.get('notes'),
                    }
                    for i in range(number_to_add):
                        items_to_create.append(ScopedItem(**base_data)) # Create instances

                    ScopedItem.objects.bulk_create(items_to_create) # Efficiently save all
                    items_created_count = len(items_to_create)

                # Logging details after successful transaction
                item_type_display = dict(ScopedItem.ITEM_TYPE_CHOICES).get(base_data.get('item_type'), 'N/A')
                log_event_desc = f"Added {items_created_count} scoped item(s): Type '{item_type_display}'."
                if base_data.get('operating_system'): log_event_desc += f" OS: {base_data.get('operating_system')}."
                # Add other details to log if needed

                log_assessment_event(self.assessment, request.user, log_event_desc)
                messages.success(request, f"{items_created_count} scoped item(s) added successfully.")

            except IntegrityError as e: # Catch potential unique constraint issues if identifier logic changes
                 messages.error(request, f"An error occurred: Could not add item(s). Possible duplicate identifier? Details: {e}")
                 context = self.get_context_data(form=form) # Re-render with original form data and errors
                 return render(request, self.template_name, context)
            except Exception as e: # Catch other potential errors
                messages.error(request, f"An unexpected error occurred while adding items: {e}")
                # Re-render with original form data but maybe without specific errors shown
                context = self.get_context_data(form=form)
                return render(request, self.template_name, context)

            # Redirect on successful creation
            return redirect('tracker:client_scope_manage', assessment_pk=self.assessment.pk)
        else:
            # Form is invalid, re-render the page with the form containing errors
            context = self.get_context_data(form=form) # Pass the invalid form back
            messages.error(request, "Failed to add scope item(s). Please check the form errors below.")
            return render(request, self.template_name, context)
@login_required
# @user_passes_test(is_client) # Handled by ClientRequiredMixin potentially
def scope_item_delete(request, assessment_pk, item_pk):
    # Using ClientRequiredMixin might be cleaner if adapted or used on a Class-based view
    if not is_client(request.user): return HttpResponseForbidden("Client permissions required.")
    profile = request.user.userprofile
    if not profile.client: return HttpResponseForbidden("Client account not linked.")

    assessment = get_object_or_404(Assessment, pk=assessment_pk)
    item = get_object_or_404(ScopedItem, pk=item_pk, assessment=assessment)

    # Permission checks
    if assessment.client != profile.client:
        return HttpResponseForbidden("Permission denied.")
    if assessment.status != 'Scoping_Client':
         messages.error(request, "Scope items can only be deleted when status is 'Scoping (Client Input)'.")
         return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)

    if request.method == 'POST':
        item_identifier = item.identifier
        item_type = item.get_item_type_display()
        item.delete()
        log_assessment_event(assessment, request.user, f"Scoped item deleted: '{item_identifier}' ({item_type}).")
        messages.success(request, f"Scoped item '{item_identifier}' deleted.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
    else:
        messages.warning(request, "Use the delete button on the scope management page.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
@login_required
# @user_passes_test(is_client) # Handled by ClientRequiredMixin potentially
def scope_submit(request, assessment_pk):
    if not is_client(request.user): return HttpResponseForbidden("Client permissions required.")
    profile = request.user.userprofile
    if not profile.client: return HttpResponseForbidden("Client account not linked.")

    assessment = get_object_or_404(Assessment, pk=assessment_pk)

    # Permission checks
    if assessment.client != profile.client:
        return HttpResponseForbidden("Permission denied.")
    if assessment.status != 'Scoping_Client':
         messages.warning(request, "Scope can only be submitted when status is 'Scoping (Client Input)'.")
         return redirect('tracker:client_assessment_detail', pk=assessment_pk)
    if not assessment.scoped_items.exists():
        messages.error(request, "Cannot submit scope with no items defined.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)

    if request.method == 'POST':
        assessment.status = 'Scoping_Review'
        assessment.save(update_fields=['status']) # Only update status field
        log_assessment_event(assessment, request.user, "Client submitted scope for review.")
        messages.success(request, "Scope submitted successfully for assessor review.")
        return redirect('tracker:client_assessment_detail', pk=assessment_pk)
    else:
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
@login_required
def download_evidence(request, evidence_pk):
    evidence = get_object_or_404(Evidence.objects.select_related('assessment__client'), pk=evidence_pk) # Optimise
    assessment = evidence.assessment
    user = request.user

    # Permission Check
    allowed = False
    if is_admin(user):
        allowed = True
    elif is_assessor(user) and assessment.assessor == user:
        allowed = True
    elif is_client(user) and user.userprofile.client == assessment.client:
        allowed = True

    if not allowed:
        # Log attempt maybe?
        # raise PermissionDenied("You do not have permission...") # More standard
        return HttpResponseForbidden("You do not have permission to download this file.")

    try:
        # Ensure file exists on storage
        if not evidence.file.storage.exists(evidence.file.name):
             raise Http404("File does not exist on storage.")

        response = FileResponse(evidence.file.open('rb'), as_attachment=True, filename=evidence.filename)
        # Optional: Add log entry for download
        log_assessment_event(assessment, user, f"Evidence downloaded: '{evidence.description}' ({evidence.filename}).")
        return response

    except FileNotFoundError: # May not be needed if storage.exists() works
         messages.error(request, "File not found. It might have been deleted.")
         raise Http404("File not found.")
    except Exception as e:
        # Log unexpected errors during file serving
        print(f"Error serving evidence file {evidence.pk}: {e}")
        messages.error(request, "An error occurred while trying to download the file.")
        # Redirect to a safe place
        if is_client(user): return redirect('tracker:client_assessment_detail', pk=assessment.pk)
        if is_assessor(user): return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)
        return redirect('tracker:admin_dashboard')
class OperatingSystemListView(AssessorOrAdminRequiredMixin, ListView):
    model = OperatingSystem
    template_name = 'tracker/os_management/os_list.html'
    context_object_name = 'operating_systems'
    paginate_by = 20 # Set the number of items per page (e.g., 20)
    ordering = ['vendor', 'name', 'version'] # Ensure consistent ordering for pagination
class OperatingSystemCreateView(AssessorOrAdminRequiredMixin, CreateView):
    model = OperatingSystem
    form_class = OperatingSystemForm
    template_name = 'tracker/os_management/os_form.html'
    success_url = reverse_lazy('tracker:os_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Add New Operating System'
        return context

    def form_valid(self, form):
        messages.success(self.request, f"Operating System '{form.instance}' created successfully.")
        return super().form_valid(form)
class OperatingSystemUpdateView(AssessorOrAdminRequiredMixin, UpdateView):
    model = OperatingSystem
    form_class = OperatingSystemForm
    template_name = 'tracker/os_management/os_form.html'
    success_url = reverse_lazy('tracker:os_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = f'Edit Operating System: {self.object}'
        return context

    def form_valid(self, form):
        messages.success(self.request, f"Operating System '{form.instance}' updated successfully.")
        return super().form_valid(form)
class OperatingSystemDeleteView(AssessorOrAdminRequiredMixin, DeleteView):
    model = OperatingSystem
    template_name = 'tracker/os_management/os_confirm_delete.html'
    success_url = reverse_lazy('tracker:os_list')
    context_object_name = 'os' # Use 'os' in the template

    def delete(self, request, *args, **kwargs):
        """
        Adds a success message. Checks for ProtectedError (though unlikely if
        on_delete=SET_NULL is used on ScopedItem.operating_system).
        """
        os_instance = self.get_object()
        os_name = str(os_instance) # Get name before deleting
        try:
            response = super().delete(request, *args, **kwargs)
            messages.success(request, f"Operating System '{os_name}' deleted successfully.")
            return response
        except ProtectedError:
            # This shouldn't happen if ScopedItem uses SET_NULL, but good practice
            messages.error(request, f"Cannot delete '{os_name}'. It might be referenced elsewhere unexpectedly.")
            return redirect('tracker:os_list')
@login_required
@user_passes_test(lambda u: is_assessor(u) or is_admin(u))
@transaction.atomic
def calculate_and_save_sample(request, assessment_pk):
    assessment = get_object_or_404(Assessment, pk=assessment_pk)

    # Permission check (Assessor assigned or Admin)
    if not (is_admin(request.user) or assessment.assessor == request.user):
         messages.error(request, "You do not have permission to modify the sample for this assessment.")
         return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)

    # Check if assessment type is CE+
    if assessment.assessment_type != 'CE+':
         messages.warning(request, "Sample calculation is only applicable for CE+ assessments.")
         return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)

    # --- Calculation Logic (moved from get_context_data) ---
    scoped_items = list(assessment.scoped_items.select_related('operating_system').all())
    items_to_select_ids = set() # Use a set for efficient ID storage

    # Group items
    grouped_items_dict = defaultdict(list)
    def get_group_key(item):
        os_name = item.operating_system.name if item.operating_system else 'Unknown OS'
        os_version = item.operating_system.version if item.operating_system else ''
        return (item.item_type, os_name, os_version)

    for item in scoped_items:
        key = get_group_key(item)
        grouped_items_dict[key].append(item)

    # Process each group and select items
    for key, items_in_group in grouped_items_dict.items():
        if not items_in_group: continue

        total_in_group = len(items_in_group)
        required_sample_size = calculate_sample_size(total_in_group)

        if required_sample_size >= total_in_group:
            selected_sample_items = items_in_group
        else:
            selected_sample_items = random.sample(items_in_group, required_sample_size)

        # Add the IDs of selected items to the set
        for selected_item in selected_sample_items:
            items_to_select_ids.add(selected_item.id)
    # --- End Calculation Logic ---

    # --- Database Update ---
    # 1. Clear existing sample flags for this assessment
    assessment.scoped_items.update(is_in_ce_plus_sample=False)

    # 2. Set the flag for the newly selected items
    if items_to_select_ids:
        ScopedItem.objects.filter(assessment=assessment, id__in=items_to_select_ids).update(is_in_ce_plus_sample=True)

    messages.success(request, f"Calculated CE+ sample updated successfully. {len(items_to_select_ids)} items selected.")
    # Log this event?
    log_assessment_event(assessment, request.user, f"Calculated CE+ sample regenerated ({len(items_to_select_ids)} items selected).")

    return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)
class NetworkListView(LoginRequiredMixin, ListView): # Remove AssessorOrAdminRequiredMixin
    model = Network
    template_name = 'tracker/network_management/network_list.html'
    context_object_name = 'networks'

    def setup(self, request, *args, **kwargs):
        """Get assessment and check permissions early."""
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # --- Use new permission check ---
        if not user_can_manage_assessment_networks(self.request.user, self.assessment):
             # Use PermissionDenied which typically results in a 403 Forbidden
             raise PermissionDenied("You do not have permission to view/manage networks for this assessment.")

    def get_queryset(self):
        """Return networks belonging to the specific assessment."""
        # setup already fetched self.assessment
        return Network.objects.filter(assessment=self.assessment).order_by('name')

    def get_context_data(self, **kwargs):
        """Add assessment and page title to context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Networks for Assessment #{self.assessment.id}"
        # Pass user role to template for dynamic links/buttons if needed
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        # Determine if editing should be allowed based on status (for template buttons)
        context['can_edit_networks'] = not self.assessment.status.startswith('Complete_')
        return context
class NetworkCreateView(LoginRequiredMixin, CreateView): # Remove AssessorOrAdminRequiredMixin
    model = Network
    form_class = NetworkForm
    template_name = 'tracker/network_management/network_form.html'

    def setup(self, request, *args, **kwargs):
        """Get assessment and check permissions early."""
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # --- Use new permission check (also check status allows adds) ---
        if not user_can_manage_assessment_networks(self.request.user, self.assessment):
             raise PermissionDenied("You do not have permission to add networks for this assessment.")
        if self.assessment.status.startswith('Complete_'):
             # Optional: Prevent adding if complete, even if user is admin/assessor
             messages.warning(request, "Cannot add networks to a completed assessment.")
             # Redirect or raise PermissionDenied - redirect might be better UX
             # For simplicity, raise PermissionDenied here. Adjust if needed.
             raise PermissionDenied("Cannot add networks to a completed assessment.")


    def form_valid(self, form):
        """Associate network with the current assessment before saving."""
        form.instance.assessment = self.assessment
        network_name = form.cleaned_data.get('name')
        response = super().form_valid(form)
        messages.success(self.request, f"Network '{network_name}' created successfully.")
        log_assessment_event(self.assessment, self.request.user, f"Network created: '{network_name}'.")
        return response

    def get_context_data(self, **kwargs):
        """Add assessment and page title to context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Add Network to Assessment #{self.assessment.id}"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        return context

    def get_success_url(self):
        """Redirect back to the network list URL used by the current user."""
        # Check user role to determine correct redirect
        if is_client(self.request.user):
             return reverse('tracker:client_network_list', kwargs={'assessment_pk': self.assessment.pk})
        else: # Admin or Assessor
             return reverse('tracker:network_list', kwargs={'assessment_pk': self.assessment.pk})
class NetworkUpdateView(LoginRequiredMixin, UpdateView): # Remove AssessorOrAdminRequiredMixin
    model = Network
    form_class = NetworkForm
    template_name = 'tracker/network_management/network_form.html'
    context_object_name = 'network'

    def setup(self, request, *args, **kwargs):
        """Check permissions for the specific assessment and status."""
        super().setup(request, *args, **kwargs)
        # Get object to access assessment
        network = self.get_object()
        self.assessment = network.assessment
         # --- Use new permission check (also check status allows edits) ---
        if not user_can_manage_assessment_networks(self.request.user, self.assessment):
             raise PermissionDenied("You do not have permission to edit networks for this assessment.")
        if self.assessment.status.startswith('Complete_'):
             raise PermissionDenied("Cannot edit networks for a completed assessment.")

    def get_queryset(self):
        """Ensure we only edit networks for the specified assessment."""
        # This queryset is mainly used by get_object, permission checked in setup
        assessment_pk = self.kwargs['assessment_pk']
        return Network.objects.filter(assessment_id=assessment_pk)

    def form_valid(self, form):
        network_name = form.cleaned_data.get('name')
        response = super().form_valid(form)
        messages.success(self.request, f"Network '{network_name}' updated successfully.")
        log_assessment_event(self.assessment, self.request.user, f"Network updated: '{network_name}'.")
        return response

    def get_context_data(self, **kwargs):
        """Add assessment and page title to context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Edit Network '{self.object.name}' (Assessment #{self.assessment.id})"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        return context

    def get_success_url(self):
        """Redirect back to the network list URL used by the current user."""
        if is_client(self.request.user):
             return reverse('tracker:client_network_list', kwargs={'assessment_pk': self.assessment.pk})
        else: # Admin or Assessor
             return reverse('tracker:network_list', kwargs={'assessment_pk': self.assessment.pk})
class NetworkDeleteView(LoginRequiredMixin, DeleteView): # Remove AssessorOrAdminRequiredMixin
    model = Network
    template_name = 'tracker/network_management/network_confirm_delete.html'
    context_object_name = 'network'

    def setup(self, request, *args, **kwargs):
        """Check permissions for the specific assessment and status."""
        super().setup(request, *args, **kwargs)
        network = self.get_object()
        self.assessment = network.assessment
        # --- Use new permission check (also check status allows deletes) ---
        if not user_can_manage_assessment_networks(self.request.user, self.assessment):
             raise PermissionDenied("You do not have permission to delete networks for this assessment.")
        if self.assessment.status.startswith('Complete_'):
             raise PermissionDenied("Cannot delete networks for a completed assessment.")

    def get_queryset(self):
        """Ensure we only delete networks for the specified assessment."""
        assessment_pk = self.kwargs['assessment_pk']
        return Network.objects.filter(assessment_id=assessment_pk)

    def form_valid(self, form):
        """Add success message and log event."""
        network_name = self.object.name
        response = super().form_valid(form)
        messages.success(self.request, f"Network '{network_name}' deleted successfully.")
        log_assessment_event(self.assessment, self.request.user, f"Network deleted: '{network_name}'.")
        return response

    def get_context_data(self, **kwargs):
        """Add assessment and page title to context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Delete Network '{self.object.name}' (Assessment #{self.assessment.id})"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        return context

    def get_success_url(self):
        """Redirect back to the network list URL used by the current user."""
        if is_client(self.request.user):
             return reverse('tracker:client_network_list', kwargs={'assessment_pk': self.assessment.pk})
        else: # Admin or Assessor
             return reverse('tracker:network_list', kwargs={'assessment_pk': self.assessment.pk})
class ProposeAssessmentDateView(LoginRequiredMixin, CreateView):
    model = AssessmentDateOption
    form_class = AssessmentDateOptionForm
    # No separate template needed, POST from detail view

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # --- Permission check: Basic role check ---
        profile = getattr(request.user, 'userprofile', None)
        if not profile or profile.role not in ['Admin', 'Assessor', 'Client']:
             raise PermissionDenied("Invalid user role for proposing dates.")
        if profile.role == 'Client' and self.assessment.client != profile.client:
             raise PermissionDenied("You cannot propose dates for this assessment.")
        # Admins/Assessors (even unassigned?) can propose - adjust if needed
        if profile.role == 'Assessor' and self.assessment.assessor and self.assessment.assessor != request.user:
            # Optionally restrict assessors to only propose for their assigned assessments
            # raise PermissionDenied("You can only propose dates for your assigned assessments.")
            pass # Allow any assessor to propose for now


    def get_form_kwargs(self):
        """ Pass the assessment instance to the form for validation """
        kwargs = super().get_form_kwargs()
        kwargs['assessment'] = self.assessment
        return kwargs

    def form_valid(self, form):
        """ Process a valid form submission """
        logger.debug(f"ProposeAssessmentDateView: form_valid entered for assessment {self.assessment.pk} by user {self.request.user.username}")
        form.instance.assessment = self.assessment
        form.instance.proposed_by = self.request.user
        try:
            # Save the object first to get an ID
            self.object = form.save()
            logger.info(f"AssessmentDateOption {self.object.pk} created for assessment {self.assessment.pk} with date {self.object.proposed_date}")

            log_assessment_event(
                self.assessment,
                self.request.user,
                f"Proposed assessment date: {self.object.proposed_date.strftime('%Y-%m-%d')}"
                 + (f". Notes: {form.cleaned_data.get('notes')}" if form.cleaned_data.get('notes') else ".")
            )
            messages.success(self.request, f"Date {self.object.proposed_date.strftime('%Y-%m-%d')} proposed successfully.")
        except IntegrityError:
            # Handle case where date already exists (unique_together constraint)
            logger.warning(f"IntegrityError: Date {form.cleaned_data.get('proposed_date')} already proposed for assessment {self.assessment.pk}.")
            messages.error(self.request, f"The date {form.cleaned_data.get('proposed_date').strftime('%Y-%m-%d')} has already been proposed for this assessment.")
            # Redirect back without saving, error message shown
            return HttpResponseRedirect(self.get_success_url())
        except Exception as e:
            logger.error(f"Error saving proposed date for assessment {self.assessment.pk}: {e}", exc_info=True)
            messages.error(self.request, f"An unexpected error occurred: {e}")
            return HttpResponseRedirect(self.get_success_url())

        logger.debug(f"ProposeAssessmentDateView: form_valid completed successfully.")
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        """ Handle invalid form submission """
        logger.warning(f"ProposeAssessmentDateView: form_invalid for assessment {self.assessment.pk}. Errors: {form.errors.as_json()}")
        # Add form errors to messages to display on the detail page
        for field, errors in form.errors.items():
            for error in errors:
                # Prepend field name for clarity, handle non-field errors
                field_name_display = form.fields[field].label if field != '__all__' and field in form.fields else 'Proposal Error'
                messages.error(self.request, f"{field_name_display}: {error}")
        # Redirect back to the detail page where messages will be shown
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        """ Redirect back to the appropriate assessment detail view """
        # Determine redirect based on user role
        profile = getattr(self.request.user, 'userprofile', None) # Use getattr for safety
        if profile and profile.role == 'Client':
            return reverse('tracker:client_assessment_detail', kwargs={'pk': self.assessment.pk})
        else: # Assessor or Admin (or other roles if permissions allow)
            return reverse('tracker:assessor_assessment_detail', kwargs={'pk': self.assessment.pk})
class UpdateAssessmentDateStatusView(LoginRequiredMixin, View):
    """ Handles POST requests to update the status of an AssessmentDateOption """

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        # Get assessment and option early for permission checks
        # Prefetch related fields needed for checks/logic
        self.assessment = get_object_or_404(
            Assessment.objects.select_related('assessor', 'client'),
            pk=self.kwargs['assessment_pk']
        )
        self.option = get_object_or_404(
            AssessmentDateOption.objects.select_related('proposed_by'), # Select proposer if needed
            pk=self.kwargs['option_pk'],
            assessment=self.assessment
        )

    def post(self, request, *args, **kwargs):
        new_status = request.POST.get('new_status')
        user = request.user
        profile = getattr(user, 'userprofile', None)

        # Validate new_status against choices
        valid_statuses = [choice[0] for choice in AssessmentDateOption.Status.choices]
        if new_status not in valid_statuses:
            messages.error(request, "Invalid status provided.")
            logger.warning(f"Invalid status '{new_status}' attempt for option {self.option.pk} by user {user.username}")
            return self.redirect_back()

        # --- Permission Check & Action Logic ---
        original_status = self.option.status
        can_perform_action = False
        log_message = "" # Initialize log message

        # Check if assessment already has a confirmed date (blocks most actions)
        is_assessment_confirmed = AssessmentDateOption.objects.filter(
            assessment=self.assessment, status=AssessmentDateOption.Status.CONFIRMED
        ).exclude(pk=self.option.pk).exists() # Exclude self in case this is the confirmation action

        # Check assessment status allows date management generally
        is_before_testing = self.assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']

        # Determine if the specific user can perform the specific status change
        if is_client(user):
            # Client can only mark as 'ClientPreferred'
            if is_before_testing and not is_assessment_confirmed and \
               new_status == AssessmentDateOption.Status.CLIENT_PREFERRED and \
               original_status == AssessmentDateOption.Status.SUGGESTED:
                can_perform_action = True
            else:
                # Log reason for denial more specifically if possible
                reason = "assessment already confirmed" if is_assessment_confirmed else \
                         "assessment status does not allow changes" if not is_before_testing else \
                         "invalid status transition"
                logger.warning(f"Client {user.username} permission denied to set status {new_status} on option {self.option.pk}: {reason}")

        elif is_assessor(user) or is_admin(user):
            # Assessor/Admin can Confirm or Reject
            if is_before_testing and not is_assessment_confirmed:
                # --- Confirmation Logic ---
                if new_status == AssessmentDateOption.Status.CONFIRMED and \
                   original_status != AssessmentDateOption.Status.CONFIRMED and \
                   original_status != AssessmentDateOption.Status.REJECTED:

                    # Assessor Availability Check (only if assessor is assigned)
                    if self.assessment.assessor and AssessorAvailability.objects.filter(assessor=self.assessment.assessor, unavailable_date=self.option.proposed_date).exists():
                        messages.error(request, f"Cannot confirm: Assessor ({self.assessment.assessor.username}) is unavailable on {self.option.proposed_date.strftime('%Y-%m-%d')}.")
                        return self.redirect_back()

                    # CE+ Window Check
                    if self.assessment.assessment_type == 'CE+' and self.assessment.date_ce_passed:
                        window_end_date = self.assessment.ce_plus_window_end_date
                        if not (window_end_date and self.assessment.date_ce_passed <= self.option.proposed_date <= window_end_date): # Check window_end_date exists
                            end_date_str = window_end_date.strftime('%Y-%m-%d') if window_end_date else "N/A"
                            messages.error(request, f"Cannot confirm: Date is outside the CE+ window ({self.assessment.date_ce_passed.strftime('%Y-%m-%d')} to {end_date_str}).")
                            return self.redirect_back()
                    elif self.assessment.assessment_type == 'CE+' and not self.assessment.date_ce_passed:
                          messages.error(request, "Cannot confirm: CE+ assessment requires the CE Self-Assessment Pass Date to be set first.")
                          return self.redirect_back()

                    can_perform_action = True # If all checks pass

                # --- Rejection Logic ---
                elif new_status == AssessmentDateOption.Status.REJECTED and \
                     original_status != AssessmentDateOption.Status.CONFIRMED and \
                     original_status != AssessmentDateOption.Status.REJECTED:
                    can_perform_action = True
            else:
                 # Log reason for denial
                 reason = "assessment already confirmed" if is_assessment_confirmed else \
                          "assessment status does not allow changes" if not is_before_testing else \
                          "invalid status transition"
                 logger.warning(f"Assessor/Admin {user.username} permission denied to set status {new_status} on option {self.option.pk}: {reason}")


        if not can_perform_action:
            messages.error(request, f"Action not allowed: Cannot change status from '{original_status}' to '{new_status}' at this time or with your role.")
            return self.redirect_back()

        # --- Perform Update within a transaction ---
        try:
            with transaction.atomic():
                self.option.status = new_status
                log_message_base = f"Assessment date option ({self.option.proposed_date.strftime('%Y-%m-%d')}) status changed to {self.option.get_status_display()}"
                log_details = []

                # If Client Preferred, reset any other preferred dates for this assessment
                if new_status == AssessmentDateOption.Status.CLIENT_PREFERRED:
                    updated_count = AssessmentDateOption.objects.filter(
                        assessment=self.assessment, status=AssessmentDateOption.Status.CLIENT_PREFERRED
                    ).exclude(pk=self.option.pk).update(status=AssessmentDateOption.Status.SUGGESTED)
                    if updated_count > 0:
                        log_details.append(f"{updated_count} other preference(s) reset to 'Suggested'.")

                # If Assessor Confirmed:
                if new_status == AssessmentDateOption.Status.CONFIRMED:
                    # 1. Update the Assessment's TARGET date
                    self.assessment.date_target_end = self.option.proposed_date
                    # 2. Update start date if not set or if it should match target
                    if not self.assessment.date_start:
                        self.assessment.date_start = self.option.proposed_date
                    # Ensure start date is not after target end date
                    if self.assessment.date_start and self.assessment.date_target_end < self.assessment.date_start:
                        self.assessment.date_start = self.assessment.date_target_end
                    self.assessment.save(update_fields=['date_target_end', 'date_start'])
                    log_details.append("Assessment Target End/Start Date set.")

                    # 3. Reject all other Suggested/Preferred options
                    rejected_count = AssessmentDateOption.objects.filter(
                        assessment=self.assessment,
                        status__in=[AssessmentDateOption.Status.SUGGESTED, AssessmentDateOption.Status.CLIENT_PREFERRED]
                    ).exclude(pk=self.option.pk).update(status=AssessmentDateOption.Status.REJECTED)
                    if rejected_count > 0:
                        log_details.append(f"{rejected_count} other option(s) rejected.")

                    # 4. Attempt to close the workflow step
                    step_name_to_complete = 'Schedule Assessment Date' # ADJUST THIS NAME IF NEEDED
                    try:
                        schedule_step_def = WorkflowStepDefinition.objects.get(name=step_name_to_complete)
                        # Use update_or_create to handle potential race conditions or missing steps gracefully
                        workflow_step, created = AssessmentWorkflowStep.objects.update_or_create(
                            assessment=self.assessment,
                            step_definition=schedule_step_def,
                            defaults={
                                'status': AssessmentWorkflowStep.Status.COMPLETE,
                                'completed_at': django_timezone.now(),
                                'completed_by': user
                            }
                        )
                        if created:
                            log_details.append(f"Workflow step '{schedule_step_def.name}' created and marked complete.")
                            logger.info(f"Workflow step '{schedule_step_def.name}' created and completed for assessment {self.assessment.pk}")
                        elif workflow_step.status != AssessmentWorkflowStep.Status.COMPLETE:
                            # If it existed but wasn't complete, log the update
                            log_details.append(f"Workflow step '{schedule_step_def.name}' marked complete.")
                            logger.info(f"Workflow step '{schedule_step_def.name}' updated to complete for assessment {self.assessment.pk}")
                        else: # Step already complete
                             logger.info(f"Workflow step '{schedule_step_def.name}' was already complete for assessment {self.assessment.pk}")
                    except WorkflowStepDefinition.DoesNotExist:
                         logger.error(f"WorkflowStepDefinition '{step_name_to_complete}' does not exist.")
                         log_details.append(f"Error: Workflow definition '{step_name_to_complete}' not found.")
                    except Exception as wf_err:
                         logger.error(f"Error updating workflow step '{step_name_to_complete}' for assessment {self.assessment.pk}: {wf_err}", exc_info=True)
                         log_details.append(f"Error updating workflow step '{step_name_to_complete}'.")
                    # --- End Workflow Step Update ---

                # Save the option itself (status changed)
                self.option.save()

                # Log the combined event
                full_log_message = log_message_base + (" " + " ".join(log_details) if log_details else ".")
                log_assessment_event(self.assessment, user, full_log_message)
                messages.success(request, f"Date {self.option.proposed_date.strftime('%Y-%m-%d')} status updated to {self.option.get_status_display()}.")

        except Exception as e:
            logger.error(f"Error updating date option status for option {self.option.pk}: {e}", exc_info=True)
            messages.error(request, f"An unexpected error occurred: {e}")

        return self.redirect_back()

    def redirect_back(self):
        """ Redirects back to the appropriate detail view """
        profile = getattr(self.request.user, 'userprofile', None)
        if profile and profile.role == 'Client':
            return redirect('tracker:client_assessment_detail', pk=self.assessment.pk)
        else: # Assessor or Admin
            return redirect('tracker:assessor_assessment_detail', pk=self.assessment.pk)
class DeleteAssessmentDateOptionView(LoginRequiredMixin, View):
    """ Handles POST requests to delete an AssessmentDateOption """

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        # Fetch related assessment for permission checks
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # Fetch the specific option to be deleted
        self.option = get_object_or_404(
            AssessmentDateOption.objects.select_related('proposed_by'), # Include proposer for checks
            pk=self.kwargs['option_pk'],
            assessment=self.assessment
        )

    def post(self, request, *args, **kwargs):
        user = request.user
        profile = getattr(user, 'userprofile', None)

        # --- Permission Check for Deletion ---
        can_delete = False
        is_before_testing = self.assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
        # Check if any date is confirmed for this assessment
        is_assessment_confirmed = AssessmentDateOption.objects.filter(
            assessment=self.assessment, status=AssessmentDateOption.Status.CONFIRMED
        ).exists()

        if self.option.status == AssessmentDateOption.Status.CONFIRMED:
            # Prevent deletion of confirmed dates via this view
            messages.error(request, "Confirmed dates cannot be deleted.")
        # Allow deletion only before testing starts AND if assessment isn't confirmed yet
        elif is_before_testing and not is_assessment_confirmed:
            if self.option.status == AssessmentDateOption.Status.SUGGESTED:
                # Allow proposer OR assessor/admin to delete suggested dates
                if (self.option.proposed_by == user) or (profile and profile.role in ['Admin', 'Assessor']):
                    can_delete = True
            elif self.option.status in [AssessmentDateOption.Status.CLIENT_PREFERRED, AssessmentDateOption.Status.REJECTED]:
                 # Allow assessor/admin to delete preferred or rejected dates
                if profile and profile.role in ['Admin', 'Assessor']:
                    can_delete = True
        # Add Admin override maybe?
        # elif is_admin(user) and self.option.status != AssessmentDateOption.Status.CONFIRMED:
        #    can_delete = True

        if not can_delete:
             logger.warning(f"User {user.username} permission denied to delete option {self.option.pk} (status: {self.option.status}, assess_confirmed: {is_assessment_confirmed}, assess_status: {self.assessment.status})")
             messages.error(request, "You do not have permission to delete this date option at this time.")
             return self.redirect_back()

        # --- Perform Deletion ---
        try:
            date_str = self.option.proposed_date.strftime('%Y-%m-%d')
            status_str = self.option.get_status_display()
            proposer_username = self.option.proposed_by.username if self.option.proposed_by else 'N/A'

            # Delete the object from the database
            self.option.delete()

            # Log the deletion event
            log_assessment_event(self.assessment, user, f"Assessment date option ({date_str}, Status: {status_str}, Proposed by: {proposer_username}) deleted.")
            messages.success(request, f"Date option {date_str} deleted successfully.")
            logger.info(f"AssessmentDateOption {self.kwargs['option_pk']} deleted for assessment {self.assessment.pk} by user {user.username}")

        except Exception as e:
            logger.error(f"Error deleting date option {self.kwargs['option_pk']}: {e}", exc_info=True)
            messages.error(request, f"An unexpected error occurred while deleting: {e}")

        return self.redirect_back()

    def redirect_back(self):
        """ Redirects back to the appropriate detail view """
        profile = getattr(self.request.user, 'userprofile', None)
        if profile and profile.role == 'Client':
            return redirect('tracker:client_assessment_detail', pk=self.assessment.pk)
        else: # Assessor or Admin
            return redirect('tracker:assessor_assessment_detail', pk=self.assessment.pk)
class LaunchScanView(LoginRequiredMixin, View):
    """
    Handles the POST request to trigger the Tenable scan launch task.
    """
    http_method_names = ['post'] # Only allow POST requests

    def post(self, request, *args, **kwargs):
        assessment_pk = self.kwargs.get('assessment_pk')
        print(f"[DEBUG LaunchScanView.post] Received POST for assessment {assessment_pk}") # DEBUG
        logger.info(f"Scan launch requested for assessment {assessment_pk} by user {request.user.username}")

        # --- Get Assessment and Perform Checks ---
        try:
            assessment = get_object_or_404(Assessment.objects.select_related('client', 'assessor'), pk=assessment_pk)

            # 1. Permission Check (Admin, Assigned Assessor, or Client Owner)
            user = request.user
            profile = getattr(user, 'userprofile', None)
            allowed = False
            if is_admin(user): allowed = True
            elif is_assessor(user) and assessment.assessor == user: allowed = True
            elif is_client(user) and profile and assessment.client == profile.client: allowed = True

            if not allowed:
                 logger.warning(f"User {user.username} permission denied to launch scan for assessment {assessment_pk}.")
                 messages.error(request, "You do not have permission to launch scans for this assessment.")
                 # Determine redirect based on role
                 if is_client(user): return redirect('tracker:client_dashboard')
                 if is_assessor(user): return redirect('tracker:assessor_dashboard')
                 return redirect('tracker:admin_dashboard')

            # 2. Condition Check (Call the model method again for server-side validation)
            scan_status = assessment.can_launch_ce_plus_scan()
            if not scan_status.get('can_launch'):
                 logger.warning(f"Scan launch aborted for assessment {assessment_pk}: Conditions not met ({scan_status.get('reason')}).")
                 messages.error(request, f"Cannot launch scan: {scan_status.get('reason')}")
                 # Redirect back to the detail page
                 detail_url_name = 'tracker:client_assessment_detail' if is_client(user) else 'tracker:assessor_assessment_detail'
                 return redirect(detail_url_name, pk=assessment.pk)

                 # CHANGES BEGIN (Call the Celery task)
                 # --- Trigger Celery Task ---
            print(f"[DEBUG LaunchScanView.post] Checks passed for assessment {assessment_pk}. Triggering Celery task...")
            launch_tenable_scan_task.delay(assessment.id)
                 # CHANGES END

            messages.success(request, f"Tenable scan launch initiated for assessment #{assessment.id}. This may take a few moments.")
            logger.info(f"Tenable scan launch task triggered for assessment {assessment.id}")

        except Http404:
             messages.error(request, "Assessment not found.")
             # Redirect based on role if possible
             profile = getattr(request.user, 'userprofile', None)
             if profile and profile.role == 'Client': return redirect('tracker:client_dashboard')
             if profile and profile.role == 'Assessor': return redirect('tracker:assessor_dashboard')
             return redirect('tracker:admin_dashboard') # Fallback
        except Exception as e:
            logger.exception(f"Error in LaunchScanView for assessment {assessment_pk}: {e}")
            messages.error(request, f"An unexpected error occurred while trying to launch the scan: {e}")

        # --- Redirect back to the detail view ---
        # Determine redirect based on user role who initiated
        user_role = getattr(request.user, 'userprofile', None).role if hasattr(request.user, 'userprofile') else None
        detail_url_name = 'tracker:client_assessment_detail' if user_role == 'Client' else 'tracker:assessor_assessment_detail'
        # Fallback if user has no profile role (e.g. admin might not have one depending on setup)
        if user_role not in ['Client', 'Assessor']:
            # Default to assessor view or admin view as appropriate
            detail_url_name = 'tracker:assessor_assessment_detail' # Or redirect admin elsewhere?

        # Ensure assessment_pk is available for redirect even after exception handling
        redirect_pk = assessment_pk if 'assessment_pk' in locals() else self.kwargs.get('assessment_pk')
        if redirect_pk:
            try:
                return redirect(detail_url_name, pk=redirect_pk)
            except NoReverseMatch:
                logger.error(f"NoReverseMatch trying to redirect to {detail_url_name} with pk {redirect_pk}")
                # Fallback redirect if specific detail view fails
                if user_role == 'Client': return redirect('tracker:client_dashboard')
                if user_role == 'Assessor': return redirect('tracker:assessor_dashboard')
                return redirect('tracker:admin_dashboard')
        else:
            # Ultimate fallback if pk was lost
            logger.error("Could not determine assessment PK for redirect in LaunchScanView")
            return redirect('tracker:dashboard') # Or appropriate main dashboard


@require_POST # Only allow POST requests
@login_required
@csrf_protect # Ensure CSRF token is checked
def update_workflow_step_status(request, assessment_pk, step_pk):
    """
    Handles POST requests to update the status of a specific AssessmentWorkflowStep.
    Requires the user to be logged in and have permission to update the step.
    Accepts any valid status from AssessmentWorkflowStep.Status.choices.
    Returns a JSON response indicating success or failure.
    """
    step = get_object_or_404(
        AssessmentWorkflowStep.objects.select_related(
            'assessment', 'step_definition', 'completed_by' # Include related fields for logging/response
        ),
        pk=step_pk,
        assessment_id=assessment_pk
    )

    # Check permissions using the model method
    if not step.is_update_allowed(request.user):
        return JsonResponse({'success': False, 'error': 'Permission denied.'}, status=403)

    # Get the desired status from the POST data (e.g., 'Complete', 'HelpNeeded')
    new_status = request.POST.get('status')

    # Validate the new status against the choices defined in the model
    valid_statuses = [choice[0] for choice in AssessmentWorkflowStep.Status.choices]
    if new_status not in valid_statuses:
        return JsonResponse({'success': False, 'error': f"Invalid status '{new_status}' provided."}, status=400)

    # --- Update the step ---
    try:
        with transaction.atomic(): # Ensure database consistency
            step.status = new_status # Set the status received from the request
            log_event_desc = "" # Initialize log description

            # Only set completion details if status is 'Complete'
            if new_status == AssessmentWorkflowStep.Status.COMPLETE:
                # Let's always update timestamp/user when explicitly marked Complete.
                step.completed_at = timezone.now()
                step.completed_by = request.user
                log_event_desc = f"Workflow step '{step.step_definition.name}' marked as Complete."
            else:
                # If status is anything other than Complete, clear completion details
                step.completed_at = None
                step.completed_by = None
                # Set specific log message based on the new status
                # Use the display value for logging if available
                status_display = dict(AssessmentWorkflowStep.Status.choices).get(new_status, new_status) # Get display name
                log_event_desc = f"Workflow step '{step.step_definition.name}' status set to {status_display}."


            step.save() # Save the changes to the database

        # Log the event using the utility function
        log_assessment_event(step.assessment, request.user, log_event_desc)

        # Return success response with updated details for the UI
        return JsonResponse({
            'success': True,
            'new_status': step.status, # Send back the internal status value (e.g., HelpNeeded)
            'new_status_display': step.get_status_display(), # Send back the display name (e.g., Help Needed)
            'completed_by': step.completed_by.username if step.completed_by else None,
            'completed_at': step.completed_at.strftime('%Y-%m-%d %H:%M') if step.completed_at else None
        })

    except Exception as e:
        # Handle potential errors during save
        print(f"Error updating workflow step status for step {step.pk}: {e}")
        # Log the error more formally using Python logging if configured
        return JsonResponse({'success': False, 'error': 'An internal error occurred while updating the status.'}, status=500)
class ExternalIPListView(LoginRequiredMixin, ListView):
    model = ExternalIP
    template_name = 'tracker/external_ip_management/externalip_list.html' # Template to create
    context_object_name = 'external_ips'
    paginate_by = 25 # Optional pagination

    def dispatch(self, request, *args, **kwargs):
        """Get assessment and check view permissions."""
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # Use the broader permission check for viewing the list
        if not user_can_manage_assessment_external_ips(request.user, self.assessment):
             raise PermissionDenied("You do not have permission to view external IPs for this assessment.")
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Return IPs belonging to the specific assessment."""
        return ExternalIP.objects.filter(assessment=self.assessment).order_by('ip_address_or_hostname')

    def get_context_data(self, **kwargs):
        """Add assessment, title, and edit permission flag to context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"External Scan Targets for Assessment #{self.assessment.id}"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        # Check if user can currently add/edit items based on role and status
        context['can_edit'] = user_can_edit_assessment_external_ips(self.request.user, self.assessment)
        return context
class ExternalIPCreateView(LoginRequiredMixin, CreateView):
    model = ExternalIP
    form_class = ExternalIPForm
    template_name = 'tracker/external_ip_management/externalip_form.html' # Template to create

    def dispatch(self, request, *args, **kwargs):
        """Get assessment and check add/edit permissions."""
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # Use stricter permission check for creating
        if not user_can_edit_assessment_external_ips(request.user, self.assessment):
             messages.error(request, "Cannot add external IPs when assessment status is not 'Scoping (Client Input)'.")
             # Redirect to list view instead of raising PermissionDenied for better UX
             return redirect(reverse('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk}))
             # Or raise PermissionDenied("You do not have permission to add external IPs...")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        """Set assessment, handle consent, log event."""
        external_ip = form.save(commit=False)
        external_ip.assessment = self.assessment

        # Set consent fields based on the form checkbox
        if form.cleaned_data.get('confirm_consent'):
            external_ip.consent_given = True
            external_ip.consented_by = self.request.user
            external_ip.consent_timestamp = timezone.now()
        else:
            # Should be caught by form validation if field is required=True
            external_ip.consent_given = False
            external_ip.consented_by = None
            external_ip.consent_timestamp = None

        try:
            external_ip.save()
            messages.success(self.request, f"External target '{external_ip.ip_address_or_hostname}' added with consent.")
            log_assessment_event(self.assessment, self.request.user, f"External IP/Hostname added: '{external_ip.ip_address_or_hostname}' (Consent Provided).")
            return super().form_valid(form)
        except IntegrityError:
            # Handle case where unique_together constraint fails (IP/Host already exists for assessment)
            form.add_error('ip_address_or_hostname', f"This IP address or hostname is already listed for this assessment.")
            return self.form_invalid(form)


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Add External Scan Target to Assessment #{self.assessment.id}"
        return context

    def get_success_url(self):
        return reverse_lazy('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk})
class ExternalIPUpdateView(LoginRequiredMixin, UpdateView):
    model = ExternalIP
    form_class = ExternalIPForm # Using the same form for now
    template_name = 'tracker/external_ip_management/externalip_form.html' # Re-use form template
    context_object_name = 'external_ip'

    def dispatch(self, request, *args, **kwargs):
        """Get object, assessment and check edit permissions."""
        self.object = self.get_object()
        self.assessment = self.object.assessment
        # Use stricter permission check for updating
        if not user_can_edit_assessment_external_ips(request.user, self.assessment):
            messages.error(request, "Cannot edit external IPs when assessment status is not 'Scoping (Client Input)'.")
            return redirect(reverse('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk}))
            # Or raise PermissionDenied(...)
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Ensure we only edit IPs for the specified assessment."""
        assessment_pk = self.kwargs['assessment_pk']
        return ExternalIP.objects.filter(assessment_id=assessment_pk)

    def form_valid(self, form):
        """Update consent only if IP/Hostname changed and checkbox ticked."""
        external_ip = form.save(commit=False)
        log_msg = f"External IP/Hostname updated: '{external_ip.ip_address_or_hostname}'."

        # Check if the critical field changed
        if 'ip_address_or_hostname' in form.changed_data:
            # IP/Hostname changed, require re-consent via checkbox
            if form.cleaned_data.get('confirm_consent'):
                external_ip.consent_given = True
                external_ip.consented_by = self.request.user
                external_ip.consent_timestamp = timezone.now()
                log_msg += " Consent re-confirmed."
            else:
                # If IP changed but consent not checked, raise validation error
                form.add_error('confirm_consent', "You must confirm consent again as the IP address or hostname has changed.")
                return self.form_invalid(form)
        # If IP/Hostname did not change, we don't need to check the 'confirm_consent'
        # checkbox here, just save other changes (like description).
        # The original consent details remain.

        try:
            external_ip.save()
            messages.success(self.request, f"External target '{external_ip.ip_address_or_hostname}' updated.")
            log_assessment_event(self.assessment, self.request.user, log_msg)
            return super().form_valid(form)
        except IntegrityError:
             form.add_error('ip_address_or_hostname', f"This IP address or hostname is already listed for this assessment.")
             return self.form_invalid(form)


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        # Pre-check the consent box on update form load if consent was previously given
        # (User still needs to submit it if IP changes)
        if self.object.consent_given and 'confirm_consent' in context['form'].fields:
             context['form'].fields['confirm_consent'].initial = True
        context['page_title'] = f"Edit External Scan Target: {self.object.ip_address_or_hostname}"
        return context

    def get_success_url(self):
        return reverse_lazy('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk})
class ExternalIPDeleteView(LoginRequiredMixin, DeleteView):
    model = ExternalIP
    template_name = 'tracker/external_ip_management/externalip_confirm_delete.html' # Template to create
    context_object_name = 'external_ip'

    def dispatch(self, request, *args, **kwargs):
        """Get object, assessment and check edit permissions."""
        self.object = self.get_object()
        self.assessment = self.object.assessment
        # Use stricter permission check for deleting
        if not user_can_edit_assessment_external_ips(request.user, self.assessment):
             messages.error(request, "Cannot delete external IPs when assessment status is not 'Scoping (Client Input)'.")
             return redirect(reverse('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk}))
             # Or raise PermissionDenied(...)
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Ensure we only delete IPs for the specified assessment."""
        assessment_pk = self.kwargs['assessment_pk']
        return ExternalIP.objects.filter(assessment_id=assessment_pk)

    def form_valid(self, form):
        """Add success message and log."""
        ip_name = self.object.ip_address_or_hostname
        response = super().form_valid(form) # This performs the delete
        messages.success(self.request, f"External target '{ip_name}' deleted.")
        log_assessment_event(self.assessment, self.request.user, f"External IP/Hostname deleted: '{ip_name}'.")
        return response # Redirects to success_url

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Delete External Scan Target: {self.object.ip_address_or_hostname}"
        return context

    def get_success_url(self):
        return reverse_lazy('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk})
class ExternalIPScanUpdateView(AssessorOrAdminRequiredMixin, UpdateView):
    model = ExternalIP
    form_class = ExternalIPScanUpdateForm # Use the specific form
    template_name = 'tracker/external_ip_management/externalip_scan_form.html' # New template needed
    context_object_name = 'external_ip'

    def setup(self, request, *args, **kwargs):
        """Get object and assessment, verify permissions."""
        super().setup(request, *args, **kwargs)
        self.object = self.get_object()
        self.assessment = self.object.assessment
        # Additional check: ensure assessor is assigned or user is admin
        if is_assessor(request.user) and self.assessment.assessor != request.user:
             raise PermissionDenied("You are not the assigned assessor for this assessment.")
        # Prevent updates if assessment is complete
        if self.assessment.status.startswith('Complete_'):
             raise PermissionDenied("Cannot update scan status for a completed assessment.")

    def get_queryset(self):
        """Ensure we only edit IPs for the specified assessment."""
        # Primarily used by get_object, permissions checked in setup/mixin
        assessment_pk = self.kwargs['assessment_pk']
        return ExternalIP.objects.filter(assessment_id=assessment_pk)

    def form_valid(self, form):
        """Set last_scanned_at timestamp and log."""
        external_ip = form.save(commit=False)
        # Update timestamp whenever scan status/notes are saved
        external_ip.last_scanned_at = timezone.now()
        external_ip.save()

        messages.success(self.request, f"Scan status updated for '{external_ip.ip_address_or_hostname}'.")
        log_assessment_event(
            self.assessment,
            self.request.user,
            f"External IP scan status updated for '{external_ip.ip_address_or_hostname}': Status={external_ip.get_scan_status_display()}."
        )
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Update Scan Status: {self.object.ip_address_or_hostname}"
        return context

    def get_success_url(self):
        # Redirect back to the main list view (used by assessors)
        return reverse_lazy('tracker:externalip_list', kwargs={'assessment_pk': self.assessment.pk})
class ScopedItemUpdateView(ClientRequiredMixin, UpdateView):
    model = ScopedItem
    form_class = ScopedItemUpdateForm # Use the new update form
    template_name = 'tracker/client/scope_item_form.html' # Template to create
    context_object_name = 'scoped_item' # Name for the object in the template

    def setup(self, request, *args, **kwargs):
        """Get assessment object early via the item being edited."""
        super().setup(request, *args, **kwargs)
        # Get the ScopedItem object itself using UpdateView's default mechanism
        # Then get the assessment from the item
        scoped_item = self.get_object() # Get object based on pk from URL
        self.assessment = scoped_item.assessment
        # Check if the logged-in client owns this assessment
        profile = request.user.userprofile
        if self.assessment.client != profile.client:
             raise PermissionDenied("You do not have permission to edit items for this assessment.")
        # Check if assessment status allows editing
        if self.assessment.status != 'Scoping_Client':
             messages.error(request, f"Cannot edit scope items when assessment status is '{self.assessment.get_status_display()}'.")
             # Redirect back to manage page might be better than PermissionDenied here
             # raise PermissionDenied("Scope editing is locked.")
             # Redirecting instead:
             # Store redirect response to be returned by dispatch if needed
             self.permission_denied_response = redirect('tracker:client_scope_manage', assessment_pk=self.assessment.pk)


    def dispatch(self, request, *args, **kwargs):
         # Check if permission was denied during setup
         if hasattr(self, 'permission_denied_response'):
             return self.permission_denied_response
         return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Ensure we only get items belonging to the specified assessment."""
        # This helps ensure user doesn't edit item from another assessment via URL manipulation
        assessment_pk = self.kwargs['assessment_pk']
        return ScopedItem.objects.filter(assessment_id=assessment_pk)

    def get_form_kwargs(self):
        # Pass assessment to the form if needed (e.g., for Network dropdown)
        kwargs = super().get_form_kwargs()
        kwargs['assessment'] = self.assessment
        return kwargs

    def form_valid(self, form):
        """Handle saving and logging."""
        item_identifier = form.instance.identifier or f"Item ID {form.instance.pk}"
        messages.success(self.request, f"Scope item '{item_identifier}' updated successfully.")
        # Log the update event
        log_assessment_event(self.assessment, self.request.user, f"Scoped item updated: '{item_identifier}' ({form.instance.get_item_type_display()}).")
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment # Already gets assessment via setup/get_object
        context['page_title'] = f"Edit Scope Item: {self.object.identifier or f'ID {self.object.pk}'}"
        context['is_update'] = True # Flag for template if needed

        # --- START: Ensure this block is present ---
        # Fetch OS Data for JS Filtering
        all_operating_systems = OperatingSystem.objects.all().order_by('name', 'version')
        os_data_for_js = []
        for os in all_operating_systems:
            os_data_for_js.append({
                'id': os.pk,
                'name': str(os),
                'category': os.category or ''
            })
        # Pass OS data to template as JSON
        # Make sure 'json' and 'DjangoJSONEncoder' are imported at the top of views.py
        context['os_data_json'] = json.dumps(os_data_for_js, cls=DjangoJSONEncoder)
        # --- END: Ensure this block is present ---

        return context

    def get_success_url(self):
        """Redirect back to the scope management page."""
        return reverse_lazy('tracker:client_scope_manage', kwargs={'assessment_pk': self.assessment.pk})
class UploadExtractReportView(LoginRequiredMixin, View):
    form_class = UploadReportForm
    template_name = 'tracker/upload_report.html'

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST, request.FILES)
        extracted_data = None
        formatted_extracted_data = {} # <-- New dictionary for template
        upload_instance = None

        if form.is_valid():
            try:
                upload_instance = form.save(commit=False)
                upload_instance.uploaded_by = request.user
                upload_instance.save()
                messages.success(request, f"Report '{upload_instance.filename}' uploaded successfully.")

                file_path = os.path.join(settings.MEDIA_ROOT, upload_instance.report_file.name)
                if os.path.exists(file_path):
                    extracted_data = extract_ce_data_from_pdf(file_path)
                    upload_instance.extracted_data_text = json.dumps(extracted_data, indent=2)

                    if extracted_data:
                        # --- START: Format keys for display ---
                        for key, value in extracted_data.items():
                            if key != 'errors': # Exclude the errors key itself
                                display_key = key.replace("_", " ").title()
                                formatted_extracted_data[display_key] = value
                        # --- END: Format keys for display ---

                        if extracted_data.get('errors'):
                            upload_instance.extraction_status = "Completed with errors"
                            messages.warning(request, "Extraction completed, but some fields could not be found.")
                        else:
                            upload_instance.extraction_status = "Completed successfully"
                            messages.success(request, "Data extracted successfully.")

                        # Save key fields
                        if extracted_data.get('report_date'):
                            try:
                                upload_instance.report_date = datetime.strptime(extracted_data['report_date'], '%d/%m/%Y').date()
                            except (ValueError, TypeError):
                                messages.error(request, f"Could not parse extracted report date: {extracted_data.get('report_date')}")
                                upload_instance.report_date = None # Ensure it's null if parsing fails
                        if extracted_data.get('certificate_number'):
                            upload_instance.certificate_number = extracted_data['certificate_number'][:100]

                        upload_instance.save(update_fields=['extracted_data_text', 'extraction_status', 'report_date', 'certificate_number'])
                    else:
                        # Handle case where extraction returns None or empty dict
                        messages.error(request, "Extraction function returned no data.")
                        upload_instance.extraction_status = "Error - Extraction failed"
                        upload_instance.save(update_fields=['extraction_status'])


                else:
                    messages.error(request, f"Uploaded file not found at path: {file_path}")
                    upload_instance.extraction_status = "Error - File not found"
                    upload_instance.save(update_fields=['extraction_status'])
            except Exception as e:
                 messages.error(request, f"An error occurred during processing: {e}")
                 if upload_instance:
                     upload_instance.extraction_status = f"Error - {e}"
                     upload_instance.save(update_fields=['extraction_status'])

        return render(request, self.template_name, {
            'form': form,
            'extracted_data': formatted_extracted_data, # <-- Pass the formatted dictionary
            'extraction_errors': extracted_data.get('errors') if extracted_data else ['Processing Error'], # Pass errors separately
            'uploaded_report': upload_instance
        })
class TriggerTenableAssetTaggingView(AdminRequiredMixin, View): # Use Admin Required
    def post(self, request, *args, **kwargs):
        # Change pk lookup from Assessment to Client
        client_id = self.kwargs.get('client_pk') # Get client_pk from URL
        client = get_object_or_404(Client, pk=client_id)
        try:
            # Call the task with the client_id
            apply_tenable_tag_to_assets.delay(client.id)
            messages.success(request, f"Asset tagging process initiated for Client '{client.name}' based on agent group. This may take time.")
        except Exception as e:
             messages.error(request, f"Failed to initiate asset tagging for Client '{client.name}': {e}")

        # Redirect back to the new group detail view
        return HttpResponseRedirect(reverse('tracker:tenable_group_detail', kwargs={'pk': client.id}))
class TriggerTenableClientTagSyncView(AssessorRequiredMixin, TemplateView): # Use Assessor permission
    """
    Manually triggers the Celery task to create or update the Tenable.io tag
    for the client associated with the given assessment.
    """
    def post(self, request, *args, **kwargs):
        assessment_id = self.kwargs.get('pk')
        assessment = get_object_or_404(Assessment.objects.select_related('client'), pk=assessment_id)
        client = assessment.client

        if not client:
            messages.error(request, "Cannot sync client tag: Assessment is not linked to a client.")
            return HttpResponseRedirect(reverse('tracker:assessor_assessment_detail', kwargs={'pk': assessment_id}))

        try:
            # Trigger the task for the *client* ID
            create_or_update_tenable_client_tag.delay(client.id)
            messages.success(request, f"Client tag synchronization initiated for '{client.name}'. This may take a few moments.")
        except Exception as e:
             # Handle potential Celery connection errors
             messages.error(request, f"Failed to initiate client tag sync: {e}")

        # Redirect back to the assessment detail page
        return HttpResponseRedirect(reverse('tracker:assessor_assessment_detail', kwargs={'pk': assessment_id}))
class GenerateAgentScriptView(LoginRequiredMixin, TemplateView): # Use LoginRequiredMixin as base
    template_name = 'tracker/assessor/generate_agent_script_v2.html' # Consider renaming/moving if client uses it heavily

    def dispatch(self, request, *args, **kwargs):
        """Check permissions before allowing access."""
        assessment_pk = self.kwargs.get('pk') # Assuming 'pk' is used in both URLs
        try:
            assessment = get_object_or_404(Assessment.objects.select_related('client', 'assessor'), pk=assessment_pk)
            self.assessment = assessment # Store for get_context_data
        except Http404:
            messages.error(request, "Assessment not found.")
            # Redirect to a safe place, maybe the main dashboard
            return redirect('tracker:dashboard') # Or appropriate dashboard based on role

        user = request.user
        allowed = False

        # Check if Admin or Assessor (assigned or not, depending on your policy)
        # Sticking to original AssessorOrAdmin check logic for these roles
        if is_admin(user) or is_assessor(user):
            # Optional: Restrict assessors only to their assigned assessments
            # if is_assessor(user) and assessment.assessor != user:
            #     pass # Not allowed if you want strict assignment
            # else:
            #     allowed = True # Allow admin, allow assigned assessor
            allowed = True # Allow any admin or assessor for now

        # Check if Client associated with the assessment
        elif is_client(user) and hasattr(user, 'userprofile') and user.userprofile.client == assessment.client:
            allowed = True

        if not allowed:
            logger.warning(f"User {user.username} denied access to generate script for assessment {assessment_pk}.")
            messages.error(request, "You do not have permission to view this page.")
            # Redirect based on role
            if is_client(user):
                return redirect('tracker:client_dashboard')
            elif is_assessor(user):
                return redirect('tracker:assessor_dashboard')
            else: # Includes admins who failed check somehow, or other roles
                return redirect('tracker:dashboard') # General dashboard

        # User has permission, proceed with the view
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # self.assessment is set in dispatch
        assessment = self.assessment
        context['assessment'] = assessment
        client = assessment.client
        context['client'] = client

        # --- Tenable Configuration ---
        linking_key = getattr(config, 'TENABLE_LINKING_KEY', '')
        tenable_base_url_setting = getattr(config, 'TENABLE_URL', 'https://cloud.tenable.com')
        # Ensure URL has scheme
        if not tenable_base_url_setting.startswith(('http://', 'https://')):
            tenable_base_url = f'https://{tenable_base_url_setting}'
        else:
            tenable_base_url = tenable_base_url_setting
        tenable_host_display = tenable_base_url.replace('https://', '').replace('http://', '')

        context['tenable_host_display'] = tenable_host_display
        agent_group_name_param = client.name # Group name is client name

        context['agent_download_url'] = getattr(settings, 'TENABLE_AGENT_DOWNLOADS_PAGE_URL', 'https://www.tenable.com/downloads/nessus-agents')
        context['linking_key_set'] = bool(linking_key)
        context['page_title'] = f"Generate Nessus Agent Install Script for {client.name}"

        # --- Generate Official Script Commands ---
        scripts = {}
        if not linking_key:
            logger.warning(f"Tenable Linking Key is not set in Constance config. Cannot generate agent scripts for assessment {assessment.pk}.")
            scripts['error'] = "Tenable Linking Key not configured in application settings. Cannot generate scripts."
            scripts['windows_official'] = "# Linking key not configured in settings."
            scripts['linux_macos_official'] = "# Linking key not configured in settings."
        else:
            # Windows Command
            windows_script_url = f"{tenable_base_url}/install/agent/installer/ms-install-script.ps1"
            groups_ps_arg = f"'{agent_group_name_param}'" # Single quotes for PowerShell
            scripts['windows_official'] = (
                f'$ProgressPreference = "SilentlyContinue"; Write-Host "Downloading Tenable PowerShell Installer..."; '
                f'Invoke-WebRequest -Uri "{windows_script_url}" -OutFile "./ms-install-script.ps1"; '
                f'Write-Host "Running Installer Script (requires Administrator)..."; '
                f'.\\ms-install-script.ps1 -key "{linking_key}" -type "agent" -groups {groups_ps_arg}; '
                f'Write-Host "Cleaning up..."; Remove-Item -Path "./ms-install-script.ps1" -Force -ErrorAction SilentlyContinue; '
                f'$ProgressPreference = "Continue"; Write-Host "Windows Agent Installation Attempt Complete."'
            )

            # Linux/macOS Command
            encoded_group_name = quote(agent_group_name_param) # URL encode group name
            linux_install_url = f"{tenable_base_url}/install/agent?groups={encoded_group_name}"
            scripts['linux_macos_official'] = (
                f"echo 'Downloading and executing Tenable installer script (requires root/sudo)...'; "
                f"curl -sSLk -H 'X-Key: {linking_key}' '{linux_install_url}' | sudo bash"
            )
        context['scripts'] = scripts

        # Fetch ALL Valid Agent URLs for the manual list
        all_agent_urls = list(NessusAgentURL.objects.filter(is_valid=True).order_by(
            'os_name', 'architecture', '-agent_version'
        ))
        context['all_agent_urls'] = all_agent_urls
        context['urls_found'] = bool(all_agent_urls)

        # Pass user role to potentially adjust template slightly if needed
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None

        return context
class TenableGroupDetailView(AdminRequiredMixin, DetailView):
    model = Client
    template_name = 'tracker/tenable/group_detail.html'
    context_object_name = 'client'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        client = self.get_object()
        context['page_title'] = f"Tenable Agent Group: {client.name}"
        context['agents'] = []
        context['agent_count'] = 0
        context['error_message'] = None
        context['config'] = config

        tio = get_tenable_io_client()
        if not tio:
            context['error_message'] = "Could not initialize connection to Tenable.io. Check API keys and URL in Django Admin > Constance."
            logger.error(context['error_message'])
            return context

        agent_group_name = client.name
        agent_group_id = None
        try:
            logger.debug(f"Searching for Tenable agent group named: '{agent_group_name}'")
            agent_groups = tio.agent_groups.list()
            for group in agent_groups:
                if group['name'] == agent_group_name:
                    agent_group_id = group.get('id')
                    logger.debug(f"Found group ID {agent_group_id} for name '{agent_group_name}'")
                    break

            if not agent_group_id:
                logger.warning(f"Agent group '{agent_group_name}' not found in Tenable.io.")
                context['error_message'] = f"Agent group '{agent_group_name}' not found in Tenable.io. Have you run the client sync task, and does the name match exactly (case-sensitive)?"
                return context

            logger.debug(f"Attempting to list agents for group ID: {agent_group_id}")
            try:
                 all_agents_iterator = tio.agents.list(limit=1000)
                 logger.debug(f"Fetched agent iterator (limit 1000). Filtering for group ID {agent_group_id}...")

                 agents_in_group = []
                 for agent_data in all_agents_iterator:
                     agent_groups_list = agent_data.get('groups', [])
                     if isinstance(agent_groups_list, list) and any(ag.get('id') == agent_group_id for ag in agent_groups_list):
                          timestamp = agent_data.get('last_connect')
                          if timestamp:
                              try:
                                  # === CORRECTED LINE BELOW ===
                                  # Use timezone.utc from the standard datetime module import
                                  agent_data['last_connect_dt'] = datetime.fromtimestamp(int(timestamp), tz=pytz.utc)
                                  # === END CORRECTION ===
                              except (ValueError, TypeError, OverflowError) as ts_err:
                                  logger.warning(f"Could not convert last_connect timestamp '{timestamp}' for agent {agent_data.get('id')}: {ts_err}")
                                  agent_data['last_connect_dt'] = None
                          else:
                              agent_data['last_connect_dt'] = None
                          agents_in_group.append(agent_data)

                 logger.debug(f"Found {len(agents_in_group)} agents in group '{agent_group_name}'.")
                 context['agents'] = agents_in_group
                 context['agent_count'] = len(agents_in_group)

            except APIError as e:
                logger.exception(f"Tenable API Error listing agents (potentially during fetch): {e}")
                context['error_message'] = f"API Error listing agents: {e}"
            except ForbiddenError:
                 logger.exception("Permission denied listing agents in Tenable. Check API key permissions.")
                 context['error_message'] = "Permission denied listing agents. Check API key permissions."
            except Exception as e:
                logger.exception(f"Unexpected error listing or processing agents for group '{agent_group_name}': {e}")
                context['error_message'] = f"Unexpected error listing/processing agents: {e}" # Keep simple for user

        except APIError as e:
            logger.exception(f"Tenable API Error finding agent group '{agent_group_name}': {e}")
            context['error_message'] = f"API Error finding agent group '{agent_group_name}': {e}"
        except ForbiddenError:
             logger.exception("Permission denied listing agent groups in Tenable. Check API key permissions.")
             context['error_message'] = "Permission denied listing agent groups. Check API key permissions."
        except Exception as e:
             logger.exception(f"Unexpected error finding agent group '{agent_group_name}': {e}")
             context['error_message'] = f"Unexpected error finding agent group: {e}" # Keep simple for user

        return context
class AssessorAvailabilityListView(AssessorOrAdminRequiredMixin, ListView):
    """
    View for Assessors/Admins to see and manage their unavailable dates.
    Handles both displaying the list (GET) and adding a new date (POST).
    """
    model = AssessorAvailability
    template_name = 'tracker/assessor/assessor_availability_list.html' # Template to be created
    context_object_name = 'unavailable_dates'

    def get_queryset(self):
        # Show only the logged-in user's unavailable dates
        # Note: AssessorOrAdminRequiredMixin ensures user is one of these roles
        # If Admins need to see ALL assessor availability, this query needs adjustment
        return AssessorAvailability.objects.filter(assessor=self.request.user).order_by('unavailable_date')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add the form for adding new unavailable dates
        if 'form' not in context: # Add form if not already passed (e.g., on POST failure)
            context['form'] = AssessorAvailabilityForm()
        context['page_title'] = "Manage My Unavailable Dates"
        return context

    def post(self, request, *args, **kwargs):
        """Handles POST request for adding a new unavailable date."""
        form = AssessorAvailabilityForm(request.POST)
        if form.is_valid():
            try:
                availability = form.save(commit=False)
                availability.assessor = request.user # Set the assessor to the logged-in user
                availability.save()
                messages.success(request, f"Date {availability.unavailable_date.strftime('%Y-%m-%d')} marked as unavailable.")
                return HttpResponseRedirect(reverse_lazy('tracker:assessor_availability_list'))
            except IntegrityError: # Catch unique_together constraint violation
                form.add_error('unavailable_date', "This date is already marked as unavailable.")
                messages.error(request, "This date is already marked as unavailable.")
            except Exception as e:
                messages.error(request, f"An error occurred: {e}")
        else:
             messages.error(request, "Please correct the errors below.")

        # Re-render the page with the invalid form and existing data
        # Need to manually fetch the queryset again for the context if using basic View/POST override
        # ListView handles this better if combined with FormMixin/CreateView logic,
        # but this explicit way works for a simple combined view.
        self.object_list = self.get_queryset()
        context = self.get_context_data(form=form)
        return self.render_to_response(context)
class DeleteAssessorAvailabilityView(AssessorOrAdminRequiredMixin, DeleteView):
    """ Handles deleting an AssessorAvailability record. """
    model = AssessorAvailability
    # Redirect back to the list view after successful deletion
    success_url = reverse_lazy('tracker:assessor_availability_list')
    template_name = 'tracker/assessor/assessor_availability_confirm_delete.html' # Template to be created
    context_object_name = 'availability'

    def get_queryset(self):
        # Ensure users can only delete their *own* availability records
        return AssessorAvailability.objects.filter(assessor=self.request.user)

    def form_valid(self, form):
        # Overriding form_valid to add messages (DeleteView uses form_valid internally for POST)
        availability_date = self.object.unavailable_date.strftime('%Y-%m-%d')
        response = super().form_valid(form)
        messages.success(self.request, f"Availability block for {availability_date} removed successfully.")
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = f"Remove Unavailability for {self.object.unavailable_date.strftime('%Y-%m-%d')}"
        return context
def user_can_manage_assessment_dates(user, assessment, option=None):
    """ Checks if a user can manage dates for an assessment/option """
    if not user or not user.is_authenticated:
        return False

    # Check if an option is already Confirmed (for the assessment overall)
    if AssessmentDateOption.objects.filter(assessment=assessment, status=AssessmentDateOption.Status.CONFIRMED).exists():
        # If already confirmed, generally no more management allowed,
        # EXCEPT maybe deleting a rejected/suggested one by assessor?
        # For now, block all management if confirmed.
        # If allowing deletion post-confirmation, refine this check.
        # If we are checking for deleting a *specific* non-confirmed option, allow it:
        if option and option.status != AssessmentDateOption.Status.CONFIRMED:
            pass # Allow check to continue for specific non-confirmed option
        else:
            return False # Block general management if any option is confirmed

    # Check if assessment status allows management (before testing/completion)
    is_before_testing = assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
    if not is_before_testing:
        return False

    # Check user role permission
    profile = getattr(user, 'userprofile', None)
    if not profile:
        return False

    is_client_user = profile.role == 'Client' and assessment.client == profile.client
    is_assessor_user = profile.role == 'Assessor' and assessment.assessor == user
    is_admin_user = profile.role == 'Admin'

    # Basic permission: Must be related client, assigned assessor, or admin
    has_basic_permission = is_client_user or is_assessor_user or is_admin_user
    if not has_basic_permission:
        return False

    # Specific action permissions (can be added later if needed, e.g., only proposer can delete 'Suggested')
    # For now, if user has basic permission and status allows, return True
    return True
class UpdateAssessmentDateStatusView(LoginRequiredMixin, View):
    """ Handles POST requests to update the status of an AssessmentDateOption """

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment.objects.select_related('assessor'), pk=self.kwargs['assessment_pk']) # Select assessor
        self.option = get_object_or_404(AssessmentDateOption, pk=self.kwargs['option_pk'], assessment=self.assessment)

    def post(self, request, *args, **kwargs):
        new_status = request.POST.get('new_status')
        user = request.user

        valid_statuses = [choice[0] for choice in AssessmentDateOption.Status.choices]
        if new_status not in valid_statuses:
            messages.error(request, "Invalid status provided.")
            return self.redirect_back()

        # Use the helper for permission check, but note it blocks if *any* date is confirmed.
        # We might need more granular checks depending on the action.
        if not user_can_manage_assessment_dates(user, self.assessment, self.option):
            # Check if the reason is simply that another date is already confirmed
            if AssessmentDateOption.objects.filter(assessment=self.assessment, status=AssessmentDateOption.Status.CONFIRMED).exists():
                 messages.warning(request, "An assessment date has already been confirmed. Status cannot be changed.")
            else:
                 messages.error(request, "You do not have permission to update the status of this date option at this time.")
            return self.redirect_back()

        original_status = self.option.status
        can_perform_action = False
        log_message = "" # Initialize log message

        # Role-based permissions
        if is_client(user):
            if new_status == AssessmentDateOption.Status.CLIENT_PREFERRED and original_status == AssessmentDateOption.Status.SUGGESTED:
                can_perform_action = True
        elif is_assessor(user) or is_admin(user):
            # --- Assessor/Admin Confirmation Logic ---
            if new_status == AssessmentDateOption.Status.CONFIRMED and original_status != AssessmentDateOption.Status.CONFIRMED and original_status != AssessmentDateOption.Status.REJECTED:
                # Check Assessor Availability
                if self.assessment.assessor and AssessorAvailability.objects.filter(assessor=self.assessment.assessor, unavailable_date=self.option.proposed_date).exists():
                    messages.error(request, f"Cannot confirm: Assessor ({self.assessment.assessor.username}) is unavailable on {self.option.proposed_date.strftime('%Y-%m-%d')}.")
                    return self.redirect_back()
                # Check CE+ Window
                if self.assessment.assessment_type == 'CE+' and self.assessment.date_ce_passed:
                    window_end_date = self.assessment.ce_plus_window_end_date
                    if not (self.assessment.date_ce_passed <= self.option.proposed_date <= window_end_date):
                        messages.error(request, f"Cannot confirm: Date is outside the CE+ window ({self.assessment.date_ce_passed.strftime('%Y-%m-%d')} to {window_end_date.strftime('%Y-%m-%d')}).")
                        return self.redirect_back()
                elif self.assessment.assessment_type == 'CE+' and not self.assessment.date_ce_passed:
                    messages.error(request, "Cannot confirm: CE+ assessment requires the CE Self-Assessment Pass Date to be set first.")
                    return self.redirect_back()

                can_perform_action = True # If all checks pass

            # --- Assessor/Admin Rejection Logic ---
            elif new_status == AssessmentDateOption.Status.REJECTED and original_status != AssessmentDateOption.Status.CONFIRMED and original_status != AssessmentDateOption.Status.REJECTED:
                can_perform_action = True

        if not can_perform_action:
            messages.error(request, f"Your role cannot change status from '{original_status}' to '{new_status}'.")
            return self.redirect_back()

        # --- Perform Update ---
        try:
            with transaction.atomic():
                self.option.status = new_status
                log_message = f"Assessment date option ({self.option.proposed_date.strftime('%Y-%m-%d')}) status changed to {self.option.get_status_display()}."

                if new_status == AssessmentDateOption.Status.CLIENT_PREFERRED:
                    AssessmentDateOption.objects.filter(
                        assessment=self.assessment, status=AssessmentDateOption.Status.CLIENT_PREFERRED
                    ).exclude(pk=self.option.pk).update(status=AssessmentDateOption.Status.SUGGESTED)
                    log_message += " Other preferences reset to 'Suggested'."

                if new_status == AssessmentDateOption.Status.CONFIRMED:
                    # 1. Update the Assessment's TARGET date (as requested)
                    self.assessment.date_target_end = self.option.proposed_date
                    # Also update date_start if it wasn't set or makes sense?
                    if not self.assessment.date_start:
                        self.assessment.date_start = self.option.proposed_date
                    self.assessment.save(update_fields=['date_target_end', 'date_start']) # Save updated date(s)

                    # 2. Reject other options
                    rejected_count = AssessmentDateOption.objects.filter(
                        assessment=self.assessment,
                        status__in=[AssessmentDateOption.Status.SUGGESTED, AssessmentDateOption.Status.CLIENT_PREFERRED]
                    ).exclude(pk=self.option.pk).update(status=AssessmentDateOption.Status.REJECTED)
                    log_message += f" Assessment Target End Date set. {rejected_count} other option(s) rejected."

                    # 3. Attempt to close the workflow step
                    # --- ADJUST 'Schedule Assessment Date' IF YOUR STEP NAME IS DIFFERENT ---
                    try:
                        schedule_step_def = WorkflowStepDefinition.objects.get(name='Schedule Assessment Date') # Find the definition
                        workflow_step = AssessmentWorkflowStep.objects.filter(
                            assessment=self.assessment,
                            step_definition=schedule_step_def
                        ).first()
                        if workflow_step and workflow_step.status != AssessmentWorkflowStep.Status.COMPLETE:
                            workflow_step.status = AssessmentWorkflowStep.Status.COMPLETE
                            workflow_step.completed_at = timezone.now()
                            workflow_step.completed_by = user
                            workflow_step.save()
                            log_message += f" Workflow step '{schedule_step_def.name}' marked complete."
                            logger.info(f"Workflow step '{schedule_step_def.name}' completed for assessment {self.assessment.pk}")
                        elif not workflow_step:
                            logger.warning(f"Could not find workflow step 'Schedule Assessment Date' for assessment {self.assessment.pk} to mark complete.")
                    except WorkflowStepDefinition.DoesNotExist:
                         logger.error("WorkflowStepDefinition 'Schedule Assessment Date' does not exist.")
                    except Exception as wf_err:
                         logger.error(f"Error updating workflow step for assessment {self.assessment.pk}: {wf_err}", exc_info=True)
                    # --- End Workflow Step Update ---

                # Save the option itself
                self.option.save()
                log_assessment_event(self.assessment, user, log_message) # Log the combined message
                messages.success(request, f"Date {self.option.proposed_date.strftime('%Y-%m-%d')} status updated to {self.option.get_status_display()}.")

        except Exception as e:
            logger.error(f"Error updating date option status for option {self.option.pk}: {e}", exc_info=True)
            messages.error(request, f"An unexpected error occurred: {e}")

        return self.redirect_back()

    def redirect_back(self):
        if is_client(self.request.user):
            return redirect('tracker:client_assessment_detail', pk=self.assessment.pk)
        else:
            return redirect('tracker:assessor_assessment_detail', pk=self.assessment.pk)
class DeleteAssessmentDateOptionView(LoginRequiredMixin, View):
    """ Handles POST requests to delete an AssessmentDateOption """
    # Keep the previous implementation, but ensure the permission check is appropriate
    # (user_can_manage_assessment_dates might be too strict if it blocks based on confirmation status)

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        self.option = get_object_or_404(AssessmentDateOption, pk=self.kwargs['option_pk'], assessment=self.assessment)

    def post(self, request, *args, **kwargs):
        user = request.user

        # Simpler Permission Check for Deletion:
        # Allow deletion if status allows management overall OR if user is admin trying to delete non-confirmed
        can_delete = False
        profile = getattr(user, 'userprofile', None)
        is_before_testing = self.assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']

        if self.option.status == AssessmentDateOption.Status.CONFIRMED:
            messages.error(request, "Confirmed dates cannot be deleted via this interface.")
        elif is_before_testing: # Only allow deletion before testing starts
            if self.option.status == AssessmentDateOption.Status.SUGGESTED:
                # Allow proposer or assessor/admin
                if (self.option.proposed_by == user) or (profile and profile.role in ['Admin', 'Assessor']):
                    can_delete = True
            elif self.option.status in [AssessmentDateOption.Status.CLIENT_PREFERRED, AssessmentDateOption.Status.REJECTED]:
                 # Allow assessor/admin
                if profile and profile.role in ['Admin', 'Assessor']:
                    can_delete = True

        if not can_delete:
             messages.error(request, "You do not have permission to delete this date option at this time.")
             return self.redirect_back()

        # Perform Deletion
        try:
            date_str = self.option.proposed_date.strftime('%Y-%m-%d')
            status_str = self.option.get_status_display()
            self.option.delete()
            log_assessment_event(self.assessment, user, f"Assessment date option ({date_str}, Status: {status_str}) deleted.")
            messages.success(request, f"Date option {date_str} deleted successfully.")
        except Exception as e:
            logger.error(f"Error deleting date option {self.option.pk}: {e}", exc_info=True)
            messages.error(request, f"An unexpected error occurred while deleting: {e}")

        return self.redirect_back()

    def redirect_back(self):
        if is_client(self.request.user):
            return redirect('tracker:client_assessment_detail', pk=self.assessment.pk)
        else:
            return redirect('tracker:assessor_assessment_detail', pk=self.assessment.pk)
class ProposeAssessmentDateView(LoginRequiredMixin, CreateView):
    model = AssessmentDateOption
    form_class = AssessmentDateOptionForm

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        # REMOVED permission check based on assessment status/confirmation
        # Basic login check is handled by LoginRequiredMixin
        profile = getattr(request.user, 'userprofile', None)
        if not profile or profile.role not in ['Admin', 'Assessor', 'Client']:
             raise PermissionDenied("Invalid user role.")
        if profile.role == 'Client' and self.assessment.client != profile.client:
             raise PermissionDenied("Client mismatch.")
        # Assessors/Admins can propose for any assessment they can access

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['assessment'] = self.assessment
        return kwargs

    def form_valid(self, form):
        logger.debug(f"ProposeAssessmentDateView: form_valid entered for assessment {self.assessment.pk} by user {self.request.user.username}") # DEBUG log
        form.instance.assessment = self.assessment
        form.instance.proposed_by = self.request.user
        try:
            # Save the object first to get an ID
            self.object = form.save()
            logger.info(f"AssessmentDateOption {self.object.pk} created for assessment {self.assessment.pk} with date {self.object.proposed_date}") # INFO log

            log_assessment_event(
                self.assessment,
                self.request.user,
                f"Proposed assessment date: {self.object.proposed_date.strftime('%Y-%m-%d')}"
                 + (f". Notes: {form.cleaned_data.get('notes')}" if form.cleaned_data.get('notes') else ".")
            )
            messages.success(self.request, f"Date {self.object.proposed_date.strftime('%Y-%m-%d')} proposed successfully.")
        except IntegrityError:
            logger.warning(f"IntegrityError: Date {form.cleaned_data.get('proposed_date')} already proposed for assessment {self.assessment.pk}.") # WARN log
            messages.error(self.request, f"The date {form.cleaned_data.get('proposed_date').strftime('%Y-%m-%d')} has already been proposed.")
            # Need to redirect back WITH the form errors shown in the template
            # Re-rendering the detail view with the invalid form is tricky here.
            # Redirecting and showing message is simpler for now.
            return HttpResponseRedirect(self.get_success_url())
        except Exception as e:
            logger.error(f"Error saving proposed date for assessment {self.assessment.pk}: {e}", exc_info=True) # ERROR log
            messages.error(self.request, f"An unexpected error occurred: {e}")
            return HttpResponseRedirect(self.get_success_url())

        logger.debug(f"ProposeAssessmentDateView: form_valid completed successfully.") # DEBUG log
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        logger.warning(f"ProposeAssessmentDateView: form_invalid for assessment {self.assessment.pk}. Errors: {form.errors.as_json()}") # WARN log
        # Pass errors via messages
        for field, errors in form.errors.items():
            for error in errors:
                 field_name_display = form.fields[field].label if field != '__all__' and field in form.fields else 'Proposal Error'
                 messages.error(self.request, f"{field_name_display}: {error}")
        # Redirect back to detail page, messages will be displayed
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        if is_client(self.request.user):
            return reverse('tracker:client_assessment_detail', kwargs={'pk': self.assessment.pk})
        else:
            return reverse('tracker:assessor_assessment_detail', kwargs={'pk': self.assessment.pk})
class MapAgentsView(LoginRequiredMixin, View):
    template_name = 'tracker/map_agents.html'

    def get_assessment(self, assessment_pk: int) -> Assessment:
        """ Helper to get assessment and check object-level permissions.
            Raises PermissionDenied or Http404 on failure.
            Returns the assessment object if successful.
        """
        print(f"[DEBUG MapAgentsView.get_assessment {assessment_pk}] Checking permissions for user {self.request.user.username}")

        # Fetch assessment first
        try:
            assessment = get_object_or_404(Assessment.objects.select_related('client', 'assessor'), pk=assessment_pk)
        except Http404:
            logger.warning(f"[MapAgentsView get_assessment {assessment_pk}] Assessment not found.")
            raise # Re-raise Http404

        user = self.request.user
        profile = getattr(user, 'userprofile', None)

        # Perform permission checks
        allowed = False
        is_adm = is_admin(user)
        is_ass = is_assessor(user)
        is_cli = is_client(user)
        print(f"[DEBUG MapAgentsView.get_assessment {assessment_pk}] Roles: Admin={is_adm}, Assessor={is_ass}, Client={is_cli}")

        if is_adm: allowed = True
        elif is_ass and assessment.assessor == user: allowed = True
        elif is_cli and profile and assessment.client == profile.client: allowed = True

        print(f"[DEBUG MapAgentsView.get_assessment {assessment_pk}] Ownership/Assignment Check Passed: {allowed}")

        if not allowed:
             logger.warning(f"[MapAgentsView get_assessment {assessment_pk}] User {user.username} permission denied (Role/Ownership mismatch).")
             raise PermissionDenied("You do not have permission for this specific assessment.")

        if assessment.assessment_type != 'CE+':
            logger.warning(f"[MapAgentsView get_assessment {assessment_pk}] Attempt to map agents for non-CE+ assessment")
            raise PermissionDenied("Agent mapping is only applicable for CE+ assessments.")

        print(f"[DEBUG MapAgentsView.get_assessment {assessment_pk}] Permissions checks passed.")
        return assessment

    # --- GET Request Handler ---
    def get(self, request, *args, **kwargs):
        assessment_pk = self.kwargs.get('assessment_pk')
        print(f"[DEBUG MapAgentsView.get {assessment_pk}] Handling GET request by user {request.user.username}")

        try:
            assessment = self.get_assessment(assessment_pk)
            self.assessment = assessment
        except PermissionDenied as e:
            messages.error(request, str(e))
            # Role-based redirect handled in handle_no_permission
            return self.handle_no_permission()
        except Http404:
             messages.error(request, "Assessment not found.")
             return self.handle_no_permission() # Use central handler for redirect

        # --- If permissions pass, continue with GET logic ---
        print(f"[DEBUG MapAgentsView.get {assessment_pk}] Permissions OK, fetching data...")
        sampled_items = ScopedItem.objects.filter(
            assessment=assessment, is_in_ce_plus_sample=True
        ).select_related('operating_system', 'network').order_by('item_type', 'identifier')

        if not sampled_items.exists():
             print(f"[DEBUG MapAgentsView.get {assessment_pk}] No sample items found, redirecting.")
             logger.info(f"[MapAgentsView GET {assessment_pk}] No sample items found, redirecting.") # Keep info log
             messages.info(request, "No items currently selected in the CE+ sample for this assessment.")
             profile = getattr(request.user, 'userprofile', None)
             detail_url_name = 'tracker:client_assessment_detail' if profile and profile.role == 'Client' else 'tracker:assessor_assessment_detail'
             return redirect(detail_url_name, pk=assessment.pk)

        # Fetch available agents from Tenable.io
        available_agents = []
        tenable_error = None
        tio = get_tenable_io_client()
        if not tio:
            tenable_error = "Could not connect to Tenable.io. Check API configuration."
            logger.error(f"[MapAgentsView GET {assessment_pk}] {tenable_error}") # Keep error log
        elif not assessment.client:
            tenable_error = "Assessment is not linked to a client. Cannot determine agent group."
            logger.error(f"[MapAgentsView GET {assessment_pk}] {tenable_error}") # Keep error log
        else:
            agent_group_name = assessment.client.name
            agent_group_id = None
            try:
                print(f"[DEBUG MapAgentsView.get {assessment_pk}] Searching Tenable group '{agent_group_name}'")
                agent_groups = tio.agent_groups.list()
                for group in agent_groups:
                    if group['name'] == agent_group_name:
                        agent_group_id = group.get('id')
                        break
                if not agent_group_id:
                    logger.warning(f"[MapAgentsView GET {assessment_pk}] Tenable group '{agent_group_name}' not found.") # Keep warning log
                    tenable_error = f"Tenable agent group '{agent_group_name}' not found. Ensure client name matches group name and sync task has run."
                else:
                    print(f"[DEBUG MapAgentsView.get {assessment_pk}] Found group {agent_group_id}. Fetching agents.")
                    all_agents_iterator = tio.agents.list(limit=2000)

                    processed_agent_count = 0
                    for agent_data in all_agents_iterator:
                        processed_agent_count += 1
                        agent_groups_list = agent_data.get('groups', [])
                        if isinstance(agent_groups_list, list) and any(ag.get('id') == agent_group_id for ag in agent_groups_list):
                            agent_uuid = agent_data.get('uuid')
                            agent_id_fallback = agent_data.get('id')

                            print(f"[DEBUG MapAgentsView.get {assessment_pk}] Processing agent data: Name='{agent_data.get('name')}', Found UUID='{agent_uuid}', Found ID='{agent_id_fallback}'")

                            final_id_for_list = agent_uuid
                            if not final_id_for_list:
                                final_id_for_list = agent_id_fallback
                                if final_id_for_list:
                                     logger.warning(f"[MapAgentsView GET {assessment_pk}] Agent '{agent_data.get('name')}' missing 'uuid' field, falling back to 'id': {agent_id_fallback}") # Keep warning log
                                else:
                                     logger.error(f"[MapAgentsView GET {assessment_pk}] Agent data missing both 'uuid' and 'id' field. Skipping agent: {agent_data}") # Keep error log
                                     continue

                            agent_name = agent_data.get('name')
                            if final_id_for_list and agent_name:
                                available_agents.append({
                                    'uuid': final_id_for_list,
                                    'name': agent_name,
                                    'status': agent_data.get('status', 'unknown').lower(),
                                    'platform': agent_data.get('platform', 'unknown')
                                })
                            else:
                                 logger.warning(f"[MapAgentsView GET {assessment_pk}] Skipping agent due to missing final_id or name. Data: {agent_data}") # Keep warning log

                    available_agents.sort(key=lambda x: x['name'].lower())
                    print(f"[DEBUG MapAgentsView.get {assessment_pk}] Processed {processed_agent_count} agents API. Added {len(available_agents)} agents from group '{agent_group_name}' to dropdown.")

            except (APIError, ForbiddenError) as e:
                 logger.exception(f"[MapAgentsView GET {assessment_pk}] Error fetching Tenable groups/agents: {e}") # Keep exception log
                 tenable_error = f"Error communicating with Tenable.io: {e}"
            except Exception as e:
                 logger.exception(f"[MapAgentsView GET {assessment_pk}] Unexpected error fetching Tenable data: {e}") # Keep exception log
                 tenable_error = "An unexpected error occurred while fetching Tenable data."

        # Prepare data structure for template
        mapping_data = []
        agents_by_name_lower = {agent['name'].lower(): agent for agent in available_agents} if available_agents else {}
        for item in sampled_items:
            preselected_uuid = item.linked_tenable_agent_uuid
            suggested_agent = None
            if not preselected_uuid and item.identifier:
                suggested_agent = agents_by_name_lower.get(item.identifier.lower())
            mapping_data.append({
                'item': item,
                'preselected_uuid': preselected_uuid,
                'suggested_agent': suggested_agent
            })

        context = {
            'assessment': assessment,
            'mapping_data': mapping_data,
            'available_agents': available_agents,
            'tenable_error': tenable_error,
            'no_sample_items': not sampled_items.exists()
        }
        print(f"[DEBUG MapAgentsView.get {assessment_pk}] Rendering template {self.template_name}")
        return render(request, self.template_name, context)


    # --- POST Request Handler ---
    def post(self, request, *args, **kwargs):
        assessment_pk = self.kwargs.get('assessment_pk')
        print(f"[DEBUG MapAgentsView.post {assessment_pk}] Handling POST request by user {request.user.username}")

        try:
            assessment = self.get_assessment(assessment_pk)
            self.assessment = assessment
        except PermissionDenied as e:
            messages.error(request, str(e))
            return self.handle_no_permission()
        except Http404:
             messages.error(request, "Assessment not found.")
             return self.handle_no_permission()

        # --- If permissions pass, continue with POST logic ---
        print(f"[DEBUG MapAgentsView.post {assessment_pk}] Permissions OK, processing form data.")
        items_updated = 0
        items_processed = 0
        # Flag to indicate if any validation error occurred for user feedback
        validation_errors_occurred = False
        try:
            with transaction.atomic():
                post_data_items = list(request.POST.items())
                print(f"[DEBUG MapAgentsView.post {assessment_pk}] Processing {len(post_data_items)} items in POST data.")

                for key, selected_agent_uuid_str in post_data_items:
                     if key.startswith('map_item_'):
                        items_processed += 1
                        item_pk_str = item_pk = None
                        try:
                            item_pk_str = key.split('_')[-1]
                            item_pk = int(item_pk_str)
                            print(f"[DEBUG MapAgentsView.post {assessment_pk}] Processing item PK: {item_pk}")

                            item_to_update = get_object_or_404(
                                ScopedItem, pk=item_pk, assessment=assessment, is_in_ce_plus_sample=True
                            )
                            current_uuid = item_to_update.linked_tenable_agent_uuid
                            print(f"[DEBUG MapAgentsView.post {assessment_pk}] Found item {item_pk}. Current linked UUID: {current_uuid}")

                            print(f"[DEBUG MapAgentsView.post {assessment_pk}] Raw value for key '{key}': '{selected_agent_uuid_str}' (Type: {type(selected_agent_uuid_str)})")

                            agent_uuid_to_save = None if selected_agent_uuid_str == "" else selected_agent_uuid_str
                            print(f"[DEBUG MapAgentsView.post {assessment_pk}] Form value received (UUID to save): {agent_uuid_to_save}")

                            current_uuid_str = str(current_uuid) if current_uuid else None
                            agent_uuid_to_save_str = str(agent_uuid_to_save) if agent_uuid_to_save else None

                            if current_uuid_str != agent_uuid_to_save_str:
                                print(f"[DEBUG MapAgentsView.post {assessment_pk}] Change detected! Attempting to save UUID '{agent_uuid_to_save}' for item {item_pk}.")
                                try:
                                     item_to_update.linked_tenable_agent_uuid = agent_uuid_to_save
                                     item_to_update.full_clean(validate_unique=False)
                                     item_to_update.save(update_fields=['linked_tenable_agent_uuid'])
                                     items_updated += 1
                                     print(f"[DEBUG MapAgentsView.post {assessment_pk}] Item {item_pk} SAVE successful.")
                                except ValidationError as ve:
                                     validation_errors_occurred = True # Set flag
                                     logger.error(f"[MapAgentsView POST {assessment_pk}] ValidationError saving item {item_pk} with value '{agent_uuid_to_save}': {ve}", exc_info=True) # Keep error log
                                     # Add specific message for this item
                                     messages.error(request, f"Failed to save link for item PK {item_pk}: Invalid value '{agent_uuid_to_save}'. Please select a valid agent.")
                                except Exception as save_err:
                                    validation_errors_occurred = True # Set flag
                                    logger.error(f"[MapAgentsView POST {assessment_pk}] Error saving item {item_pk} with value '{agent_uuid_to_save}': {save_err}", exc_info=True) # Keep error log
                                    messages.error(request, f"An error occurred saving the link for item {item_pk}: {save_err}")
                                    # Consider rollback: transaction.set_rollback(True)

                            else:
                                print(f"[DEBUG MapAgentsView.post {assessment_pk}] No change detected for item {item_pk}. Skipping save.")

                        except (ValueError, TypeError):
                             logger.warning(f"[MapAgentsView POST {assessment_pk}] Could not parse item PK from POST key: {key}", exc_info=True) # Keep warning log
                             messages.warning(request, f"Skipped processing due to invalid key format: {key}")
                        except ScopedItem.DoesNotExist:
                             logger.warning(f"[MapAgentsView POST {assessment_pk}] ScopedItem PK {item_pk_str} not found or not in sample.")
                        except MultipleObjectsReturned:
                             logger.error(f"[MapAgentsView POST {assessment_pk}] Multiple ScopedItems found for PK {item_pk_str}.") # Keep error log
                             messages.error(request, f"Configuration error: Multiple items found for PK {item_pk_str}.")

            # --- Transaction finished ---
            log_message = f"Processed agent mapping: {items_updated} item link(s) updated out of {items_processed} sample items processed."
            # Only log success if no validation errors occurred during the loop
            if not validation_errors_occurred:
                 messages.success(request, f"Agent mapping saved successfully. {items_updated} link(s) updated.")
            else:
                 # Give a summary message indicating partial success / issues
                 messages.warning(request, f"Agent mapping processed. {items_updated} link(s) updated, but some errors occurred (see details above).")

            log_assessment_event(assessment, request.user, log_message)
            logger.info(f"[MapAgentsView POST {assessment.pk}] {log_message}") # Keep info log
            print(f"[DEBUG MapAgentsView.post {assessment_pk}] Mapping process finished. Updated: {items_updated}, Processed: {items_processed}, ValidationErrors: {validation_errors_occurred}")

        except Exception as e: # Catch errors during the overall transaction/loop
            logger.exception(f"[MapAgentsView POST {assessment.pk}] Error saving agent mappings during transaction: {e}") # Keep exception log
            print(f"[DEBUG MapAgentsView.post {assessment_pk}] CRITICAL ERROR saving mappings: {e}")
            messages.error(request, f"An unexpected critical error occurred while saving mappings: {e}")

        # --- Redirect based on user role ---
        profile = getattr(request.user, 'userprofile', None)
        detail_url_name = 'tracker:client_assessment_detail' if profile and profile.role == 'Client' else 'tracker:assessor_assessment_detail'
        print(f"[DEBUG MapAgentsView.post {assessment_pk}] Redirecting to {detail_url_name}")
        return redirect(detail_url_name, pk=assessment.pk)

    def handle_no_permission(self):
        """ Redirect users based on role if they fail permission checks. """
        messages.error(self.request, "You do not have permission to access the agent mapping page for this assessment.")
        profile = getattr(self.request.user, 'userprofile', None)
        if profile:
            if profile.role == 'Client':
                return redirect('tracker:client_dashboard')
            elif profile.role == 'Assessor':
                assessment_pk = self.kwargs.get('assessment_pk')
                if assessment_pk:
                    try: return redirect('tracker:assessor_assessment_detail', pk=assessment_pk)
                    except Exception: pass
                return redirect('tracker:assessor_dashboard')
        return redirect('tracker:admin_dashboard')

@staff_member_required
def tenable_policy_template_list_view(request):
    """
    Admin view to list Tenable scan policies (showing integer ID for scan creation)
    and standard templates (showing UUID for info).
    """
    policies_list = [] # For configured policies with integer IDs
    templates_list = [] # For standard templates with UUIDs
    error_message = None
    tio = get_tenable_io_client()

    if not tio:
        error_message = "Could not initialize connection to Tenable.io. Check API keys/URL in Constance settings."
        logger.error(f"[Admin Policy View] {error_message}")
    else:
        processed_policy_ids = set() # Track processed integer IDs to avoid duplicates

        # --- Step 1: Get Configured Policies ---
        try:
            print("[DEBUG Admin Policy View] Attempting: tio.policies.list()")
            policies_raw = tio.policies.list()
            print(f"[DEBUG Admin Policy View] tio.policies.list() returned type: {type(policies_raw)}")

            if isinstance(policies_raw, list):
                print(f"[DEBUG Admin Policy View] Processing {len(policies_raw)} configured policies...")
                for index, item in enumerate(policies_raw):
                    if isinstance(item, dict):
                        name = item.get('name')
                        # CHANGES BEGIN: Get the integer 'id' field primarily
                        policy_id = item.get('id')
                        template_uuid_val = item.get('template_uuid') # Still get template UUID for info

                        if name and policy_id is not None: # Check if 'id' exists
                            try:
                                policy_id_int = int(policy_id) # Ensure it's an integer
                                if policy_id_int not in processed_policy_ids:
                                    item_data = {
                                        'name': name,
                                        'policy_id': policy_id_int, # Store the integer ID
                                        'template_uuid': template_uuid_val or 'N/A', # Store template UUID if available
                                        'description': item.get('description', ''),
                                        'type': 'Configured Policy'
                                    }
                                    policies_list.append(item_data)
                                    processed_policy_ids.add(policy_id_int)
                                else:
                                    print(f"[DEBUG Admin Policy View] Duplicate Policy ID {policy_id_int} found in policies.list(). Skipping.")
                            except (ValueError, TypeError):
                                 # Log if 'id' is present but not an integer
                                 print(f"[DEBUG Admin Policy View] Policy ID '{policy_id}' for policy '{name}' is not an integer. Skipping.")
                        # CHANGES END
                        else:
                            print(f"[DEBUG Admin Policy View] Configured policy at index {index} missing 'name' or 'id': {str(item)}. Skipping.")
                    else:
                         print(f"[DEBUG Admin Policy View] Item in policies list at index {index} is not a dict: Type={type(item)}. Skipping.")
            else:
                print(f"[DEBUG Admin Policy View] tio.policies.list() did not return a list.")

        except Exception as e:
            logger.exception(f"[Admin Policy View] Error fetching or processing tio.policies.list(): {e}")
            print(f"[DEBUG Admin Policy View] Error fetching/processing configured policies: {e}")
            if not error_message: error_message = "Error retrieving configured policies from Tenable."

        # --- Step 2: Get Standard Templates (Informational) ---
        try:
            print("[DEBUG Admin Policy View] Attempting: tio.policies.templates()")
            templates_raw_dict = tio.policies.templates()
            print(f"[DEBUG Admin Policy View] tio.policies.templates() returned type: {type(templates_raw_dict)}")

            if isinstance(templates_raw_dict, dict):
                 print(f"[DEBUG Admin Policy View] Processing {len(templates_raw_dict)} standard templates...")
                 for name, uuid_val in templates_raw_dict.items():
                     if isinstance(name, str) and isinstance(uuid_val, str) and len(uuid_val) > 10: # Basic validation
                         templates_list.append({
                             'name': name.replace('_', ' ').title(),
                             'template_uuid': uuid_val, # Templates only have UUIDs
                             'description': 'Standard Template - Cannot be used directly for scan creation.',
                             'type': 'Standard Template'
                         })
                     else:
                          print(f"[DEBUG Admin Policy View] Invalid format in templates dict: Key={name}, Value={uuid_val}. Skipping.")
            else:
                 print(f"[DEBUG Admin Policy View] tio.policies.templates() did not return a dict.")

        except Exception as e:
            logger.exception(f"[Admin Policy View] Error fetching or processing tio.policies.templates(): {e}")
            print(f"[DEBUG Admin Policy View] Error fetching/processing standard templates: {e}")
            if not error_message: error_message = "Error retrieving standard policy templates from Tenable."

        # --- Step 3: Sort the lists ---
        if policies_list:
            try:
                policies_list.sort(key=lambda x: x.get('name', '').lower())
                print(f"[DEBUG Admin Policy View] Successfully processed and sorted {len(policies_list)} configured policies.")
                logger.info(f"[Admin Policy View] Successfully processed {len(policies_list)} configured policies.")
            except Exception as sort_err:
                 logger.exception(f"[Admin Policy View] Error during policy sorting phase: {sort_err}")
                 error_message = "An error occurred while sorting the policy data."
        if templates_list:
             try:
                templates_list.sort(key=lambda x: x.get('name', '').lower())
             except Exception: pass # Ignore template sorting errors


    # --- Stage 4: Context and Rendering ---
    context = {
        **admin.site.each_context(request),
        'title': 'Tenable Scan Policies & Templates',
        'policies': policies_list, # Pass the policy list with integer IDs
        'templates': templates_list, # Pass the template list separately
        'error_message': error_message,
        'has_permission': True, # Assuming staff_member_required handles this
        'opts': {'app_label': 'tracker'}, # Needed for admin template context
    }
    # Template path remains the same
    return render(request, 'tracker/admin/tenable_policy_list.html', context)

@staff_member_required
def tenable_scanner_list_view(request):
    """Admin view to list available Tenable scanners and scanner groups."""
    scanners_list = []
    error_message = None
    tio = get_tenable_io_client()

    if not tio:
        error_message = "Could not initialize connection to Tenable.io..."
        logger.error(f"[Admin Scanner View] {error_message}")
    else:
        scanners_raw = None
        api_call_successful = False
        try:
            # Use tio.scanners.list() to get scanners and groups
            print("[DEBUG Admin Scanner View] Attempting: tio.scanners.list()")
            scanners_raw = tio.scanners.list()
            api_call_successful = True
            print(f"[DEBUG Admin Scanner View] SUCCESS: tio.scanners.list() returned type: {type(scanners_raw)}")

        except APIError as e:
            logger.exception(f"[Admin Scanner View] Tenable API Error listing scanners: {e}")
            error_message = f"API Error listing scanners: {e}. Check Tenable connection and permissions."
        except ForbiddenError:
             logger.exception("[Admin Scanner View] Permission denied listing scanners in Tenable.")
             error_message = "Permission denied listing scanners. Check API key permissions."
        except Exception as e:
             logger.exception(f"[Admin Scanner View] Unexpected error calling tio.scanners.list(): {e}")
             error_message = f"An unexpected error occurred during API call: {e}"

        # --- Process Data ---
        if api_call_successful:
            if not isinstance(scanners_raw, list):
                log_msg = f"[Admin Scanner View] API call succeeded but returned non-list data: Type={type(scanners_raw)}, Value='{str(scanners_raw)[:500]}'." # noqa E501
                logger.error(log_msg)
                print(f"[DEBUG] {log_msg}")
                if not error_message:
                    error_message = "Received unexpected data format from Tenable API (expected list for scanners)."
                scanners_to_process = []
            else:
                scanners_to_process = scanners_raw
                print(f"[DEBUG Admin Scanner View] API call returned a list. Item count: {len(scanners_to_process)}. Processing...")

            # Filter for dictionaries with expected keys ('name', 'uuid', 'status')
            valid_items = []
            if scanners_to_process:
                for index, item in enumerate(scanners_to_process):
                    if isinstance(item, dict):
                        # Expect 'name', 'uuid', 'status', 'type' (e.g., 'cloud', 'managed')
                        name = item.get('name')
                        uuid_val = item.get('uuid')
                        if name and uuid_val:
                            item_data = {
                                'name': name,
                                'uuid': uuid_val,
                                'status': item.get('status', 'unknown'),
                                'type': item.get('type', 'unknown'),
                            }
                            valid_items.append(item_data)
                        else:
                            log_msg = f"[Admin Scanner View] Scanner dict at index {index} missing 'name' or 'uuid': {str(item)}. Skipping." # noqa E501
                            logger.warning(log_msg)
                            print(f"[DEBUG] {log_msg}")
                    else:
                        log_msg = f"[Admin Scanner View] Item in scanners list at index {index} is not a dict: Type={type(item)}, Value='{str(item)[:100]}'. Skipping." # noqa E501
                        logger.warning(log_msg)
                        print(f"[DEBUG] {log_msg}")

            # Sort the valid items by name
            if valid_items:
                try:
                    scanners_list = sorted(valid_items, key=lambda x: x.get('name', '').lower())
                    print(f"[DEBUG Admin Scanner View] Successfully processed and sorted {len(scanners_list)} scanners.")
                    logger.info(f"[Admin Scanner View] Successfully processed {len(scanners_list)} scanners.")
                except Exception as sort_err:
                    logger.exception(f"[Admin Scanner View] Error during sorting phase: {sort_err}")
                    print(f"[DEBUG Admin Scanner View] ERROR during sorting: {sort_err}")
                    error_message = "An error occurred while sorting the scanner data."
                    scanners_list = valid_items # Show unsorted
            else:
                 print("[DEBUG Admin Scanner View] No valid scanner items found after filtering.")
                 scanners_list = []

    # --- Context and Rendering ---
    context = {
        **admin.site.each_context(request),
        'title': 'Tenable Scanners & Groups', # Updated title
        'scanners': scanners_list, # Use 'scanners' key for clarity
        'error_message': error_message,
        'has_permission': True,
        'opts': {'app_label': 'tracker'},
    }
    # Use a new template file name
    return render(request, 'tracker/admin/tenable_scanner_list.html', context)
def get_tenable_scan_status_ajax(request, assessment_id):
    # Basic permission check (enhance as needed for your roles)
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Authentication required.'}, status=401)

    assessment = get_object_or_404(Assessment, pk=assessment_id)

    # Add more granular permission checks if necessary, e.g.,
    # if not request.user.is_staff and assessment.assessor != request.user and assessment.client.user_profile.user != request.user:
    #     return JsonResponse({'error': 'Permission denied.'}, status=403)

    scan_id_to_query = assessment.tenable_scan_id

    if not scan_id_to_query:
        return JsonResponse({
            'status': assessment.scan_status,
            'status_display': assessment.get_scan_status_display(),
            'message': assessment.scan_status_message or "No Tenable scan is currently linked to this assessment.",
            'progress': 0,
            'raw_tenable_status': 'not_linked',
            'can_launch': True # Can attempt to launch if not linked
        })

    logger.debug(f"AJAX poll: Fetching Tenable status for scan ID {scan_id_to_query} (Assessment {assessment_id})")
    tenable_scan_details = get_scan_details_by_uuid_or_id(scan_id_to_query)

    if tenable_scan_details:
        raw_tenable_status = tenable_scan_details.get('status') # Common place for status
        if not raw_tenable_status and 'info' in tenable_scan_details: # Some scans nest it
            raw_tenable_status = tenable_scan_details['info'].get('status')

        # --- Update local assessment status based on Tenable's report ---
        # This logic can be refined to be more comprehensive
        current_local_status = assessment.scan_status
        new_local_status = current_local_status
        status_message = assessment.scan_status_message # Keep existing unless overridden

        if raw_tenable_status == 'completed':
            if current_local_status not in [Assessment.SCAN_COMPLETED, Assessment.SCAN_PROCESSING, Assessment.SCAN_IMPORTED]:
                new_local_status = Assessment.SCAN_COMPLETED
                status_message = "Scan completed by Tenable. Ready for result processing."
        elif raw_tenable_status == 'running':
            if current_local_status != Assessment.SCAN_LAUNCHED: # Assuming LAUNCHED implies it could be running
                new_local_status = Assessment.SCAN_LAUNCHED
            status_message = "Scan is actively running in Tenable."
        elif raw_tenable_status in ['canceled', 'aborted', 'stopped', 'error']: # 'error' is a guess, check API docs
            if current_local_status != Assessment.SCAN_ERROR:
                new_local_status = Assessment.SCAN_ERROR
                status_message = f"Scan in Tenable ended with status: {raw_tenable_status}."
        elif raw_tenable_status == 'pending': # Or 'queued', 'pending launch' etc.
            if current_local_status != Assessment.SCAN_PENDING: # If you have SCAN_PENDING
                new_local_status = Assessment.SCAN_PENDING
            status_message = "Scan is pending/queued in Tenable."
        # Add other status mappings as needed (e.g., 'paused')

        if new_local_status != current_local_status or status_message != assessment.scan_status_message:
            assessment.scan_status = new_local_status
            assessment.scan_status_message = status_message
            assessment.save()
        # --- End local status update ---

        progress = 0 # Agent scans don't usually provide granular progress via this API
        can_launch_new_scan = True # Default

        if raw_tenable_status == 'running':
            progress = 50 # Arbitrary visual cue for "in progress"
            can_launch_new_scan = False
        elif raw_tenable_status == 'completed':
            progress = 100
            can_launch_new_scan = True # Can re-launch a completed scan
        elif raw_tenable_status in ['pending', 'queued', 'paused']: # Check exact Tenable terms
            progress = 25 # Arbitrary
            can_launch_new_scan = False
        elif raw_tenable_status in ['canceled', 'aborted', 'error']:
            progress = 0
            can_launch_new_scan = True # Can try again if it errored

        return JsonResponse({
            'status': assessment.scan_status, # Return our (potentially updated) local status
            'status_display': assessment.get_scan_status_display(),
            'message': assessment.scan_status_message,
            'progress': progress,
            'raw_tenable_status': raw_tenable_status or 'unknown',
            'can_launch': can_launch_new_scan,
            'last_modified_tenable': tenable_scan_details.get('last_modification_date') # Unix timestamp
        })
    else:
        # Failed to get details from Tenable (scan might be deleted, or API error)
        logger.warning(f"AJAX poll: Could not retrieve details for scan ID {scan_id_to_query} from Tenable.")
        # Potentially update local status to error if scan consistently not found
        # For now, return current local status to avoid rapid changes on transient errors
        return JsonResponse({
            'status': assessment.scan_status,
            'status_display': assessment.get_scan_status_display(),
            'message': assessment.scan_status_message or "Could not fetch live status from Tenable at this moment.",
            'progress': 0,
            'raw_tenable_status': 'error_fetching',
            'can_launch': True # Default to allow launch if status is uncertain
        })

@login_required # Ensure the user is logged in, add more specific permissions as needed
def launch_tenable_scan_trigger_view(request, assessment_id: int):
    """
    View to trigger the Celery task for launching a Tenable scan for a given assessment.
    This view is typically called by a button press via a POST request.
    """
    assessment = get_object_or_404(Assessment, pk=assessment_id)

    # Optional: Add more specific permission checks here if needed
    # e.g., check if request.user is the client contact or an assessor for this assessment.
    # For example:
    # if not (request.user.is_staff or assessment.client.user_profile.user == request.user):
    #     messages.error(request, "You do not have permission to launch this scan.")
    #     # Redirect to a safe page, e.g., the assessment detail page itself
    #     return redirect(reverse('tracker:client_assessment_detail', args=[assessment.id]))


    if request.method == 'POST':
        logger.info(f"User {request.user} manually triggered Tenable scan launch for Assessment ID: {assessment_id} via web UI.")
        # Call the Celery task asynchronously
        launch_tenable_scan_task.delay(assessment_id)
        messages.success(request, f"Tenable scan launch process initiated for Assessment {assessment.id}. The status will update automatically on this page.")
    else:
        # This view should ideally only be accessed via POST from the form
        messages.warning(request, "Invalid request method to launch scan. Please use the button.")

    # Redirect back to the assessment detail page the user was on.
    # The error occurred in ClientAssessmentDetailView for URL /client/assessments/14/
    # So, we assume the URL name for that view is 'client_assessment_detail'
    # and it takes the assessment_id (or pk) as an argument.
    # Adjust if your URL pattern for ClientAssessmentDetailView is different.
    try:
        # Attempt to redirect back to the client assessment detail view
        # This assumes your ClientAssessmentDetailView URL pattern is named 'client_assessment_detail'
        # and takes the assessment's pk as an argument.
        redirect_url = reverse('tracker:client_assessment_detail', kwargs={'pk': assessment_id})
    except Exception: # Catch NoReverseMatch if the name or args are different
        logger.warning(f"Could not reverse 'tracker:client_assessment_detail' for assessment {assessment_id}. Falling back.")
        # Fallback redirect - adjust to a sensible default if the above fails
        # For example, to the client's dashboard or a general assessment list
        if hasattr(assessment.client, 'get_absolute_url'):
            redirect_url = assessment.client.get_absolute_url()
        elif hasattr(request.user, 'get_absolute_url'): # e.g. user profile / dashboard
             redirect_url = request.user.get_absolute_url()
        else: # Absolute fallback
            redirect_url = reverse('tracker:client_dashboard') # Assuming you have a client_dashboard URL

    return redirect(redirect_url)

from django.shortcuts import redirect # Add redirect if not already there
from django.urls import reverse # Add reverse if not already there
from django.contrib.auth.decorators import login_required

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
class ClientWorkflowVisualPartialView(ClientRequiredMixin, DetailView):
    """ Renders just the workflow visual partial for AJAX updates. """
    model = Assessment
    template_name = 'tracker/partials/client_workflow_visual.html' # Render only the partial
    context_object_name = 'assessment' # The partial expects 'assessment'

    def get_queryset(self):
        """ Ensure client can only access their own assessment's visual """
        # Note: ClientRequiredMixin already ensures user is a client and has profile.client
        profile = self.request.user.userprofile
        if not profile.client:
            # This case should ideally be handled by the mixin, but as a safeguard:
            logger.warning(f"User {self.request.user.username} attempting to access workflow visual but has no linked client.")
            return Assessment.objects.none()

        # Filter assessments for the user's client
        queryset = Assessment.objects.filter(client=profile.client)

        # Prefetch data needed by the client_workflow_visual.html partial
        # Adjust prefetch based on what client_workflow_visual.html actually uses
        queryset = queryset.prefetch_related(
            'workflow_steps__step_definition' # Likely needed to determine current step/status
        )
        return queryset

    def get(self, request, *args, **kwargs):
        """ Handle GET request and render the partial or handle errors. """
        try:
            # get_object will use get_queryset, enforcing client permission
            self.object = self.get_object()
            context = self.get_context_data(object=self.object)

            # Rule 4: Add UTC Debug Print
            now_utc = timezone.now()
            print(f"[DEBUG ClientWorkflowVisualPartialView GET {self.object.pk}] Rendering visual partial. Current UTC time: {now_utc.isoformat()}")

            # Rule 5 & 8: Render the template
            return render(request, self.template_name, context)

        except Http404:
            # Rule 6: Handle foreseeable error (Object not found / Permission via queryset)
            logger.warning(f"User {request.user.username} triggered 404 accessing workflow visual for assessment PK {kwargs.get('pk')}")
            # Return an empty response or simple error message suitable for AJAX replacement
            return HttpResponse("", status=404)
        except Exception as e:
            # Rule 6: Handle other errors
            logger.error(f"Error rendering workflow visual for assessment PK {kwargs.get('pk')}: {e}", exc_info=True)
            # Return an empty response or simple error message suitable for AJAX replacement
            return HttpResponse("", status=500)