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
from tracker.forms import (
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
from tracker.models import (
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

from tracker.tasks import (
    sync_client_with_tenable,
    apply_tenable_tag_to_assets,
    scrape_nessus_agent_urls,
    validate_agent_urls,
    create_or_update_tenable_client_tag,
    launch_tenable_scan_task
)


from tracker.utils import (
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

from tracker.mixin import (
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin,
AdminRequiredMixin,
UserPassesTestMixin,
ClientRequiredMixin,

)


logger = logging.getLogger(__name__)


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