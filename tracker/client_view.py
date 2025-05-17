# Standard library
import json
import os
import random
from collections import defaultdict

from datetime import date, datetime, timezone, time # Make sure 'timezone' is included here
from django.utils import timezone as django_timezone # Keep django one if needed elsewhere, aliased
import pytz


from urllib.parse import quote
import logging

# Third-party
import requests
from requests.auth import HTTPBasicAuth
from tenable.errors import APIError, NotFoundError, ForbiddenError

# Django core
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.core.serializers.json import DjangoJSONEncoder
from django.db import IntegrityError, transaction
from django.db.models import Count, Min, ProtectedError, Value, CharField, Q
from django.db.models.functions import Coalesce, Concat
from django.forms import modelformset_factory
from django.http import (
    FileResponse,
    Http404,
    HttpResponseForbidden,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods, require_POST
from django.views.generic import (
    CreateView,
    DeleteView,
    DetailView,
    FormView,
    ListView,
    UpdateView, TemplateView,
)
from django.views import View
from django.shortcuts import render
from constance import config


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
    AssessmentDateOptionForm
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
    AssessmentDateOption,
    AssessorAvailability,
    ScanStatus,
    WorkflowStepDefinition,
    TenableScanLog,
)
from .pdf_extractor import extract_ce_data_from_pdf
from .tasks import apply_tenable_tag_to_assets, create_or_update_tenable_client_tag

from .tasks import (
    sync_client_with_tenable, apply_tenable_tag_to_assets, # Use the new/renamed tasks
    scrape_nessus_agent_urls, validate_agent_urls # Keep others if needed
)
from .tenable_client import get_tenable_io_client



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


)

from .mixin import (
ClientRequiredMixin,
AdminRequiredMixin,
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin

)

logger = logging.getLogger(__name__)


@login_required
@user_passes_test(is_client, login_url=reverse_lazy('login'))
def client_dashboard(request):
    profile = request.user.userprofile
    if not profile.client:
        messages.warning(request, "Your client account is not linked to a company.")
        return redirect('logout')

    client = profile.client

    # --- Fetch main list of assessments for display ---
    client_assessments = Assessment.objects.filter(client=client).select_related('assessor').order_by('-created_at')

    # --- Calculate assessment counts and next deadline ---
    completed_statuses = ['Complete_Passed', 'Complete_Failed']

    # Assuming the status field in Assessment model is named 'status'
    completed_assessments_count = Assessment.objects.filter(
        client=client,
        status__in=completed_statuses
    ).count()

    active_assessments_count = Assessment.objects.filter(
        client=client
    ).exclude(
        status__in=completed_statuses
    ).count()

    next_deadline_assessment = Assessment.objects.filter(
        client=client,
        date_target_end__isnull=False,
        date_target_end__gte=timezone.now().date()
    ).exclude(
        status__in=completed_statuses  # Only from active assessments
    ).order_by('date_target_end').first()
    next_deadline_val = next_deadline_assessment.date_target_end if next_deadline_assessment else None

    # --- Fetch Nessus Agent URLs ---
    # Fetches all NessusAgentURL objects where is_valid=True, using model's default ordering
    nessus_agent_urls_list = NessusAgentURL.objects.filter(is_valid=True)

    # --- Support Email ---
    support_email_val = "support@cyberask.co.uk"

    # --- Initialize Context ---
    context = {
        'client': client,
        'assessments': client_assessments,  # Main list for iteration in template

        # Variables based on your specific requirements
        'active_assessments_count': active_assessments_count,
        'completed_assessments_count': completed_assessments_count,
        'next_deadline': next_deadline_val,
        'nessus_agent_urls': nessus_agent_urls_list,  # QuerySet of NessusAgentURL objects
        'support_email': support_email_val,

        # Tenable related context variables (initialized)
        'agent_status_summary': None,
        'tenable_error': None,
        'tenable_agents_details': [],
        'tenable_group_name_searched': None,
        'tenable_group_id_found': None
    }

    # --- START Tenable Agent Status Fetch ---
    tio = get_tenable_io_client()
    if not tio:
        context['tenable_error'] = "Could not initialize connection to Tenable.io. Check API configuration."
        logger.warning(f"Tenable connection failed for client dashboard: {client.name}")
    else:
        agent_group_name = client.name  # Assuming client.name is the Tenable agent group name
        context['tenable_group_name_searched'] = agent_group_name

        agent_group_id = None
        agents_in_group_details = []
        agent_status_summary_dict = defaultdict(int)
        agent_status_summary_dict['total'] = 0

        try:
            logger.debug(f"[Client Dashboard {client.name}] Searching for Tenable agent group '{agent_group_name}'")
            agent_groups = tio.agent_groups.list()
            for group in agent_groups:
                if group['name'] == agent_group_name:
                    agent_group_id = group.get('id')
                    context['tenable_group_id_found'] = agent_group_id
                    logger.debug(f"[Client Dashboard {client.name}] Found group ID {agent_group_id}")
                    break

            if not agent_group_id:
                logger.warning(
                    f"[Client Dashboard {client.name}] Agent group '{agent_group_name}' not found in Tenable.io.")
            else:
                logger.debug(f"[Client Dashboard {client.name}] Listing agents for group ID {agent_group_id}")
                try:
                    all_agents_iterator = tio.agents.list(limit=1000)
                    for agent_data in all_agents_iterator:
                        agent_groups_list = agent_data.get('groups', [])
                        if isinstance(agent_groups_list, list) and any(
                                ag.get('id') == agent_group_id for ag in agent_groups_list):
                            agents_in_group_details.append(agent_data)
                            status = agent_data.get('status', 'unknown').lower()
                            agent_status_summary_dict[status] += 1
                            agent_status_summary_dict['total'] += 1

                    logger.debug(
                        f"[Client Dashboard {client.name}] Found {agent_status_summary_dict['total']} agents. Statuses: {dict(agent_status_summary_dict)}")
                    context['agent_status_summary'] = dict(agent_status_summary_dict)
                    context['tenable_agents_details'] = agents_in_group_details

                except APIError as e:  # from tenable.errors import APIError
                    logger.exception(f"[Client Dashboard {client.name}] Tenable API Error listing agents: {e}")
                    context['tenable_error'] = "Error retrieving agent status from Tenable.io."
                except ForbiddenError:  # from tenable.errors import ForbiddenError
                    logger.exception(f"[Client Dashboard {client.name}] Permission denied listing agents in Tenable.")
                    context['tenable_error'] = "Permission denied retrieving agent status."
                except Exception as e:
                    logger.exception(
                        f"[Client Dashboard {client.name}] Unexpected error listing/processing agents: {e}")
                    context['tenable_error'] = "Unexpected error retrieving agent status."

        except APIError as e:
            logger.exception(f"[Client Dashboard {client.name}] Tenable API Error finding agent group: {e}")
            context['tenable_error'] = "Error accessing Tenable.io agent groups."
        except ForbiddenError:
            logger.exception(f"[Client Dashboard {client.name}] Permission denied finding agent group.")
            context['tenable_error'] = "Permission denied accessing Tenable.io agent groups."
        except Exception as e:
            logger.exception(f"[Client Dashboard {client.name}] Unexpected error finding agent group: {e}")
            context['tenable_error'] = "Unexpected error accessing Tenable.io."
    # --- END Tenable Agent Status Fetch ---

    return render(request, 'tracker/client/client_dashboard.html', context)


def key_to_str(key_tuple):
    return f"{key_tuple[0]} ({key_tuple[1]})"















class ClientListView(AdminRequiredMixin, ListView):
    model = Client
    template_name = 'tracker/admin/client_list.html'
    context_object_name = 'clients'
class ClientCreateView(AdminRequiredMixin, CreateView):
    model = Client
    form_class = ClientForm
    template_name = 'tracker/admin/client_form.html'
    success_url = reverse_lazy('tracker:client_list')

    def form_valid(self, form):
        # form.instance.created_by = self.request.user # Assign creator if field exists
        response = super().form_valid(form)
        if self.object:
            # Call the RENAMED task
            sync_client_with_tenable.delay(self.object.id) # <-- UPDATED
            messages.info(self.request, f"Client '{self.object.name}' created. Synchronizing Tag & Group with Tenable...")
        return response
class ClientUpdateView(AdminRequiredMixin, UpdateView):
    model = Client
    form_class = ClientForm
    template_name = 'tracker/admin/client_form.html'
    success_url = reverse_lazy('tracker:client_list')

    def form_valid(self, form):
        # --- Existing Companies House Logic ---
        client_instance = self.get_object() # Get the object *before* saving the form
        name_changed = 'name' in form.changed_data
        # NOTE: Assuming 'organization_number' is the correct field name from your form/model
        # Adjust if the field name for the company number is different.
        number_changed = 'organization_number' in form.changed_data # Or 'companies_house_number'? Check your form.

        if (name_changed or number_changed) and client_instance.companies_house_validated:
            # Reset validation status if relevant fields changed
            form.instance.companies_house_validated = False
            form.instance.last_companies_house_validation = None
            form.instance.validated_name = None # Clear tracked validated data
            form.instance.validated_number = None
            messages.warning(self.request, f"Client details changed. Companies House validation status reset for '{form.instance.name}'. Please re-validate.")
        # --- End Existing Companies House Logic ---

        # Call the parent form_valid() method to save the object
        response = super().form_valid(form) # Save happens here, self.object is now updated

        # --- TRIGGER CELERY TASK *AFTER* successful save ---
        if self.object: # Ensure the object exists after saving
            # Trigger the task, passing the PK of the saved object
            create_or_update_tenable_client_tag.delay(self.object.id)
            # Add a message about Tenable sync initiation
            messages.info(self.request, f"Synchronizing client '{self.object.name}' details with Tenable...")
        # --- END TRIGGER ---

        if self.object:
            # Call the RENAMED task
            sync_client_with_tenable.delay(self.object.id)  # <-- UPDATED
            messages.info(self.request,
                          f"Client '{self.object.name}' updated. Synchronizing Tag & Group with Tenable...")
        return response # Return the response from super().form_valid()
class ClientDeleteView(AdminRequiredMixin, DeleteView):
    model = Client
    template_name = 'tracker/admin/client_confirm_delete.html'
    success_url = reverse_lazy('tracker:client_list')

    # Removed the 'delete' method override as 'post' handles it now

    def post(self, request, *args, **kwargs):
        """
        Override post to handle ProtectedError during the deletion process,
        which might occur during transaction commit.
        """
        try:
            # Get client name BEFORE attempting delete for the message
            # Note: self.object is set before post runs for DeleteView via get_object
            client_name = self.get_object().name
            # Attempt the deletion process by calling the parent post method
            response = super().post(request, *args, **kwargs)
            # If super().post() succeeds (no exception), add success message
            messages.success(request, f"Client '{client_name}' deleted successfully.")
            return response
        except ProtectedError:
            # If ProtectedError occurs during super().post() execution
            messages.error(request, f"Cannot delete client '{self.get_object().name}' because they have associated assessments. Please delete or reassign their assessments first.")
            return redirect('tracker:client_list')
class ClientAssessmentListView(ClientRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/client/assessment_list.html'
    context_object_name = 'assessments'

    def get_queryset(self):
        profile = self.request.user.userprofile
        return Assessment.objects.filter(client=profile.client).select_related('assessor').order_by('-created_at')


class ClientAssessmentDetailView(ClientRequiredMixin, DetailView):
    model = Assessment
    template_name = 'tracker/client/assessment_detail.html'
    context_object_name = 'assessment'

    def get_queryset(self):
        # Ensure workflow steps and related data are prefetched efficiently
        print(
            f"[DEBUG] ClientAssessmentDetailView.get_queryset called at {timezone.now()} - PID: {os.getpid()}")  # [DEBUG]
        profile = self.request.user.userprofile
        if not profile.client:
            # Handled by mixin, but safeguard
            return Assessment.objects.none()

        # CHANGES BEGIN — 2025-05-16 12:00:00
        # Corrected 'scan_logs__initiated_by' to 'tenable_scan_logs__initiated_by'
        return Assessment.objects.filter(client=profile.client).prefetch_related(
            'scoped_items__operating_system',
            'scoped_items__network',
            'evidence_files__uploaded_by',
            'logs__user',
            'networks',
            'assessment_cloud_services__cloud_service_definition',
            'external_ips',
            'workflow_steps__step_definition',
            'workflow_steps__completed_by',
            'date_options__proposed_by',

        ).select_related('client', 'assessor__userprofile')
        # CHANGES END — 2025-05-16 12:00:00

    def get_context_data(self, **kwargs):
        print(
            f"[DEBUG] ClientAssessmentDetailView.get_context_data starting at {timezone.now()} - PID: {os.getpid()}")  # [DEBUG]
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()
        user = self.request.user
        today = date.today()

        # --- Standard Context ---
        context['can_edit_scope'] = assessment.status == 'Scoping_Client'
        context['downloadable_evidence'] = assessment.evidence_files.all()  # Uses prefetch
        context['logs'] = assessment.logs.order_by('-timestamp')[:20]  # Uses prefetch and model ordering

        # --- CE+ Sample Items Logic ---
        all_scope_items = list(assessment.scoped_items.all())  # Use prefetched
        ce_plus_sample_items_list = [item for item in all_scope_items if item.is_in_ce_plus_sample]
        context['has_ce_plus_sample'] = assessment.assessment_type == 'CE+' and bool(ce_plus_sample_items_list)

        sample_items_with_status = []
        if assessment.assessment_type == 'CE+':
            for item in ce_plus_sample_items_list:
                item.eol_status = 'ok'  # Default status
                if item.operating_system:
                    if not item.operating_system.is_supported:
                        item.eol_status = 'unsupported'
                    # Check EOL only if it's supported, or always if EOL means unsupported
                    if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                        item.eol_status = 'eol'
                elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other',
                                            'IP']:  # Types that don't typically have OS EOL
                    item.eol_status = 'unknown'  # Or 'n/a'
                sample_items_with_status.append(item)
        context['ce_plus_sample_items'] = sorted(sample_items_with_status,
                                                 key=lambda x: (x.item_type, str(x.operating_system or '')))

        # --- Scope Summary Logic ---
        scope_summary_data = defaultdict(
            lambda: {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})})
        scope_summary_data['total_items'] = len(all_scope_items)
        scope_summary_data['has_unsupported_or_eol'] = False
        for item in all_scope_items:
            os_name_str, vendor_hint_str, is_supported, is_eol = "Unknown OS", "unknown", True, False
            if item.operating_system:
                os_name_str, vendor_hint_str = str(
                    item.operating_system), item.operating_system.vendor.lower() if item.operating_system.vendor else "unknown"
                is_supported = item.operating_system.is_supported
                if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today: is_eol, is_supported = True, False
            if not is_supported or is_eol: scope_summary_data['has_unsupported_or_eol'] = True
            os_info_key = (os_name_str, vendor_hint_str)
            cat_map = {'Server': 'servers', 'Laptop': 'workstations', 'Desktop': 'workstations', 'Mobile': 'mobiles',
                       'Firewall': 'network_devices', 'Router': 'network_devices', 'Switch': 'network_devices',
                       'IP': 'network_devices', 'SaaS': 'cloud_services', 'PaaS': 'cloud_services',
                       'IaaS': 'cloud_services'}
            category_key = cat_map.get(item.item_type, 'other')
            group_dict = scope_summary_data[category_key]
            group_dict['count'] += 1
            os_data = group_dict['os_types'][os_info_key]
            os_data['count'] += 1
            if not is_supported: os_data['is_supported'] = False
            if is_eol: os_data['is_eol'] = True
        # Convert defaultdicts back to dicts for template JSON serialization safety if needed
        final_scope_summary = {'total_items': scope_summary_data['total_items'],
                               'has_unsupported_or_eol': scope_summary_data['has_unsupported_or_eol']}
        for category, data in scope_summary_data.items():
            if category not in ['total_items', 'has_unsupported_or_eol']: final_scope_summary[category] = {
                'count': data['count'], 'os_types': {key: dict(val) for key, val in data['os_types'].items()}}
        context['scope_summary'] = final_scope_summary

        # --- Workflow Context Logic ---
        workflow_steps = list(assessment.workflow_steps.all())  # Use prefetched
        current_step = None
        steps_with_permission = []
        for step in workflow_steps:
            step.can_update = step.is_update_allowed(user)  # Check permissions
            steps_with_permission.append(step)
            if step.status not in [AssessmentWorkflowStep.Status.COMPLETE,
                                   AssessmentWorkflowStep.Status.SKIPPED] and current_step is None:
                current_step = step
        context['workflow_steps'] = sorted(steps_with_permission, key=lambda s: s.step_definition.step_order)
        context['current_step'] = current_step

        # === Assessment Date Scheduling Context (Client View) ===
        date_options = list(assessment.date_options.all())  # Use prefetched
        context['assessment_date_options'] = date_options

        confirmed_date_option = next(
            (opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
        context[
            'display_confirmed_assessment_date'] = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start
        has_explicitly_confirmed_option = confirmed_date_option is not None

        is_before_testing = assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
        context['assessment_allows_date_management'] = is_before_testing and not has_explicitly_confirmed_option

        context['propose_date_form'] = AssessmentDateOptionForm(assessment=assessment)

        unavailable_dates_json = "[]"
        if assessment.assessor:
            unavailable_dates = AssessorAvailability.objects.filter(
                assessor=assessment.assessor
            ).values_list('unavailable_date', flat=True)
            unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
            unavailable_dates_json = json.dumps(unavailable_dates_str)
        context['assessor_unavailable_dates_json'] = unavailable_dates_json

        context['ce_plus_window_start_date'] = assessment.date_ce_passed
        context['ce_plus_window_end_date'] = assessment.ce_plus_window_end_date  # From model property
        context['confirmed_assessment_date'] = context['display_confirmed_assessment_date']  # For consistency

        # --- Timer Date (for countdown JS using Assessment.date_target_end) ---
        context['assessment_end_date_iso'] = None
        context['scan_launch_status'] = assessment.can_launch_ce_plus_scan()  # Assuming this method exists
        if assessment.date_target_end:
            try:
                # Use timezone directly for awareness
                end_datetime_utc = timezone.make_aware(datetime.combine(assessment.date_target_end, time.max), pytz.utc)
                context['assessment_end_date_iso'] = end_datetime_utc.isoformat()
            except ValueError:  # Handles cases where date_target_end might be invalid for datetime.combine
                logger.warning(
                    f"Could not create datetime for countdown timer from date_target_end: {assessment.date_target_end} for assessment {assessment.pk}")

        # CHANGES BEGIN — 2025-05-16 12:00:00
        # --- Tenable Scan Logs ---
        # Corrected assessment.scan_logs to assessment.tenable_scan_logs
        # This uses the prefetched data due to 'tenable_scan_logs__initiated_by' in get_queryset
        tenable_scan_logs_list = list(assessment.tenable_scan_logs.all().order_by('-created_at'))

        context['tenable_scan_logs'] = tenable_scan_logs_list
        print(
            f"[DEBUG] Added {len(tenable_scan_logs_list)} Tenable scan logs to context for assessment {assessment.pk} at {timezone.now()} - PID: {os.getpid()}")  # [DEBUG]
        # CHANGES END — 2025-05-16 12:00:00

        print(
            f"[DEBUG] ClientAssessmentDetailView.get_context_data finishing at {timezone.now()} - PID: {os.getpid()}")  # [DEBUG]
        return context




