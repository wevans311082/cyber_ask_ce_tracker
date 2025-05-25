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
from django.views.generic import *


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.admin.views.decorators import staff_member_required
from django.urls import reverse_lazy
from django.utils import timezone
from django.contrib import messages
from django.http import Http404 # Make sure this is imported


# Local app imports
from tracker.forms import *
from tracker.models import *
from tracker.tasks import *
from tracker.utils import *
from tracker.mixin import *

logger = logging.getLogger(__name__)


def _key_to_str(key):
    """Converts a key (potentially a tuple) to a string for dictionary keys in context."""
    if isinstance(key, tuple):
        return '__'.join(map(str, key))
    return str(key)

# --- Context function for 'Agree Date' step (for new step partial) ---
def get_step_agree_date_context(assessment, workflow_step, request):
    """Prepares context for the 'Agree Date' step card."""
    date_options = list(assessment.date_options.select_related('proposed_by').order_by('proposed_date'))
    confirmed_date_option = next(
        (opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
    display_confirmed_assessment_date = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start
    editable_statuses = ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review'] # Ensure Assessment.status choices match
    assessment_allows_date_management = assessment.status in editable_statuses and not confirmed_date_option
    assessor_unavailable_dates_json = "[]"
    if assessment.assessor:
        unavailable_dates = AssessorAvailability.objects.filter(
            assessor=assessment.assessor
        ).values_list('unavailable_date', flat=True)
        unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
        assessor_unavailable_dates_json = json.dumps(unavailable_dates_str)
    ce_plus_window_start_date = assessment.date_ce_passed
    ce_plus_window_end_date = getattr(assessment, 'ce_plus_window_end_date', None) # Uses property on Assessment model

    context = {
        'assessment_date_options': date_options,
        'display_confirmed_assessment_date': display_confirmed_assessment_date,
        'assessment_allows_date_management': assessment_allows_date_management,
        'propose_date_form': AssessmentDateOptionForm(assessment=assessment, user=request.user),
        'assessor_unavailable_dates_json': assessor_unavailable_dates_json,
        'ce_plus_window_start_date': ce_plus_window_start_date,
        'ce_plus_window_end_date': ce_plus_window_end_date,
        'confirmed_assessment_date': display_confirmed_assessment_date,
        # Common context for step actions partial
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'step_status': workflow_step.status,
        'status_choices': workflow_step.Status,
        'step_pk': workflow_step.pk,
        'assessment_pk': assessment.pk,
        'workflow_step': workflow_step, # Pass the whole object for convenience
    }
    return context

# --- Context functions moved from LoadAssessmentCardContentView ---

def get_scope_summary_context(assessment, workflow_step, request):
    """Prepares context for the 'Scope Summary' card."""
    # Ensure ScopedItem, OperatingSystem, Network models are imported or handled via assessment relations
    all_scope_items = list(assessment.scoped_items.select_related('operating_system', 'network').all())
    scope_summary_data = defaultdict(
        lambda: {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})})
    scope_summary_data['total_items'] = len(all_scope_items)
    scope_summary_data['has_unsupported_or_eol'] = False
    today = date.today()

    for item in all_scope_items:
        os_name_str, vendor_hint_str, is_supported, is_eol = "Unknown OS", "unknown", True, False
        if item.operating_system:
            os_name_str = str(item.operating_system)
            vendor_hint_str = item.operating_system.vendor.lower() if item.operating_system.vendor else "unknown"
            is_supported = item.operating_system.is_supported
            if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                is_eol = True
                is_supported = False  # EOL implies not supported for CE+
        if not is_supported or is_eol:
            scope_summary_data['has_unsupported_or_eol'] = True

        os_info_key = (os_name_str, vendor_hint_str)
        cat_map = {
            'Server': 'servers', 'Laptop': 'workstations', 'Desktop': 'workstations',
            'Mobile': 'mobiles', 'Firewall': 'network_devices', 'Router': 'network_devices',
            'Switch': 'network_devices', 'IP': 'network_devices', 'SaaS': 'cloud_services',
            'PaaS': 'cloud_services', 'IaaS': 'cloud_services'
        }
        category_key = cat_map.get(item.item_type, 'other')
        group_dict = scope_summary_data[category_key]
        group_dict['count'] += 1
        os_data = group_dict['os_types'][os_info_key]
        os_data['count'] += 1
        if not is_supported: os_data['is_supported'] = False
        if is_eol: os_data['is_eol'] = True

    final_scope_summary = {
        'total_items': scope_summary_data['total_items'],
        'has_unsupported_or_eol': scope_summary_data['has_unsupported_or_eol']
    }
    for category, data_dict in scope_summary_data.items():
        if category not in ['total_items', 'has_unsupported_or_eol']:
            final_scope_summary[category] = {
                'count': data_dict['count'],
                'os_types': {_key_to_str(key): dict(val) for key, val in data_dict['os_types'].items()}
            }
    return {
        'scope_summary': final_scope_summary,
        'can_edit_scope': assessment.status == 'Scoping_Client',  # Example permission
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_networks_context(assessment, workflow_step, request):
    """Prepares context for the 'Networks' card."""
    return {
        'networks': assessment.networks.all(),
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_cloud_services_context(assessment, workflow_step, request):
    """Prepares context for the 'Cloud Services' card."""
    # Ensure AssessmentCloudService, CloudServiceDefinition models are imported/handled
    return {
        'assessment_cloud_services': assessment.assessment_cloud_services.select_related(
            'cloud_service_definition', 'verified_by' # Assuming verified_by is a FK to User
        ).all(),
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_external_ips_context(assessment, workflow_step, request):
    """Prepares context for the 'External IPs' card."""
    return {
        'external_ips': assessment.external_ips.all(),
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_date_scheduling_context(assessment, workflow_step, request): # Original/Legacy one
    """Prepares context for the original 'Date Scheduling' card."""
    date_options = list(assessment.date_options.select_related('proposed_by').order_by('proposed_date'))
    confirmed_date_option = next(
        (opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
    display_confirmed_assessment_date = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start
    editable_statuses = ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
    assessment_allows_date_management = assessment.status in editable_statuses and not confirmed_date_option
    assessor_unavailable_dates_json = "[]"
    if assessment.assessor:
        unavailable_dates = AssessorAvailability.objects.filter(
            assessor=assessment.assessor
        ).values_list('unavailable_date', flat=True)
        unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
        assessor_unavailable_dates_json = json.dumps(unavailable_dates_str)
    return {
        'assessment_date_options': date_options,
        'display_confirmed_assessment_date': display_confirmed_assessment_date,
        'assessment_allows_date_management': assessment_allows_date_management,
        'propose_date_form': AssessmentDateOptionForm(assessment=assessment, user=request.user),
        'assessor_unavailable_dates_json': assessor_unavailable_dates_json,
        'ce_plus_window_start_date': assessment.date_ce_passed,
        'ce_plus_window_end_date': getattr(assessment, 'ce_plus_window_end_date', None),
        'confirmed_assessment_date': display_confirmed_assessment_date,
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_ce_plus_sample_context(assessment, workflow_step, request):
    """Prepares context for the 'CE+ Sample' card."""
    # Ensure ScopedItem model is handled
    today = date.today()
    all_scope_items = list(assessment.scoped_items.select_related('operating_system', 'network').all())
    ce_plus_sample_items_list = [item for item in all_scope_items if item.is_in_ce_plus_sample]
    sample_items_with_status = []
    if assessment.assessment_type == 'CE+': # Ensure Assessment model has assessment_type field
        for item in ce_plus_sample_items_list:
            item.eol_status = 'ok' # Assuming you add this attribute dynamically
            if item.operating_system:
                if not item.operating_system.is_supported:
                    item.eol_status = 'unsupported'
                if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                    item.eol_status = 'eol'
            elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other', 'IP']: # Assuming ScopedItem has item_type
                item.eol_status = 'unknown'
            sample_items_with_status.append(item)
    return {
        'has_ce_plus_sample': assessment.assessment_type == 'CE+' and bool(ce_plus_sample_items_list),
        'ce_plus_sample_items': sorted(sample_items_with_status,
                                       key=lambda x: (x.item_type, str(x.operating_system or ''))),
        'scan_launch_status': assessment.can_launch_ce_plus_scan(),  # Method on Assessment model
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_downloads_context(assessment, workflow_step, request):
    """Prepares context for the 'Downloads' card."""
    # Ensure EvidenceFile model is handled
    return {
        'downloadable_evidence': assessment.evidence_files.select_related('uploaded_by').all(),
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }

def get_scan_history_context(assessment, workflow_step, request):
    """Prepares context for the 'Scan History' card."""
    # Ensure TenableScanLog model is handled
    return {
        'tenable_scan_logs': assessment.tenable_scan_logs.select_related('assessment').order_by('-created_at'),
        'workflow_step': workflow_step,
        'can_update_step': workflow_step.is_update_allowed(request.user),
        'status_choices': workflow_step.Status,
    }


def get_workflow_checklist_context(assessment, workflow_step_for_card_context, request):
    """
    Prepares context for the full workflow checklist card.
    'workflow_step_for_card_context' will be None when this is loaded as a named card.
    """
    actual_workflow_steps_qs = assessment.workflow_steps.select_related(
        'step_definition',
        'completed_by'
    ).order_by('step_definition__step_order')

    # Process steps to add the 'can_update_by_current_user' attribute
    processed_workflow_steps = []
    for step_item in actual_workflow_steps_qs:
        # Call the existing method on your model instance
        step_item.can_update_by_current_user = step_item.is_update_allowed(request.user)
        processed_workflow_steps.append(step_item)

    context = {
        'assessment': assessment,
        'workflow_steps_list': processed_workflow_steps,  # Use the processed list
        'status_choices': AssessmentWorkflowStep.Status,  # For use in the template loop
        'assessment_pk': assessment.pk,  # For URLs within the template
        # 'workflow_step': workflow_step_for_card_context, # This context is for the card shell, may be None
    }
    return context


def get_assessment_info_context(assessment: Assessment, workflow_step_for_card_context, request):
    print(f"\n--- ENTERING get_assessment_info_context (User: {request.user.username}) ---")

    is_edit_mode_requested = request.GET.get('edit_mode') == 'true'
    print(f"[DEBUG] Is 'edit_mode=true' in URL? {is_edit_mode_requested}")

    can_actually_edit_this_assessment = False  # Default to no edit permission
    assessment_form_instance = None

    profile = getattr(request.user, 'userprofile', None)

    print(f"[DEBUG] Profile object: {profile}")
    if profile:
        profile_role = getattr(profile, 'role', None)  # Safely get role
        profile_client = getattr(profile, 'client', None)  # Safely get client associated with profile
        assessment_client = getattr(assessment, 'client', None)  # Safely get client of assessment

        print(f"[DEBUG] Profile Role: {profile_role}")
        print(f"[DEBUG] Profile Client: {profile_client} (ID: {profile_client.pk if profile_client else 'N/A'})")
        print(
            f"[DEBUG] Assessment Client: {assessment_client} (ID: {assessment_client.pk if assessment_client else 'N/A'})")

        if profile_role in ['Assessor', 'Admin']:
            can_actually_edit_this_assessment = True
            print(f"[DEBUG] User is Assessor/Admin. Setting can_actually_edit_this_assessment = True")
        elif profile_role == 'Client':
            if profile_client and assessment_client and profile_client == assessment_client:
                can_actually_edit_this_assessment = True
                print(f"[DEBUG] User is Client AND client match. Setting can_actually_edit_this_assessment = True")
            else:
                print(f"[DEBUG] User is Client BUT client mismatch or one is None.")
        else:
            print(f"[DEBUG] User role is '{profile_role}', not Assessor, Admin, or matching Client.")
    else:
        print(f"[DEBUG] No userprofile found for user '{request.user.username}'.")

    print(
        f"[DEBUG] Value of 'can_actually_edit_this_assessment' before form instantiation check: {can_actually_edit_this_assessment}")

    is_in_edit_mode_final = is_edit_mode_requested and can_actually_edit_this_assessment
    print(
        f"[DEBUG] Value of 'is_in_edit_mode_final' (is_edit_mode_requested AND can_actually_edit_this_assessment): {is_in_edit_mode_final}")

    if is_in_edit_mode_final:
        print(f"[DEBUG] Condition MET: Instantiating AssessmentInfoForm for user '{request.user.username}'.")
        assessment_form_instance = AssessmentInfoForm(instance=assessment, user=request.user)
    else:
        print(f"[DEBUG] Condition NOT MET for form instantiation.")
        if not is_edit_mode_requested:
            print(f"  Reason: 'edit_mode=true' was not in the URL or not parsed as true.")
        if not can_actually_edit_this_assessment:
            print(f"  Reason: User does not have permission ('can_actually_edit_this_assessment' is False).")

    context = {
        'assessment': assessment,
        'can_edit_assessment_info': can_actually_edit_this_assessment,
        'is_edit_mode': is_in_edit_mode_final,
        'assessment_info_form': assessment_form_instance,
    }
    print(f"[DEBUG] Returning context. Form present: {'Yes' if assessment_form_instance else 'No'}")
    print(f"--- EXITING get_assessment_info_context ---\n")
    return context














































































































@login_required
# @client_access_required # Or specific permission decorator
def step_agree_date_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Agree Date' step for an assessment.
    Renders the partial for date agreement.
    """
    # assessment = get_object_or_404(Assessment, pk=assessment_id)
    # step = get_object_or_404(Step, assessment=assessment, function_name='agree_date') # Example
    context = {
        'assessment_id': assessment_id,
        # 'assessment': assessment,
        # 'step': step,
        # Add other necessary context for agreeing on dates
    }
    return render(request, 'tracker/partials/step/step_agree_date.html', context)

@login_required
# @client_access_required
def step_define_user_devices_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Define User Devices' step for an assessment.
    Renders the partial for defining user devices.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for user devices
    }
    return render(request, 'tracker/partials/step/step_define_user_devices.html', context)

@login_required
# @client_access_required
def step_define_external_ips_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Define External IPs' step for an assessment.
    Renders the partial for defining external IP addresses.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for external IPs
    }
    return render(request, 'tracker/partials/step/step_define_external_ips.html', context)

@login_required
# @client_access_required
def step_define_servers_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Define Servers' step for an assessment.
    Renders the partial for defining servers.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for servers
    }
    return render(request, 'tracker/partials/step/step_define_servers.html', context)

@login_required
# @client_access_required
def step_provide_mfa_proof_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Provide MFA Proof' step for an assessment.
    Renders the partial for providing MFA proof.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for MFA proof
    }
    return render(request, 'tracker/partials/step/step_provide_mfa_proof.html', context)

@login_required
# @client_access_required # Or could be assessor for finalization
def step_select_sample_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Select Sample' step for an assessment (CE+).
    Renders the partial for selecting the device sample.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for sample selection
    }
    return render(request, 'tracker/partials/step/step_select_sample.html', context)

@login_required
# @client_access_required
def step_confirm_availability_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Confirm Availability' step for an assessment.
    Renders the partial for confirming availability for assessment activities.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for availability confirmation
    }
    return render(request, 'tracker/partials/step/step_confirm_availability.html', context)

@login_required
# @assessor_access_required # Likely an assessor task
def step_finalise_sample_list_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Finalise Sample List' step for an assessment (CE+).
    Renders the partial for finalising the device sample.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for sample finalization
    }
    return render(request, 'tracker/partials/step/step_finalise_sample_list.html', context)

@login_required
# @client_access_required # Or could be for assessor to provide/verify
def step_install_nessus_agents_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Install Nessus Agents' step.
    Renders the partial related to Nessus Agent installation instructions/status.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for Nessus agent installation
    }
    return render(request, 'tracker/partials/step/step_install_nessus_agents.html', context)

@login_required
# @client_access_required
def step_book_user_slots_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Book User Slots' step for assessment activities.
    Renders the partial for booking user interview/testing slots.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for booking user slots
    }
    return render(request, 'tracker/partials/step/step_book_user_slots.html', context)

@login_required
# @client_access_required # Or could be for assessor to provide template
def step_inform_users_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Inform Users' step.
    Renders the partial related to informing users about the assessment.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for informing users
    }
    return render(request, 'tracker/partials/step/step_inform_users.html', context)

@login_required
# @client_access_required
def step_install_mobile_app_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Install Mobile App' step if applicable.
    Renders the partial for mobile app installation instructions/status.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for mobile app installation
    }
    return render(request, 'tracker/partials/step/step_install_mobile_app.html', context)

@login_required
# @client_access_required
def step_update_devices_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Update Devices' step.
    Renders the partial related to ensuring devices are updated.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for device updates
    }
    return render(request, 'tracker/partials/step/step_update_devices.html', context)

@login_required
# @client_access_required # Or assessor for viewing results
def step_agent_test_scans_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Agent Test Scans' step.
    Renders the partial for agent-based test scan status/results.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for agent test scans
    }
    return render(request, 'tracker/partials/step/step_agent_test_scans.html', context)

@login_required
# @client_access_required
def step_remediate_agent_scans_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Remediate Agent Scans' step.
    Renders the partial for remediation of agent scan findings.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for agent scan remediation
    }
    return render(request, 'tracker/partials/step/step_remediate_agent_scans.html', context)

@login_required
# @assessor_access_required # Or client for viewing status
def step_external_scan_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'External Scan' step.
    Renders the partial for external scan status/results.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for external scans
    }
    return render(request, 'tracker/partials/step/step_external_scan.html', context)

@login_required
# @client_access_required
def step_remediate_external_scan_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Remediate External Scan' step.
    Renders the partial for remediation of external scan findings.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for external scan remediation
    }
    return render(request, 'tracker/partials/step/step_remediate_external_scan.html', context)

@login_required
# @client_access_required # Or assessor for triggering
def step_send_test_emails_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Send Test Emails' step for malware checks.
    Renders the partial for sending/confirming test emails.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for sending test emails
    }
    return render(request, 'tracker/partials/step/step_send_test_emails.html', context)

@login_required
# @assessor_access_required # Primarily assessor driven
def step_assessment_day_execution_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Assessment Day Execution' step.
    Renders the partial for activities on the assessment day.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for assessment day execution
    }
    return render(request, 'tracker/partials/step/step_assessment_day_execution.html', context)

@login_required
# @assessor_access_required
def step_generate_report_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Generate Report' step.
    Renders the partial for report generation status/options.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for report generation
    }
    return render(request, 'tracker/partials/step/step_generate_report.html', context)

@login_required
# @assessor_access_required
def step_issue_certificate_view(request: HttpRequest, assessment_id: int) -> HttpResponse:
    """
    Handles the 'Issue Certificate' step.
    Renders the partial for certificate issuance.
    """
    context = {
        'assessment_id': assessment_id,
        # Add context for certificate issuance
    }
    return render(request, 'tracker/partials/step/step_issue_certificate.html', context)
