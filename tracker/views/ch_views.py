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