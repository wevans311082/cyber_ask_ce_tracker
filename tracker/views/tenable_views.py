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
from django.http import FileResponse, Http404, HttpResponseForbidden, HttpResponseRedirect, JsonResponse, HttpRequest, HttpResponse, HttpResponseBadRequest
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
from tracker.mixin import *


logger = logging.getLogger(__name__)

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
