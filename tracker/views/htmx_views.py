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
    HttpResponse, HttpResponseBadRequest, HttpResponseNotFound
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

# Local app imports
from tracker.forms import *
from tracker.models import *
from tracker.tasks import *
from tracker.utils import *



import json
import os
import logging  # Recommended for server-side logging
import uuid

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.html import escape  # For safely rendering messages


from tracker.tenable_client import get_tenable_io_client  # Assuming this is your Tenable client utility

from tracker.scan_parser import process_scan_data_into_models



from collections import defaultdict
from datetime import date

from django.http import Http404, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.views import View
from django.utils import timezone
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _

# Local app imports
from tracker.forms import *
from tracker.models import *
from tracker.tasks import *
from tracker.utils import *
from tracker.mixin import *
from tracker.views import *
from . import step_views
from . import personnel_views

logger = logging.getLogger(__name__)


@login_required
def htmx_fetch_tenable_scan_results(request, log_id):
    """
    HTMX view to fetch Tenable scan results for a given TenableScanLog ID,
    save them to a JSON file, update the scan_log with the path,
    trigger parsing of the saved file, and return a status message.
    """
    # [DEBUG] htmx_fetch_tenable_scan_results called at 2025-05-18 19:00:00
    print(f"[DEBUG PRINT] htmx_fetch_tenable_scan_results called for log_id: {log_id} at {timezone.now()}")
    logger.info(f"[DEBUG LOGGER] htmx_fetch_tenable_scan_results called for log_id: {log_id} at {timezone.now()}")

    if not request.htmx:
        print("[DEBUG PRINT] htmx_fetch_tenable_scan_results accessed without HTMX headers.")
        logger.warning("htmx_fetch_tenable_scan_results accessed without HTMX headers.")
        return HttpResponse("This endpoint is for HTMX requests only.", status=400)

    try:
        scan_log = get_object_or_404(TenableScanLog, id=log_id)
    except Http404:
        print(f"[DEBUG PRINT] TenableScanLog with id {log_id} not found.")
        logger.error(f"TenableScanLog with id {log_id} not found.")
        return HttpResponse(
            '<div class="alert alert-danger alert-sm mb-0" role="alert">Error: Scan log not found.</div>',
            status=404
        )

    if not scan_log.tenable_scan_run_uuid:
        print(f"[DEBUG PRINT] Scan log {log_id} does not have a Tenable Scan Run UUID.")
        logger.warning(f"Scan log {log_id} does not have a Tenable Scan Run UUID.")
        return HttpResponse(
            '<div class="alert alert-warning alert-sm mb-0" role="alert">Cannot fetch: Scan Run UUID is missing for this log.</div>',
            status=400
        )

    if scan_log.status != "COMPLETED":
        print(
            f"[DEBUG PRINT] Attempted to fetch results for non-completed scan log {log_id} (status: {scan_log.status}).")
        logger.warning(f"Attempted to fetch results for non-completed scan log {log_id} (status: {scan_log.status}).")
        return HttpResponse(
            f'<div class="alert alert-info alert-sm mb-0" role="alert">Info: Scan status is "{escape(scan_log.status)}". Results can only be fetched for "COMPLETED" scans.</div>',
            status=400
        )

    tio = get_tenable_io_client()
    if not tio:
        print("[DEBUG PRINT] Could not initialize TenableIO client in htmx_fetch_tenable_scan_results.")
        logger.error("Could not initialize TenableIO client in htmx_fetch_tenable_scan_results.")
        return HttpResponse(
            '<div class="alert alert-danger alert-sm mb-0" role="alert">Error: Failed to initialize Tenable client. Check server logs.</div>',
            status=500
        )

    scan_uuid_str = ""
    filename = ""  # Initialize filename for use in messages
    all_scan_vulns_count = 0  # Initialize count

    try:
        if isinstance(scan_log.tenable_scan_run_uuid, uuid.UUID):
            scan_uuid_str = str(scan_log.tenable_scan_run_uuid)
        else:
            scan_uuid_str = scan_log.tenable_scan_run_uuid

        print(
            f"[DEBUG PRINT] Fetching vulnerabilities from Tenable.io for scan_uuid: {scan_uuid_str} (log_id: {log_id})")
        logger.info(f"Fetching vulnerabilities from Tenable.io for scan_uuid: {scan_uuid_str} (log_id: {log_id})")

        scan_iterator = tio.exports.vulns(scan_uuid=scan_uuid_str)
        all_scan_vulns = []
        for v_idx, v in enumerate(scan_iterator):
            all_scan_vulns.append(v)
        all_scan_vulns_count = len(all_scan_vulns)

        print(
            f"[DEBUG PRINT] Successfully fetched {all_scan_vulns_count} vulnerability records for scan {scan_uuid_str}.")
        logger.info(f"Successfully fetched {all_scan_vulns_count} vulnerability records for scan {scan_uuid_str}.")

        relative_reports_dir = 'scan_reports'
        reports_dir_full_path = os.path.join(settings.MEDIA_ROOT, relative_reports_dir)
        os.makedirs(reports_dir_full_path, exist_ok=True)

        timestamp = timezone.now().strftime("%Y%m%d%H%M")
        safe_scan_uuid_filename_part = scan_uuid_str.replace('-', '')
        filename = f"{timestamp}_{safe_scan_uuid_filename_part}.json"  # filename is now defined here

        relative_filepath = os.path.join(relative_reports_dir, filename)
        filepath_full = os.path.join(reports_dir_full_path, filename)

        with open(filepath_full, 'w') as fp:
            json.dump(all_scan_vulns, fp, indent=2)

        print(f"[DEBUG PRINT] Saved {all_scan_vulns_count} records to {filepath_full} for scan_log {log_id}.")
        logger.info(f"Saved {all_scan_vulns_count} records to {filepath_full} for scan_log {log_id}.")

        scan_log.saved_report_path = relative_filepath
        scan_log.report_last_saved_at = timezone.now()

        print(f"[DEBUG PRINT] Attempting to save scan_log (id: {scan_log.id}) with:")
        print(f"[DEBUG PRINT]   scan_log.saved_report_path = {scan_log.saved_report_path}")
        print(f"[DEBUG PRINT]   scan_log.report_last_saved_at = {scan_log.report_last_saved_at}")

        update_fields_list = ['saved_report_path', 'report_last_saved_at', 'updated_at']
        print(f"[DEBUG PRINT]   update_fields = {update_fields_list}")

        scan_log.save(update_fields=update_fields_list)

        print(f"[DEBUG PRINT] scan_log.save() called for id: {scan_log.id}.")

        # ---- Call the parser ----
        print(f"[DEBUG PRINT] Attempting to parse saved file for scan_log_id: {scan_log.id}")
        logger.info(f"Attempting to parse saved file for scan_log_id: {scan_log.id}")

        parsing_successful, parsing_message = process_scan_data_into_models(scan_log.id)

        final_message = ""
        alert_class = "alert-info"  # Default

        if parsing_successful:
            print(f"[DEBUG PRINT] Parsing successful for scan_log_id {scan_log.id}: {parsing_message}")
            logger.info(f"Parsing successful for scan_log_id {scan_log.id}: {parsing_message}")
            final_message = (
                f"Successfully fetched and saved {all_scan_vulns_count:,} vulnerabilities to <code>{filename}</code>. "
                f"Parsing: {escape(parsing_message)}")
            alert_class = "alert-success"
        else:
            print(f"[DEBUG PRINT] Parsing failed for scan_log_id {scan_log.id}: {parsing_message}")
            logger.error(f"Parsing failed for scan_log_id {scan_log.id}: {parsing_message}")
            final_message = (
                f"Successfully fetched and saved {all_scan_vulns_count:,} vulnerabilities to <code>{filename}</code>. "
                f"However, data processing failed: {escape(parsing_message)}")
            alert_class = "alert-warning"

        return HttpResponse(
            f'<div class="alert {alert_class} alert-sm mb-0" role="alert"><i class="fas fa-info-circle me-1"></i>{final_message}</div>'
        )

    except Exception as e:
        print(
            f"[DEBUG PRINT] Type of scan_log.tenable_scan_run_uuid: {type(scan_log.tenable_scan_run_uuid)}, Value: {scan_log.tenable_scan_run_uuid}")
        logger.error(
            f"Type of scan_log.tenable_scan_run_uuid: {type(scan_log.tenable_scan_run_uuid)}, Value: {scan_log.tenable_scan_run_uuid}")

        print(
            f"[DEBUG PRINT] ERROR in htmx_fetch_tenable_scan_results for scan_log {log_id} (scan_uuid used: {scan_uuid_str if scan_uuid_str else 'not set'}): {e}")
        logger.exception(
            f"ERROR in htmx_fetch_tenable_scan_results for scan_log {log_id} (scan_uuid used: {scan_uuid_str if scan_uuid_str else 'not set'}): {e}")

        error_message = escape(str(e))
        # Ensure filename is available for the error message if the error occurs after filename generation
        fetch_error_detail = f"Could not fetch/save/parse results for <code>{filename if filename else 'unknown file'}</code>."
        return HttpResponse(
            f'<div class="alert alert-danger alert-sm mb-0" role="alert"><strong>Error:</strong> {fetch_error_detail} {error_message}. Please check server logs.</div>',
            status=500
        )


class LoadAssessmentCardContentView(ClientRequiredMixin, View): # Ensure ClientRequiredMixin is appropriate or use a more general one
    NAMED_CARD_TEMPLATES = {
        'workflow_checklist': 'tracker/partials/workflow_checklist_card.html',
        'assessment_info': 'tracker/partials/assessment_info_card.html',
        # Although we'll call a view directly for personnel,
        # having an entry here can be good for consistency or if you ever want a static fallback.
        # For direct view calling, this specific template path might not be used if the card_name is intercepted.
        'personnel_contacts': 'tracker/partials/_assessment_personnel_list.html',
    }

    # CONTEXT_FUNCTION_MAP might not need a new entry if we call the view directly.
    # If assessment_personnel_list_partial needed extra context from here, we'd add it.
    # For now, it's self-contained.
    CONTEXT_FUNCTION_MAP = {
        'tracker/partials/client_scope_summary.html': 'get_scope_summary_context',
        'tracker/partials/step/step_agree_date.html': 'get_step_agree_date_context',
        'tracker/partials/workflow_checklist_card.html': 'get_workflow_checklist_context',
        'tracker/partials/assessment_info_card.html': 'get_assessment_info_context',
    }

    def get_workflow_step_for_view(self, assessment, step_pk, request):
        # ... (this helper method remains the same as you provided) ...
        profile = request.user.userprofile  # type: ignore
        if not profile or not profile.client or assessment.client != profile.client:
            logger.warning(
                f"User {request.user.username} permission issue for step {step_pk} with assessment {assessment.id}.")
            raise PermissionDenied("Permission denied for this workflow step.")
        workflow_step = get_object_or_404(
            AssessmentWorkflowStep.objects.select_related('step_definition'),
            pk=step_pk,
            assessment=assessment
        )
        return workflow_step


    def get(self, request, assessment_pk, step_pk=None, card_name=None, **kwargs):
        print(f"\n--- Debugging LoadAssessmentCardContentView.get() ---")
        print(f"Request path: {request.path}")
        print(f"assessment_pk: {assessment_pk}, step_pk: {step_pk}, card_name: '{card_name}'")

        if not request.htmx:
            print("Request is NOT HTMX. Returning BadRequest.")
            return HttpResponseBadRequest("This endpoint is for HTMX requests only.")
        print("Request IS HTMX.")

        try:
            # Permission check: Ensure user is client and this assessment belongs to them.
            # Your ClientRequiredMixin might handle parts of this, but explicit checks are good.
            profile = request.user.userprofile
            if not profile or not profile.client: # Ensure user has a profile and is linked to a client
                print(f"User {request.user.username} has no associated client profile.")
                raise PermissionDenied("User has no associated client.")
            assessment = get_object_or_404(Assessment, pk=assessment_pk)
            if assessment.client != profile.client:
                print(f"Assessment client {assessment.client.id} does not match user's client {profile.client.id}.")
                raise PermissionDenied("This assessment does not belong to your client account.")
            print(f"Successfully fetched assessment ID: {assessment.pk} for user {request.user.username}")

        except Http404:
            logger.warning(f"Assessment with pk={assessment_pk} not found for user {request.user.username}.")
            return HttpResponse("Error: Assessment not found.", status=404)
        except PermissionDenied as e:
            logger.warning(f"Permission denied for assessment_pk={assessment_pk}, user={request.user.username}: {str(e)}")
            return HttpResponse(f"Error: {str(e)}", status=403)
        except Exception as e: # Catch other potential errors like UserProfile.DoesNotExist
            logger.error(f"Unexpected error during assessment access for user {request.user.username}, assessment_pk={assessment_pk}: {e}", exc_info=True)
            return HttpResponse("Error: An unexpected issue occurred while accessing the assessment.", status=500)


        # --- MODIFICATION FOR PERSONNEL CONTACTS CARD ---
        if card_name == 'personnel_contacts':
            print(f"Specific handling for named card: '{card_name}'. Calling assessment_personnel_list_partial view.")
            # Directly call the view function that renders the personnel list partial
            # This view function handles its own context and template rendering.
            try:
                # Ensure this import is at the top of the file:
                from .personnel_views import assessment_personnel_list_partial
                response = assessment_personnel_list_partial(request, assessment_pk=assessment.pk)
                # Add HX-Trigger for nav update if needed for this card type
                response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'cardName': card_name}})
                print("--- Exiting LoadAssessmentCardContentView.get() via personnel_contacts direct call ---")
                return response
            except Exception as e_personnel_view:
                logger.error(f"Error calling assessment_personnel_list_partial for card '{card_name}': {e_personnel_view}", exc_info=True)
                # Fallback to a generic error card content if the direct view call fails
                error_context = {'assessment': assessment, 'workflow_step': None,
                                 'error_message': _("Error loading personnel contacts. An administrator has been notified.")}
                html_content = render_to_string('tracker/partials/_default_card_content.html', error_context, request=request)
                return HttpResponse(html_content, status=500)
        # --- END MODIFICATION ---

        card_template = None
        workflow_step_for_context = None

        if card_name: # This will now handle other named cards like 'assessment_info', 'workflow_checklist'
            print(f"Processing named card: '{card_name}'")
            card_template = self.NAMED_CARD_TEMPLATES.get(card_name)
            print(f"Template path from NAMED_CARD_TEMPLATES: '{card_template}'")
            if not card_template:
                print(f"Error: Named card '{card_name}' not found in NAMED_CARD_TEMPLATES.")
                return HttpResponseNotFound(f"The card '{card_name}' could not be found.")
        elif step_pk:
            print(f"Processing step-specific card for step_pk: {step_pk}")
            try:
                workflow_step_for_context = self.get_workflow_step_for_view(assessment, step_pk, request)
                card_template = workflow_step_for_context.step_definition.card_template_path
                print(f"Template path from step_definition: '{card_template}'")
            except (Http404, PermissionDenied) as e:
                print(f"Error fetching workflow_step: {str(e)}")
                logger.warning(
                    f"HTMX card load: Error fetching step - {type(e).__name__} for assess_pk={assessment_pk}, step_pk={step_pk}, user={request.user.username}")
                status_code = 404 if isinstance(e, Http404) else 403
                error_card_html = render_to_string('tracker/partials/_default_card_content.html', {
                    'assessment': assessment, 'workflow_step': None,
                    'error_message': _("Error loading step details. It may not exist or you may not have permission.")
                }, request=request)
                return HttpResponse(error_card_html, status=status_code)
        else:
            print("Error: Neither card_name nor step_pk provided.")
            return HttpResponseBadRequest("Card identifier not provided.")

        if not card_template:
            print(f"Error: No card_template could be determined. Using default error card.")
            logger.warning(
                f"No card template could be determined for assess_pk={assessment_pk}, step_pk={step_pk}, card_name={card_name}. Using default.")
            card_template = 'tracker/partials/_default_card_content.html'
            base_context = {
                'assessment': assessment,
                'workflow_step': workflow_step_for_context,
                'error_message': _("Content card not configured or found.")
            }
            html_content = render_to_string(card_template, base_context, request=request)
            response = HttpResponse(html_content)
            if step_pk: response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'stepPk': step_pk}})
            return response

        print(f"Attempting to use card_template: '{card_template}'")
        base_context = {'assessment': assessment, 'workflow_step': workflow_step_for_context, 'user': request.user}

        function_name_str = self.CONTEXT_FUNCTION_MAP.get(card_template)
        print(f"Context function name from CONTEXT_FUNCTION_MAP: '{function_name_str}' for template '{card_template}'")
        specific_context = {}

        if function_name_str:
            print(
                f"Checking if 'step_views' module (imported as '{step_views.__name__}') has attribute '{function_name_str}'")
            if hasattr(step_views, function_name_str):
                context_function = getattr(step_views, function_name_str)
                print(f"Found context function '{function_name_str}' in step_views. Calling it...")
                try:
                    specific_context = context_function(assessment, workflow_step_for_context, request)
                    print(f"Context function '{function_name_str}' executed successfully.")
                except Exception as e_context:
                    print(f"ERROR calling context function '{function_name_str}': {str(e_context)}")
                    logger.error(f"Error calling context function '{function_name_str}': {e_context}", exc_info=True)
                    base_context['card_error'] = _("Error preparing dynamic content for this card.")
            else:
                print(f"ERROR: Context function '{function_name_str}' NOT found in step_views module.")
                logger.error(
                    f"Context function '{function_name_str}' mapped for '{card_template}' but NOT found in step_views module.")
                base_context['card_error'] = _("Card configuration error (server: context function missing).")
        else:
            print(f"No specific context function mapped for template '{card_template}'.")
            logger.info(f"No specific context function mapped for template '{card_template}'. Using base context only.")

        base_context.update(specific_context)
        print(f"Final context keys: {list(base_context.keys())}")

        try:
            html_content = render_to_string(card_template, base_context, request=request)
            print("Successfully rendered template to string.")
        except Exception as e_render_main:
            print(f"ERROR rendering template '{card_template}': {str(e_render_main)}")
            logger.error(f"Error rendering main card template '{card_template}': {e_render_main}", exc_info=True)
            default_error_context = {'assessment': assessment, 'workflow_step': workflow_step_for_context,
                                     'error_message': _("Error rendering this content card.")}
            html_content = render_to_string('tracker/partials/_default_card_content.html', default_error_context,
                                            request=request)

        response = HttpResponse(html_content)
        if step_pk:
            response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'stepPk': step_pk}})
        elif card_name:
            response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'cardName': card_name}})
        print("--- Exiting LoadAssessmentCardContentView.get() ---")
        return response








# Helper that was in client_views.py, may be needed if not accessible otherwise
def key_to_str(key_tuple):
    """Converts a tuple key (name, vendor_hint) to a string for JSON keys."""
    if isinstance(key_tuple, tuple) and len(key_tuple) == 2:
        return f"{key_tuple[0]} ({key_tuple[1]})"
    return str(key_tuple)  # Fallback

# CHANGES END — 2025-05-20 21:00:00