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
def view_scan_results_raw(request, assessment_pk, log_id):
    """
    Displays the raw JSON content of a previously fetched and saved Tenable scan report
    by rendering the client_scan_results_raw.html template.
    """
    # [DEBUG] view_scan_results_raw called at 2025-05-18 17:05:00
    logger.info(
        f"[DEBUG] view_scan_results_raw called for log_id: {log_id}, assessment_pk: {assessment_pk} at {timezone.now()}")

    context = {
        'scan_log': None,
        'report_data_json_str': None,
        'filename': None,
        'assessment_pk': assessment_pk,  # Pass through for template links
        'error_message_custom': None,  # For custom error messages to display in the template
    }

    try:
        scan_log = get_object_or_404(TenableScanLog, id=log_id, assessment_id=assessment_pk)
        context['scan_log'] = scan_log
        context['assessment'] = scan_log.assessment  # For breadcrumbs if needed
    except Http404:
        logger.error(f"TenableScanLog with id {log_id} and assessment_pk {assessment_pk} not found.")
        context['error_message_custom'] = "Error: The specified scan log entry could not be found."
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=404)

    if not scan_log.saved_report_path:
        logger.warning(f"No saved report path found for TenableScanLog id {log_id}.")
        context['error_message_custom'] = (
            "No report has been fetched and saved for this scan log entry yet. "
            "Please use the 'Fetch Results' button on the assessment details page first."
        )
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=404)

    context['filename'] = os.path.basename(scan_log.saved_report_path)
    full_report_path = os.path.join(settings.MEDIA_ROOT, scan_log.saved_report_path)

    if not os.path.exists(full_report_path):
        logger.error(f"Saved report file not found at path: {full_report_path} for scan_log id {log_id}.")
        context['error_message_custom'] = (
            f"Error: The saved report file (<code>{escape(scan_log.saved_report_path)}</code>) "
            "could not be found on the server, even though a path was recorded. "
            "It might have been moved or deleted. Try fetching the results again."
        )
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=404)

    try:
        with open(full_report_path, 'r') as f:
            report_content_json = json.load(f)
        context['report_data_json_str'] = json.dumps(report_content_json, indent=2)

    except FileNotFoundError:  # Should be caught by os.path.exists, but as a fallback
        logger.error(
            f"FileNotFoundError for {full_report_path} (scan_log id {log_id}). This should have been caught by os.path.exists.")
        context['error_message_custom'] = f"Error: Report file not found at <code>{escape(full_report_path)}</code>."
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=404)
    except json.JSONDecodeError:
        logger.error(f"JSONDecodeError for {full_report_path} (scan_log id {log_id}). The file might be corrupted.")
        context['error_message_custom'] = (
            f"Error: Could not decode the JSON report file at <code>{escape(full_report_path)}</code>. "
            "The file may be corrupted. Try fetching the results again."
        )
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=500)
    except Exception as e:
        logger.exception(
            f"An unexpected error occurred while trying to display report {full_report_path} for scan_log {log_id}: {e}")
        context['error_message_custom'] = f"An unexpected error occurred: {escape(str(e))}"
        return render(request, 'tracker/client/client_scan_results_raw.html', context, status=500)

    return render(request, 'tracker/client/client_scan_results_raw.html', context)

@login_required
def get_scan_log_summary_htmx(request, log_id):
    # [DEBUG] get_scan_log_summary_htmx called for log_id: {{ log_id }} at {{ timezone.now() }}
    try:
        scan_log = get_object_or_404(
            TenableScanLog.objects.select_related('assessment__client'),
            id=log_id
        )
        if not request.user.is_staff:
            if not (hasattr(scan_log.assessment, 'client') and hasattr(scan_log.assessment.client,
                                                                       'user_profile') and scan_log.assessment.client.user_profile.user == request.user):
                logger.warning(f"User {request.user.username} permission denied for scan_log {log_id}.")
                raise Http404("Permission denied.")

    except (TenableScanLog.DoesNotExist, ValueError, Http404):
        logger.warning(f"Scan log {log_id} not found or access denied for user {request.user.username}.")
        return HttpResponse("Scan log not found or access denied.", status=404)

    scan_deleted_in_tenable = False
    tenable_api_error_message = None
    updated_fields = []
    tio = None

    try:
        tio = get_tenable_io_client()
        if not tio:
            raise ValueError("Tenable API client could not be initialized. Check configuration.")

        tenable_status_from_api = None
        history_item_details_dict = None  # This will store the specific history entry if found

        # Priority 1: Check specific scan run (history) if UUIDs are available
        if scan_log.tenable_scan_run_uuid and scan_log.tenable_scan_definition_id:
            logger.info(
                f"Attempting to find specific scan run UUID: {scan_log.tenable_scan_run_uuid} within history of Def ID: {scan_log.tenable_scan_definition_id}")
            try:
                # CHANGES BEGIN — GEMINI-2025-05-17 12:30:00
                # Iterate through history as per user's documentation check for their pytenable version
                # tio.scans.history(scan_id) returns an iterator
                found_specific_run = False
                history_iterator = tio.scans.history(scan_id=scan_log.tenable_scan_definition_id)

                for history_entry in history_iterator:

                    logger.info( f"[DEBUG] {history_entry}")

                    # Each 'history_entry' is a dict. We need to find the one matching our run_uuid.
                    # The field containing the run's unique UUID in the history entry is typically 'history_uuid' or 'uuid'.
                    # Let's check for 'uuid' first as it's common, then 'history_uuid'.
                    # The value from Tenable needs to be compared with str(scan_log.tenable_scan_run_uuid)

                    entry_run_uuid = history_entry.get('scan_uuid')  # Common key for the run's own UUID
                    if not entry_run_uuid:  # Fallback if 'uuid' is not the key
                        entry_run_uuid = history_entry.get('history_uuid')

                    if entry_run_uuid and entry_run_uuid == str(scan_log.tenable_scan_run_uuid):
                        history_item_details_dict = history_entry  # Found the specific run
                        tenable_status_from_api = history_item_details_dict.get('status')
                        logger.info(
                            f"Found matching Tenable history entry for run {scan_log.tenable_scan_run_uuid}. Status: {tenable_status_from_api}")
                        found_specific_run = True
                        break  # Exit loop once found

                if not found_specific_run:
                    logger.warning(
                        f"Scan run UUID {scan_log.tenable_scan_run_uuid} not found within the history of definition ID {scan_log.tenable_scan_definition_id}.")
                    tenable_status_from_api = "RUN_NOT_FOUND_IN_HISTORY"
                # CHANGES END — GEMINI-2025-05-17 12:30:00

            except APIError as e:
                if e.code == 404:  # 404 on the scan_definition_id itself when trying to get history
                    logger.warning(
                        f"Scan definition ID {scan_log.tenable_scan_definition_id} not found in Tenable (404) when trying to fetch history for run {scan_log.tenable_scan_run_uuid}.")
                    scan_deleted_in_tenable = True  # If definition is gone, run is effectively gone too.
                    tenable_status_from_api = "DELETED_IN_TENABLE"
                else:
                    logger.error(
                        f"Tenable API error fetching history for def ID {scan_log.tenable_scan_definition_id} (run {scan_log.tenable_scan_run_uuid}): {e}",
                        exc_info=True)
                    tenable_api_error_message = f"API Error (History Fetch): {e.code} - {e.msg if hasattr(e, 'msg') else str(e)}"
            except Exception as e_hist:  # Catch other errors during history iteration
                logger.error(
                    f"Error processing history for def ID {scan_log.tenable_scan_definition_id} (run {scan_log.tenable_scan_run_uuid}): {e_hist}",
                    exc_info=True)
                tenable_api_error_message = f"Error processing scan history: {str(e_hist)}"

        # Priority 2: If no specific run status found (or no run_uuid), check the scan definition's general status
        if not tenable_status_from_api or tenable_status_from_api in ["RUN_NOT_FOUND_IN_HISTORY"]:
            if scan_log.tenable_scan_definition_id:
                logger.info(
                    f"Attempting to fetch Tenable details for scan definition ID: {scan_log.tenable_scan_definition_id} (as run info was inconclusive or not applicable).")
                try:
                    scan_def_details = tio.scans.details(scan_id=scan_log.tenable_scan_definition_id)
                    if scan_def_details:
                        current_def_status = scan_def_details.get('status')
                        logger.info(
                            f"Tenable status for definition {scan_log.tenable_scan_definition_id}: {current_def_status}")
                        # Only overwrite if we didn't get a more specific status like "RUN_NOT_FOUND_IN_HISTORY"
                        # or if tenable_status_from_api is still None
                        if not tenable_status_from_api or tenable_status_from_api == "RUN_NOT_FOUND_IN_HISTORY":
                            tenable_status_from_api = current_def_status

                        if scan_log.scan_name != scan_def_details.get('name'):
                            scan_log.scan_name = scan_def_details.get('name')
                            updated_fields.append('scan_name')
                except APIError as e:
                    if e.code == 404:
                        logger.warning(
                            f"Scan definition ID {scan_log.tenable_scan_definition_id} also not found in Tenable (404). Scan is likely deleted.")
                        scan_deleted_in_tenable = True
                        tenable_status_from_api = "DELETED_IN_TENABLE"
                    else:
                        logger.error(
                            f"Tenable API error fetching scan definition details for {scan_log.tenable_scan_definition_id}: {e}",
                            exc_info=True)
                        if not tenable_api_error_message:
                            tenable_api_error_message = f"API Error (Definition Details): {e.code} - {e.msg if hasattr(e, 'msg') else str(e)}"
            elif scan_log.tenable_scan_run_uuid and not scan_log.tenable_scan_definition_id:  # Should be rare
                logger.warning(
                    f"Scan log {log_id} has a run UUID but no definition ID. Cannot fetch definition status.")
                if tenable_status_from_api in ["RUN_NOT_FOUND_IN_HISTORY"]:
                    scan_deleted_in_tenable = True
                    tenable_status_from_api = "DELETED_IN_TENABLE"

        # Update local scan_log status based on what was fetched
        if tenable_status_from_api:
            new_status_candidate = tenable_status_from_api.upper().replace(" ", "_")

            if scan_log.status != new_status_candidate:
                scan_log.status = new_status_candidate
                updated_fields.append('status')

            current_log_message = scan_log.log_message or ""
            refresh_message = f"Status refreshed from Tenable at {timezone.now().strftime('%Y-%m-%d %H:%M')}: API reported '{tenable_status_from_api}'."

            if not current_log_message.endswith(f"API reported '{tenable_status_from_api}'."):
                scan_log.log_message = f"{current_log_message}\n{refresh_message}".strip()
                updated_fields.append('log_message')

        if scan_deleted_in_tenable and scan_log.status != "DELETED_IN_TENABLE":
            scan_log.status = "DELETED_IN_TENABLE"
            updated_fields.append('status')
            if not (scan_log.log_message and "confirmed deleted in Tenable" in scan_log.log_message):
                scan_log.log_message = f"{scan_log.log_message or ''}\nScan (run/definition) confirmed deleted in Tenable at {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}.".strip()
                updated_fields.append('log_message')

        if updated_fields:
            scan_log.save(update_fields=list(set(updated_fields)))
            logger.info(f"Updated TenableScanLog {scan_log.id} with fields: {updated_fields}")

    except ValueError as ve:
        logger.error(f"Configuration or Value error for scan log {log_id}: {ve}", exc_info=True)
        tenable_api_error_message = str(ve)
    except APIError as e:
        logger.error(f"General Tenable API error for scan log {log_id}: {e}", exc_info=True)
        tenable_api_error_message = f"Tenable API Error: {e.code} - {e.msg if hasattr(e, 'msg') else str(e)}"
        if scan_log and scan_log.status != "API_ERROR":
            scan_log.status = "API_ERROR"
            scan_log.save(update_fields=['status'])
    except Exception as e:
        logger.error(f"Unexpected error processing scan log {log_id} summary: {e}", exc_info=True)
        tenable_api_error_message = f"An unexpected error occurred: {str(e)}"
        if scan_log and scan_log.status != "SYSTEM_ERROR":
            scan_log.status = "SYSTEM_ERROR"
            scan_log.save(update_fields=['status'])

    context = {
        'scan_log': scan_log,
        'scan_deleted_in_tenable': scan_deleted_in_tenable,
        'tenable_api_error_message': tenable_api_error_message,
        'assessment_id': scan_log.assessment.id
    }
    return render(request, 'tracker/partials/client_scan_log_summary_content.html', context)


@login_required
def delete_scan_log_htmx(request, log_id):
    # [DEBUG] delete_scan_log_htmx called for log_id: {{ log_id }} at {{ timezone.now() }}
    if request.method == 'POST':  # Using POST for simplicity with hx-post
        try:
            # Add permission check: ensure user can delete this log
            # Example, adjust to your permission model:
            scan_log = get_object_or_404(
                TenableScanLog,
                id=log_id
                # assessment__client__user_profile__user=request.user # Example permission
            )
            # Add a more robust permission check here based on your application's roles
         #   if not request.user.is_staff:  # Example: only staff can delete
         #       if not (hasattr(scan_log.assessment, 'client') and hasattr(scan_log.assessment.client,
         #                                                                  'user_profile') and scan_log.assessment.client.user_profile.user == request.user):
         #           logger.warning(f"User {request.user.username} permission denied for deleting scan_log {log_id}.")
         #           return HttpResponse("Permission denied.", status=403)

            log_name_for_audit = scan_log.scan_name or str(scan_log.id)
            scan_log.delete()
            logger.info(f"User {request.user.username} deleted TenableScanLog ID {log_id} ('{log_name_for_audit}').")
            # For HTMX, returning an empty 200 response is often enough if hx-swap="outerHTML" is used on the target.
            # The target element (the accordion item) will be removed.
            return HttpResponse(status=200)
        except TenableScanLog.DoesNotExist:
            return HttpResponse("Scan log not found or access denied.", status=404)
        except Exception as e:
            logger.error(f"Error deleting scan_log ID {log_id} by user {request.user.username}: {e}", exc_info=True)
            # You might want to return a specific error message to HTMX if needed
            return HttpResponse(f"Error deleting log: {str(e)}", status=500)
    return HttpResponseBadRequest("Invalid request method.")
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
        # Make sure 'json' and 'DjangoJSONEncoder' are imported at the top of views_old.py
        context['os_data_json'] = json.dumps(os_data_for_js, cls=DjangoJSONEncoder)
        # --- END: Ensure this block is present ---

        return context

    def get_success_url(self):
        """Redirect back to the scope management page."""
        return reverse_lazy('tracker:client_scope_manage', kwargs={'assessment_pk': self.assessment.pk})
class AssessmentUpdateStatusView(AssessorOrAdminRequiredMixin, UpdateView): # Allow Admin too
    model = Assessment
    form_class = AssessmentStatusUpdateForm
    template_name = 'tracker/assessor/assessment_update_form.html' # Can be integrated

    def get_queryset(self):
        # Allow admin to update any, assessor only their own
        user = self.request.user
        if is_admin(user):
            return Assessment.objects.all()
        elif is_assessor(user):
             return Assessment.objects.filter(assessor=user)
        return Assessment.objects.none()

    def form_valid(self, form):
        assessment = self.get_object()
        old_status = assessment.get_status_display() # Get display value for log
        assessment = form.save() # Save first to get updated instance
        new_status = assessment.get_status_display()

        # Log event if status actually changed
        if old_status != new_status:
             log_message = f"Assessment status changed from '{old_status}' to '{new_status}'."
             if form.cleaned_data.get('final_outcome'):
                 log_message += f" Final outcome set to '{form.cleaned_data['final_outcome']}'."
             log_assessment_event(assessment, self.request.user, log_message)

        messages.success(self.request, f"Assessment status updated successfully.")
        return redirect(self.get_success_url())

    def get_success_url(self):
        # Redirect back to the detail view based on user role
        user = self.request.user
        if is_admin(user):
            # Admin might want to go back to the Admin detail view if one exists, or list
             return reverse('tracker:admin_assessment_list') # Adjust if admin detail view exists
        else: # Assessor
             return reverse('tracker:assessor_assessment_detail', kwargs={'pk': self.object.pk})
class AssessmentCloudServiceListView(LoginRequiredMixin, ListView):
    model = AssessmentCloudService
    template_name = 'tracker/assessment_cloud_service/service_list.html'
    context_object_name = 'assessment_services'

    def dispatch(self, request, *args, **kwargs):
        """Get assessment and check permissions before proceeding."""
        self.assessment = get_object_or_404(Assessment, pk=self.kwargs['assessment_pk'])
        if not user_can_manage_assessment_cloud_services(request.user, self.assessment):
            raise PermissionDenied("You do not have permission to view cloud services for this assessment.")
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        """Return services belonging to the specific assessment."""
        return AssessmentCloudService.objects.filter(
            assessment=self.assessment
        ).select_related('cloud_service_definition').order_by('cloud_service_definition__name')

    def get_context_data(self, **kwargs):
        """Add assessment and other context."""
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Cloud Services for Assessment #{self.assessment.id}"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        # Determine if adding should be allowed based on status
        context['can_add_services'] = not self.assessment.status.startswith('Complete_')
        # Pass is_client flag for potential template use
        context['is_client_user'] = is_client(self.request.user)
        return context
class AssessmentCloudServiceAddView(LoginRequiredMixin, CreateView):
    model = AssessmentCloudService
    form_class = AssessmentCloudServiceForm
    template_name = 'tracker/assessment_cloud_service/assessment_cloud_service_add_form.html'

    # Ensure this setup method is present to set self.assessment early
    def setup(self, request, *args, **kwargs):
        """Fetches the Assessment object early and stores it on the view instance."""
        super().setup(request, *args, **kwargs) # Call parent setup methods first
        assessment_pk = self.kwargs.get('assessment_pk')
        if assessment_pk:
            # Fetch the Assessment object and store it as an instance attribute
            # This makes self.assessment available to other methods like get_context_data
            self.assessment = get_object_or_404(Assessment, pk=assessment_pk)
        else:
            # If assessment_pk is missing from URL kwargs, raise an error early
            raise Http404("Assessment primary key not found in URL for view setup")
        # Add any permission checks related to self.assessment here if needed
        # e.g., check if self.request.user belongs to self.assessment.client

    # get_context_data can now safely use self.assessment set by setup()
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # self.assessment should exist now if setup ran correctly and didn't raise Http404
        context['assessment'] = self.assessment # Pass object to template context
        context['page_title'] = f"Add Cloud Service for Assessment {self.assessment.id}" # Use self.assessment safely

        # Pass role flags (useful for base templates or conditional rendering)
        profile = getattr(self.request.user, 'userprofile', None)
        context['is_client_user'] = profile and profile.role == 'Client'
        context['is_assessor_or_admin'] = profile and profile.role in ['Assessor', 'Admin']
        context['user_role'] = profile.role if profile else None
        return context

    # get_form_kwargs fetches assessment independently to pass specifically to the form.
    # This provides robustness in case of complex MRO issues with mixins/setup timing.
    def get_form_kwargs(self):
        """Pass assessment to the form's __init__ method."""
        kwargs = super().get_form_kwargs()
        assessment_pk = self.kwargs.get('assessment_pk')
        if assessment_pk:
            # Fetch assessment again here to pass specifically to the form kwargs
            assessment = get_object_or_404(Assessment, pk=assessment_pk)
            kwargs['assessment'] = assessment
        else:
            # This path should ideally not be reached if setup runs first and raises Http404
            kwargs['assessment'] = None
            messages.error(self.request,"Critical Error: Assessment ID missing when initializing form.")

        # NOTE: Do NOT pass 'user' here unless the form's __init__ explicitly handles it.
        # kwargs['user'] = self.request.user # This caused the TypeError previously

        return kwargs

    # form_valid uses self.assessment (set by setup) and self.request.user
    def form_valid(self, form):
        print("\n--- DEBUG: form_valid entered ---") # DEBUG
        try:
            print(f"DEBUG: Raw Cleaned data: {form.cleaned_data}") # DEBUG
        except Exception as e:
            print(f"DEBUG: Error printing cleaned_data: {e}") # DEBUG

        # self.assessment should be available here thanks to setup()
        if not hasattr(self, 'assessment') or not self.assessment:
             print("--- DEBUG: CRITICAL ERROR - self.assessment not set in form_valid ---") # DEBUG
             messages.error(self.request, "Critical error: Assessment context lost.")
             return self.form_invalid(form)

        assessment_service = form.save(commit=False)
        assessment_service.assessment = self.assessment # Link to current assessment

        add_new = form.cleaned_data.get('add_new_service')
        existing_service = form.cleaned_data.get('cloud_service_definition')
        print(f"DEBUG: add_new flag: {add_new}") # DEBUG
        print(f"DEBUG: existing_service object: {existing_service}") # DEBUG

        if add_new:
            print("--- DEBUG: Attempting to add new service definition ---") # DEBUG
            try:
                new_def_name = form.cleaned_data.get('new_service_name', 'MISSING_NAME') # DEBUG check if exists
                print(f"DEBUG: New service name from form: {new_def_name}") # DEBUG
                # Ensure user is available
                if not hasattr(self.request, 'user') or not self.request.user.is_authenticated:
                     print("--- DEBUG: ERROR - Request user not available ---") # DEBUG
                     messages.error(self.request, "Error: User information not available.")
                     return self.form_invalid(form)

                new_def = CloudServiceDefinition.objects.create(
                    name=new_def_name,
                    vendor=form.cleaned_data.get('new_service_vendor'),
                    service_url=form.cleaned_data.get('new_service_url'),
                    description=form.cleaned_data.get('new_service_description'),
                    requires_mfa_for_ce=form.cleaned_data.get('new_service_requires_mfa', False),
                    is_globally_approved=False,
                    created_by=self.request.user # Use user from request
                )
                assessment_service.cloud_service_definition = new_def
                print(f"--- DEBUG: New Definition Created, PK: {new_def.pk} ---") # DEBUG
                messages.info(self.request, f"New service '{new_def.name}' suggested and added to assessment pending approval.")
            except Exception as e:
                 print(f"--- DEBUG: ERROR creating new CloudServiceDefinition: {e} ---") # DEBUG
                 import traceback # DEBUG
                 traceback.print_exc() # DEBUG - Print full traceback to console
                 messages.error(self.request, f"Error creating suggested service: {e}")
                 return self.form_invalid(form)

        elif existing_service:
             print(f"--- DEBUG: Linking to existing service: {existing_service.name} (PK: {existing_service.pk}) ---") # DEBUG
             # The form linking should already be done by form.save(commit=False) if field is in form.Meta.fields
             assessment_service.cloud_service_definition = existing_service # Ensure it's set if not done by form
             messages.success(self.request, f"Service '{existing_service.name}' added to assessment.")
        else:
             # This should be caught by form validation, but double-check
             print("--- DEBUG: ERROR - Neither add_new nor existing_service is true after clean() ---") # DEBUG
             messages.error(self.request, "Could not add service. No existing service selected or new service suggested properly.")
             return self.form_invalid(form)

        # --- Attempt to save the AssessmentCloudService ---
        try:
            print(f"--- DEBUG: Attempting to save AssessmentCloudService ---") # DEBUG
            print(f"DEBUG: Assessment PK: {assessment_service.assessment.pk if assessment_service.assessment else 'None'}") # DEBUG
            print(f"DEBUG: Service Definition: {assessment_service.cloud_service_definition}") # DEBUG
            print(f"DEBUG: Client Notes: {assessment_service.client_notes}") # DEBUG
            # Add prints for mfa proof fields if needed

            assessment_service.save() # Save the AssessmentCloudService instance

            print(f"--- DEBUG: AssessmentCloudService SAVED, PK: {assessment_service.pk} ---") # DEBUG
            # save_m2m is only needed if the form has M2M fields, which this one doesn't seem to
            # form.save_m2m()
            # print("--- DEBUG: save_m2m called (if applicable) ---") # DEBUG

        except Exception as e:
            print(f"--- DEBUG: ERROR saving AssessmentCloudService: {e} ---") # DEBUG
            import traceback # DEBUG
            traceback.print_exc() # DEBUG - Print full traceback to console
            messages.error(self.request, f"Error saving service to assessment: {e}")
            # If a new definition was created, consider deleting it on failure
            if add_new and 'new_def' in locals() and new_def:
                try:
                    print(f"--- DEBUG: Attempting to delete newly created definition {new_def.pk} due to save error ---") # DEBUG
                    new_def.delete()
                except Exception as del_e:
                    print(f"--- DEBUG: Error deleting new_def after save failure: {del_e} ---") # DEBUG
            return self.form_invalid(form)

        print("--- DEBUG: form_valid completed successfully, redirecting ---") # DEBUG
        return redirect(self.get_success_url())

    # get_success_url uses self.assessment set by setup()
    def get_success_url(self):
         # Clients typically add services, redirect to their list view
         # self.assessment should exist here
         return reverse('tracker:client_assessment_cloud_service_list', kwargs={'assessment_pk': self.assessment.pk})
class AssessmentCloudServiceUpdateView(LoginRequiredMixin, UpdateView):
    model = AssessmentCloudService
    # No static form_class anymore, determined by get_form_class
    # Use the new template for updating
    template_name = 'tracker/assessment_cloud_service/assessment_cloud_service_update_form.html'


    # Assessment is set by AssessmentRelatedObjectMixin in setup

    def get_form_class(self):
        """Return the form class to use based on user role."""
        profile = getattr(self.request.user, 'userprofile', None)
        # Check if user is associated with the assessment's client or is Assessor/Admin
        # You might need more specific permission checks here

        if profile and profile.role == 'Client':
             # Add check: Is this user part of the client company for this assessment?
             if self.object.assessment.client == profile.client:
                 return AssessmentCloudServiceUpdateForm
             else:
                  raise PermissionDenied("You are not authorized to edit this service for this client.")
        elif profile and profile.role in ['Assessor', 'Admin']:
             # Add check: Is this assessor assigned to this assessment? (If applicable)
             # Or just allow any assessor/admin?
             return AssessmentCloudServiceAssessorForm
        else:
             # Fallback or raise permission denied if user has unexpected/no role
             raise PermissionDenied("You do not have permission to edit this service entry.")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # assessment context usually added by mixin
        # context['assessment'] = self.object.assessment
        # Pass role flags needed by the template for conditional rendering
        profile = getattr(self.request.user, 'userprofile', None)
        context['is_client_user'] = profile and profile.role == 'Client'
        context['is_assessor_or_admin'] = profile and profile.role in ['Assessor', 'Admin']
        context['user_role'] = profile.role if profile else None

        # Keep service name for display
        context['service_name'] = self.object.cloud_service_definition.name if self.object.cloud_service_definition else "Suggested Service (Pending Approval)"
        context['page_title'] = f"Update {context['service_name']}"
        return context

    def get_form_kwargs(self):
        """ Pass assessment or other args if needed by forms """
        kwargs = super().get_form_kwargs()
        # Pass assessment if any update form needs it (unlikely for these simple forms)
        # kwargs['assessment'] = self.object.assessment
        return kwargs

    def form_valid(self, form):
        """Handle saving for both client and assessor forms."""
        instance = form.save(commit=False)
        profile = getattr(self.request.user, 'userprofile', None)
        user_role = profile.role if profile else None

        if user_role in ['Assessor', 'Admin']:
            # Specific logic for assessor form submission
            # Check if any verification fields actually changed to set timestamp/user
            changed_fields = form.changed_data
            verification_fields = ['mfa_admin_verified', 'mfa_user_verified', 'is_compliant', 'assessor_notes']
            if any(field in changed_fields for field in verification_fields):
                instance.verified_by = self.request.user
                instance.last_verified_at = timezone.now()
            messages.success(self.request, "Verification details updated successfully.")

        elif user_role == 'Client':
             # Logic specific to client form submission
             # Check if files were cleared or changed
             if 'mfa_admin_proof' in form.changed_data or 'mfa_user_proof' in form.changed_data:
                 messages.success(self.request, "MFA Proof files updated successfully.")
             elif 'client_notes' in form.changed_data:
                 messages.success(self.request, "Client notes updated successfully.")
             elif form.changed_data: # Check if anything else changed
                  messages.success(self.request, "Service details updated successfully.")
             else:
                  messages.info(self.request, "No changes were detected.")
                  # Redirect immediately if no changes, skip save
                  return redirect(self.get_success_url())

        else:
             # Handle unexpected role - shouldn't happen if get_form_class works
             messages.error(self.request, "Could not save changes due to permission issue.")
             return self.form_invalid(form)

        try:
            instance.save()
            form.save_m2m() # If there were any M2M fields
        except Exception as e:
             messages.error(self.request, f"Error saving changes: {e}")
             return self.form_invalid(form)

        return redirect(self.get_success_url())

    def get_success_url(self):
        """Redirect back to the appropriate list view based on user role."""
        profile = getattr(self.request.user, 'userprofile', None)
        assessment_pk = self.object.assessment.pk
        if profile and profile.role == 'Client':
             # Use the client-specific list URL from your urls.py
             return reverse('tracker:client_assessment_cloud_service_list', kwargs={'assessment_pk': assessment_pk})
        else: # Assessor or Admin
             # Use the assessor/admin list URL from your urls.py
             return reverse('tracker:assessment_cloud_service_list', kwargs={'assessment_pk': assessment_pk})
class AssessmentCloudServiceDeleteView(LoginRequiredMixin, DeleteView):
    model = AssessmentCloudService
    template_name = 'tracker/assessment_cloud_service/service_confirm_delete.html'
    context_object_name = 'assessment_service'

    def dispatch(self, request, *args, **kwargs):
        """Get assessment and check permissions before proceeding."""
        self.object = self.get_object()
        self.assessment = self.object.assessment
        if not user_can_manage_assessment_cloud_services(request.user, self.assessment):
            raise PermissionDenied("You do not have permission to delete this cloud service entry.")
        # Prevent deletion if assessment is complete? Usually okay to delete.
        # if self.assessment.status.startswith('Complete_'):
        #     raise PermissionDenied("Cannot delete cloud services from a completed assessment.")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        """Add success message and log."""
        service_name = self.object.cloud_service_definition.name
        # Consider deleting uploaded files here if desired
        # (obj.mfa_admin_proof.delete(save=False), obj.mfa_user_proof.delete(save=False))
        # before calling super().form_valid()
        response = super().form_valid(form)
        messages.success(self.request, f"Cloud Service '{service_name}' removed from assessment.")
        log_assessment_event(self.assessment, self.request.user, f"Cloud service removed: '{service_name}'.")
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['assessment'] = self.assessment
        context['page_title'] = f"Remove Cloud Service: {self.object.cloud_service_definition.name}"
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None
        return context

    def get_success_url(self):
        """Redirect back to the service list."""
        if is_client(self.request.user):
            return reverse('tracker:client_assessment_cloud_service_list', kwargs={'assessment_pk': self.assessment.pk})
        else:
            return reverse('tracker:assessment_cloud_service_list', kwargs={'assessment_pk': self.assessment.pk})
class AssessmentCreateView(AdminRequiredMixin, CreateView):
    model = Assessment
    form_class = AssessmentCreateForm
    template_name = 'tracker/admin/assessment_form.html'
    success_url = reverse_lazy('tracker:admin_assessment_list')

    def form_valid(self, form):
        self.object = form.save()
        log_assessment_event(self.object, self.request.user, f"Assessment created ({self.object.get_assessment_type_display()}) for {self.object.client.name}.")
        messages.success(self.request, f"Assessment for '{self.object.client.name}' created.")
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, "Failed to create assessment. Please check the form data.")
        return super().form_invalid(form)
class AssessmentDeleteView(AdminRequiredMixin, DeleteView):
    model = Assessment
    template_name = 'tracker/admin/assessment_confirm_delete.html' # Template we will create next
    success_url = reverse_lazy('tracker:admin_assessment_list')
    context_object_name = 'assessment' # To refer to the assessment in the template

    def delete(self, request, *args, **kwargs):
        """
        Adds a success message upon successful deletion.
        """
        assessment = self.get_object() # Get object before deleting it
        assessment_id = assessment.id
        client_name = assessment.client.name # Get client name for the message

        # Call the superclass's delete method
        response = super().delete(request, *args, **kwargs)

        # Add success message
        messages.success(request, f"Assessment #{assessment_id} for client '{client_name}' deleted successfully.")
        return response


    def get_context_data(self, **kwargs):
         context = super().get_context_data(**kwargs)
         context['page_title'] = f"Confirm Deletion of Assessment {self.object.id}"
         return context
class AdminAssessmentListView(AdminRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/admin/assessment_list.html'
    context_object_name = 'assessments'
    queryset = Assessment.objects.select_related('client', 'assessor__userprofile').order_by('-created_at') # Include assessor profile if needed