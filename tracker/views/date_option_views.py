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