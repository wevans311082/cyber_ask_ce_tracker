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