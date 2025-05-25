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
