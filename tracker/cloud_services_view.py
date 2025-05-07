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
    NessusAgentURL
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



class CloudServiceDefinitionListView(AssessorOrAdminRequiredMixin, ListView):
    model = CloudServiceDefinition
    template_name = 'tracker/cloud_service_mgmt/definition_list.html' # Template to create
    context_object_name = 'definitions'
    paginate_by = 20
    queryset = CloudServiceDefinition.objects.order_by('vendor', 'name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = "Manage Cloud Service Definitions"
        # --- NEW: Add count for pending approval ---
        context['pending_approval_count'] = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()
        # --- END NEW ---
        return context
class CloudServiceDefinitionCreateView(AssessorOrAdminRequiredMixin, CreateView):
    model = CloudServiceDefinition
    form_class = CloudServiceDefinitionForm
    template_name = 'tracker/cloud_service_mgmt/definition_form.html' # Template to create
    success_url = reverse_lazy('tracker:cloud_service_definition_list')

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        # If an admin/assessor creates it AND checks 'approved', set approved_by
        if form.cleaned_data.get('is_globally_approved'):
             form.instance.approved_by = self.request.user
        messages.success(self.request, f"Cloud Service Definition '{form.instance.name}' created.")
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = "Add New Cloud Service Definition"
        return context
class CloudServiceDefinitionUpdateView(AssessorOrAdminRequiredMixin, UpdateView):
    model = CloudServiceDefinition
    form_class = CloudServiceDefinitionForm
    template_name = 'tracker/cloud_service_mgmt/definition_form.html'
    context_object_name = 'definition'
    success_url = reverse_lazy('tracker:cloud_service_definition_list')

    def form_valid(self, form):
         # If the approval status changed to True, record who approved it
        if 'is_globally_approved' in form.changed_data and form.cleaned_data.get('is_globally_approved'):
            if not form.instance.approved_by: # Only set if not already set
                form.instance.approved_by = self.request.user
        elif 'is_globally_approved' in form.changed_data and not form.cleaned_data.get('is_globally_approved'):
             # Clear approver if unchecked? Optional, depends on desired logic.
             form.instance.approved_by = None # Example: Clear approver if unapproved

        messages.success(self.request, f"Cloud Service Definition '{form.instance.name}' updated.")
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = f"Edit Cloud Service Definition: {self.object.name}"
        return context
class CloudServiceDefinitionDeleteView(AdminRequiredMixin, DeleteView): # Only Admins can delete definitions? Or Assessor too? Decide permission.
    model = CloudServiceDefinition
    template_name = 'tracker/cloud_service_mgmt/definition_confirm_delete.html' # Template to create
    context_object_name = 'definition'
    success_url = reverse_lazy('tracker:cloud_service_definition_list')

    def form_valid(self, form):
        # Handle ProtectedError in case definitions are linked via PROTECT
        try:
            definition_name = self.object.name
            response = super().form_valid(form)
            messages.success(self.request, f"Cloud Service Definition '{definition_name}' deleted.")
            return response
        except ProtectedError:
            messages.error(self.request, f"Cannot delete '{self.object.name}' as it is linked to one or more assessments.")
            return redirect('tracker:cloud_service_definition_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = f"Delete Cloud Service Definition: {self.object.name}"
        return context
