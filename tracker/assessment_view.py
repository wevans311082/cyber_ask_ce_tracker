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
log_assessment_event,
user_can_manage_assessment_cloud_services
)

from .mixin import (
ClientRequiredMixin,
AdminRequiredMixin,
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin

)

logger = logging.getLogger(__name__)

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