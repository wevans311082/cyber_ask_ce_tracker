from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse_lazy, reverse
from django.views import View
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView, FormView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib import messages
from datetime import date
from django.utils import timezone
from django.db.models.functions import Concat, Coalesce
from django.core.exceptions import PermissionDenied # Import PermissionDenied
from django.forms import modelformset_factory # For scope items potentially
from django.db.models import ProtectedError # <-- ADD THIS LINE
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from collections import defaultdict
from django.http import HttpResponseRedirect
from django.db import IntegrityError
from django.utils import timezone # Add timezone import
from .models import ExternalIP, Assessment # Add ExternalIP model
from .forms import ExternalIPForm, ExternalIPScanUpdateForm
from django.contrib.auth.mixins import UserPassesTestMixin
from django.core.serializers.json import DjangoJSONEncoder
from django.contrib.auth.mixins import LoginRequiredMixin # Use appropriate mixin
from .forms import UploadReportForm # Import the new form
from .models import UploadedReport, Assessment # Import new model
from .pdf_extractor import extract_ce_data_from_pdf
import json
import os
import requests
import random
from django.db import transaction # Import transaction
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.conf import settings
from datetime import datetime


from django.http import HttpResponseForbidden, FileResponse, Http404, JsonResponse # Added JsonResponse
from django.db.models import Count, Min, Value, CharField, ProtectedError
from .models import Client, UserProfile, Assessment, ScopedItem, Evidence, AssessmentLog, OperatingSystem, Network, CloudServiceDefinition, AssessmentCloudService
from .models import Assessment, AssessmentWorkflowStep
from .forms import (
    ClientForm, CustomUserCreationForm, CustomUserChangeForm, AssessmentCreateForm,
    AssessmentStatusUpdateForm, EvidenceForm,
    OperatingSystemForm, NetworkForm, CloudServiceDefinitionForm, AssessmentCloudServiceForm,  AssessmentCloudServiceAssessorForm, ScopedItemForm, ScopedItemUpdateForm, AssessmentCloudServiceUpdateForm
)
from django.contrib.auth.models import User
import requests # Import requests library for API calls
from requests.auth import HTTPBasicAuth # For API authentication



def calculate_sample_size(count):
    """Calculates required sample size based on the provided table."""
    if count <= 0:
        return 0
    elif count == 1:
        return 1
    elif 2 <= count <= 5:
        return 2
    elif 6 <= count <= 19:
        return 3
    elif 20 <= count <= 60:
        return 4
    else: # 61+
        return 5
def is_admin(user):
    # Ensure user is authenticated and has a profile before checking role
    return user.is_authenticated and hasattr(user, 'userprofile') and user.userprofile is not None and user.userprofile.role == 'Admin'
def is_assessor(user):
    return user.is_authenticated and hasattr(user, 'userprofile') and user.userprofile is not None and user.userprofile.role == 'Assessor'
def is_client(user):
    return user.is_authenticated and hasattr(user, 'userprofile') and user.userprofile is not None and user.userprofile.role == 'Client'
def user_can_manage_assessment_networks(user, assessment):
    """Checks if a user can manage networks for a given assessment."""
    if not user.is_authenticated:
        return False
    if is_admin(user):
        return True # Admins can manage any
    if is_assessor(user) and assessment.assessor == user:
        return True # Assigned assessor can manage
    if is_client(user) and assessment.client == user.userprofile.client:
        # Allow client management if assessment is not yet completed
        if not assessment.status.startswith('Complete_'):
            return True
    return False
def user_can_manage_assessment_external_ips(user, assessment):
    """
    Checks if a user can VIEW the External IPs list for a given assessment.
    Allows Admins, assigned Assessors, and associated Clients (regardless of assessment status).
    Editing permissions are checked separately.
    """
    if not user.is_authenticated:
        return False
    if is_admin(user):
        return True # Admins can always view

    # Assessors can view their assigned assessments
    if is_assessor(user) and assessment.assessor == user:
        return True

    # Clients can VIEW if it's their assessment (status doesn't restrict viewing list)
    if is_client(user) and hasattr(user, 'userprofile') and assessment.client == user.userprofile.client:
        return True # Allow client to view their list always

    # Default deny if none of the above match
    return False
def is_admin_or_assessor(user):
    return is_admin(user) or is_assessor(user)
def user_can_edit_assessment_external_ips(user, assessment):
    """
    Checks if a user can ADD, EDIT, or DELETE External IPs for an assessment.
    Allows Admins and Assessors (unless assessment is complete).
    Allows Clients only if the 'Define External IPs' workflow step (Order 3)
    is not marked as 'Complete' and the assessment is not fully complete.
    """
    if not user.is_authenticated:
        return False

    # --- Prevent edits on completed assessments for ALL roles ---
    # Uses the string prefix check for simplicity
    if assessment.status.startswith('Complete_'):
        return False

    # --- Admin/Assessor Permissions ---
    # Allow Admin/Assessor edits unless assessment is complete (checked above)
    if is_admin(user):
        return True
    if is_assessor(user) and assessment.assessor == user:
        return True

    # --- Client Permissions Tied to Workflow Step 3 ---
    if is_client(user) and hasattr(user, 'userprofile') and assessment.client == user.userprofile.client:
        try:
            # Find the workflow step for defining external IPs (assuming order 3)
            # Use .select_related('step_definition') for efficiency if needed elsewhere
            external_ip_workflow_step = AssessmentWorkflowStep.objects.get(
                assessment=assessment,
                step_definition__step_order=3 # Step 3 = Define External IPs
            )

            # Allow editing only if this specific step is NOT 'Complete'
            # Uses the Status choices enum defined in the AssessmentWorkflowStep model
            return external_ip_workflow_step.status != AssessmentWorkflowStep.Status.COMPLETE

        except AssessmentWorkflowStep.DoesNotExist:
            # If the workflow step wasn't created for some reason, deny permission
            print(f"Warning: Workflow Step 3 not found for Assessment {assessment.id}. Denying external IP edit permission.")
            return False
        except Exception as e:
            # Log unexpected errors and deny permission
            print(f"Error checking workflow step 3 status for assessment {assessment.id}: {e}")
            return False # Fail safe

    # Default deny if user is not admin, assigned assessor, or associated client
    return False




class AdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_admin(self.request.user)

    def handle_no_permission(self):
        # Optional: Customize response for permission denied
        if not self.request.user.is_authenticated:
            return super().handle_no_permission() # Redirect to login
        messages.error(self.request, "Admin permissions required.")
        # Redirect non-admins somewhere appropriate, maybe the main dashboard
        # Check if user has any profile first
        if hasattr(self.request.user, 'userprofile') and self.request.user.userprofile is not None:
            if is_assessor(self.request.user):
                 return redirect('tracker:assessor_dashboard')
            elif is_client(self.request.user):
                 return redirect('tracker:client_dashboard')
        # Fallback if no role or profile
        return redirect('login')
class AssessorRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_assessor(self.request.user)

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "Assessor permissions required.")
        # Redirect non-assessors
        if is_admin(self.request.user):
            return redirect('tracker:admin_dashboard')
        elif is_client(self.request.user):
            return redirect('tracker:client_dashboard')
        return redirect('login')
class ClientRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        # Also check if the client user is linked to a company
        return is_client(self.request.user) and self.request.user.userprofile.client is not None

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()

        # Check if they are a client but just not linked yet
        if is_client(self.request.user) and self.request.user.userprofile.client is None:
            messages.warning(self.request, "Your client account is not yet linked to a company. Please contact an administrator.")
            return redirect('login') # Or an error page/logout

        messages.error(self.request, "Client permissions required.")
        # Redirect non-clients
        if is_admin(self.request.user):
            return redirect('tracker:admin_dashboard')
        elif is_assessor(self.request.user):
            return redirect('tracker:assessor_dashboard')
        return redirect('login')
class AssessorOrAdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_admin(self.request.user) or is_assessor(self.request.user)

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "Admin or Assessor permissions required.")
        if is_client(self.request.user):
            return redirect('tracker:client_dashboard')
        return redirect('login')
def log_assessment_event(assessment, user, event_description):
    """Creates an AssessmentLog entry."""
    try:
        # Check if user is None or AnonymousUser before logging
        log_user = user if user and user.is_authenticated else None
        AssessmentLog.objects.create(assessment=assessment, user=log_user, event=event_description)
    except Exception as e:
        # Log the error instead of crashing the view
        print(f"Error logging assessment event for assessment {assessment.id}: {e}")
        # Optionally use Python's logging module here
        # import logging
        # logging.error(f"Error logging assessment event for assessment {assessment.id}: {e}", exc_info=True)
        pass # Allow the main view function to continue
@login_required
def dashboard(request):
    user = request.user
    # Check if profile exists FIRST
    if not hasattr(user, 'userprofile') or user.userprofile is None:
         messages.error(request, "Your user profile is not configured. Please contact support.")
         # Log them out explicitly is safer here
         return redirect('logout') # Assumes a logout URL name exists

    # Now check roles
    if is_admin(user):
        return redirect('tracker:admin_dashboard')
    elif is_assessor(user):
        return redirect('tracker:assessor_dashboard')
    elif is_client(user):
         if user.userprofile.client: # Already checked profile exists
             return redirect('tracker:client_dashboard')
         else:
             messages.warning(request, "Your client account is not yet linked to a company. Please contact an administrator.")
             return redirect('logout') # Log out if not linked
    else:
        # Handles cases where profile exists but role is None or invalid
        messages.error(request, "Your user role is not configured correctly. Please contact support.")
        return redirect('logout') # Log out if role invalid
@login_required
@user_passes_test(is_admin, login_url=reverse_lazy('login')) # Redirect to login if test fails
def admin_dashboard(request):
    # --- ADD THIS QUERY ---
    pending_approval_count = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()
    # --- END ADD ---
    context = {
        'user_count': User.objects.count(),
        'client_count': Client.objects.count(),
        'assessment_count': Assessment.objects.count(),
        'assessments_pending_review': Assessment.objects.filter(status='Scoping_Review').count(),
        'pending_approval_count': pending_approval_count, # <-- Add to context
    }
    return render(request, 'tracker/admin/admin_dashboard.html', context)
class ClientListView(AdminRequiredMixin, ListView):
    model = Client
    template_name = 'tracker/admin/client_list.html'
    context_object_name = 'clients'
class ClientCreateView(AdminRequiredMixin, CreateView):
    model = Client
    form_class = ClientForm
    template_name = 'tracker/admin/client_form.html'
    success_url = reverse_lazy('tracker:client_list')

    def form_valid(self, form):
        messages.success(self.request, f"Client '{form.instance.name}' created successfully.")
        return super().form_valid(form)
class ClientUpdateView(AdminRequiredMixin, UpdateView):
    model = Client
    form_class = ClientForm
    template_name = 'tracker/admin/client_form.html'
    success_url = reverse_lazy('tracker:client_list')

    def form_valid(self, form):
        # --- ADDED LOGIC ---
        client_instance = self.get_object() # Get the object *before* saving the form
        name_changed = 'name' in form.changed_data
        number_changed = 'organization_number' in form.changed_data

        if (name_changed or number_changed) and client_instance.companies_house_validated:
            # Reset validation status if relevant fields changed
            form.instance.companies_house_validated = False
            form.instance.last_companies_house_validation = None
            form.instance.validated_name = None # Clear tracked validated data
            form.instance.validated_number = None
            messages.warning(self.request, f"Client details changed. Companies House validation status reset for '{form.instance.name}'. Please re-validate.")
        # --- END ADDED LOGIC ---

        messages.success(self.request, f"Client '{form.instance.name}' updated successfully.")
        return super().form_valid(form)
class ClientDeleteView(AdminRequiredMixin, DeleteView):
    model = Client
    template_name = 'tracker/admin/client_confirm_delete.html'
    success_url = reverse_lazy('tracker:client_list')

    # Removed the 'delete' method override as 'post' handles it now

    def post(self, request, *args, **kwargs):
        """
        Override post to handle ProtectedError during the deletion process,
        which might occur during transaction commit.
        """
        try:
            # Get client name BEFORE attempting delete for the message
            # Note: self.object is set before post runs for DeleteView via get_object
            client_name = self.get_object().name
            # Attempt the deletion process by calling the parent post method
            response = super().post(request, *args, **kwargs)
            # If super().post() succeeds (no exception), add success message
            messages.success(request, f"Client '{client_name}' deleted successfully.")
            return response
        except ProtectedError:
            # If ProtectedError occurs during super().post() execution
            messages.error(request, f"Cannot delete client '{self.get_object().name}' because they have associated assessments. Please delete or reassign their assessments first.")
            return redirect('tracker:client_list')
class UserListView(AdminRequiredMixin, ListView):
    model = User
    template_name = 'tracker/admin/user_list.html'
    context_object_name = 'users'
    queryset = User.objects.select_related('userprofile', 'userprofile__client').order_by('username') # Optimize query
class UserCreateView(AdminRequiredMixin, CreateView):
    model = User
    form_class = CustomUserCreationForm
    template_name = 'tracker/admin/user_form.html'
    success_url = reverse_lazy('tracker:user_list')

    def form_valid(self, form):
        user = form.save() # Form's save method handles User and UserProfile
        messages.success(self.request, f"User '{user.username}' created successfully.")
        return redirect(self.success_url)

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the errors below.")
        return super().form_invalid(form)
class UserUpdateView(AdminRequiredMixin, UpdateView):
    model = User
    form_class = CustomUserChangeForm
    template_name = 'tracker/admin/user_form.html'
    success_url = reverse_lazy('tracker:user_list')

    def get_queryset(self):
         # Ensure we can edit any user, including those without profiles (though forms expect profile)
         return User.objects.select_related('userprofile').all()

    # get_form_kwargs is automatically handled by UpdateView to pass instance

    def form_valid(self, form):
        user = form.save() # Form's save method handles User and UserProfile update
        messages.success(self.request, f"User '{user.username}' updated successfully.")
        return redirect(self.success_url)

    def form_invalid(self, form):
        messages.error(self.request, "Please correct the errors below.")
        return super().form_invalid(form)
class AdminAssessmentListView(AdminRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/admin/assessment_list.html'
    context_object_name = 'assessments'
    queryset = Assessment.objects.select_related('client', 'assessor__userprofile').order_by('-created_at') # Include assessor profile if needed
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
# --- END MODIFY View (Step 1) ---

# --- MODIFY Companies House Confirmation View (Step 2: Handle POST) ---
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
# --- END MODIFY View (Step 2) ---

# --- END NEW View (Step 2) ---

# --- END MODIFY View ---


@login_required
@user_passes_test(is_assessor, login_url=reverse_lazy('login'))
def assessor_dashboard(request):
    assigned_assessments = Assessment.objects.filter(assessor=request.user).select_related('client').order_by('status', 'date_target_end')
    assessments_requiring_review = Assessment.objects.filter(status='Scoping_Review', assessor=request.user).count()
    # --- ADD THIS QUERY ---
    pending_approval_count = CloudServiceDefinition.objects.filter(is_globally_approved=False).count()
    # --- END ADD ---
    context = {
        'assessments': assigned_assessments,
        'assessment_count': assigned_assessments.count(),
        'assessments_pending_review': assessments_requiring_review,
        'pending_approval_count': pending_approval_count, # <-- Add to context
    }
    return render(request, 'tracker/assessor/assessor_dashboard.html', context)
class AssessorAssessmentListView(AssessorRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/assessor/assessment_list.html'
    context_object_name = 'assessments'

    def get_queryset(self):
        return Assessment.objects.filter(assessor=self.request.user).select_related('client').order_by('status', 'date_target_end')
class AssessorAssessmentDetailView(AssessorOrAdminRequiredMixin, DetailView):
    model = Assessment
    template_name = 'tracker/assessor/assessment_detail.html'
    context_object_name = 'assessment'

    def get_queryset(self):
        # Ensure workflow steps are prefetched here
        user = self.request.user
        base_qs = Assessment.objects.select_related(
            'client', 'assessor'
        ).prefetch_related(
            'scoped_items__operating_system',
            'evidence_files__uploaded_by',
            'logs__user',
            'external_ips', # Added for External IPs
            # --- Make sure these prefetches are present ---
            'workflow_steps__step_definition',
            'workflow_steps__completed_by',
            # --- End check ---
        )
        if is_admin(user):
            return base_qs
        elif is_assessor(user):
            return base_qs.filter(assessor=user)
        else:
            return Assessment.objects.none()


    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()

        # --- Standard context items ---
        context['evidence_form'] = EvidenceForm()
        context['status_update_form'] = AssessmentStatusUpdateForm(instance=assessment)
        context['needs_scope_review'] = assessment.status == 'Scoping_Review'
        context['downloadable_evidence'] = assessment.evidence_files.all()
        context['logs'] = assessment.logs.all()[:20]
        context['stored_sample_items'] = list(assessment.scoped_items.filter(is_in_ce_plus_sample=True).select_related('operating_system').order_by('item_type', 'operating_system__name', 'id'))
        context['sample_summary'] = { 'total_selected_items': len(context['stored_sample_items']) }
        # Add user_role for template logic
        context['user_role'] = self.request.user.userprofile.role if hasattr(self.request.user, 'userprofile') else None


        # --- START: Verify this whole block exists ---
        # --- Workflow Context Logic ---
        workflow_steps = list(assessment.workflow_steps.all()) # Get steps via prefetched relationship
        current_step = None
        steps_with_permission = []

        for step in workflow_steps:
            # Calculate permission using the request user
            step.can_update = step.is_update_allowed(self.request.user) # Adds permission flag
            steps_with_permission.append(step) # Add the modified step to the new list

            # Determine the current step (first non-complete one)
            if step.status != AssessmentWorkflowStep.Status.COMPLETE and current_step is None:
                current_step = step
        # --- END NEW ---

        # Add the processed steps and current step to the context
        context['workflow_steps'] = steps_with_permission # Use the list with the added 'can_update' attribute
        context['current_step'] = current_step
        # --- END: Verify this whole block exists ---


        return context
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
@user_passes_test(is_client, login_url=reverse_lazy('login'))
def client_dashboard(request):
    # Mixin should handle the check for profile.client existence now
    profile = request.user.userprofile
    client_assessments = Assessment.objects.filter(client=profile.client).select_related('assessor').order_by('-created_at')
    context = {
        'client': profile.client,
        'assessments': client_assessments,
    }
    return render(request, 'tracker/client/client_dashboard.html', context)
class ClientAssessmentListView(ClientRequiredMixin, ListView):
    model = Assessment
    template_name = 'tracker/client/assessment_list.html'
    context_object_name = 'assessments'

    def get_queryset(self):
        profile = self.request.user.userprofile
        return Assessment.objects.filter(client=profile.client).select_related('assessor').order_by('-created_at')
class ClientAssessmentDetailView(ClientRequiredMixin, DetailView):
    model = Assessment
    template_name = 'tracker/client/assessment_detail.html'
    context_object_name = 'assessment'

    def get_queryset(self):
        # Ensure workflow steps and related data are prefetched efficiently
        profile = self.request.user.userprofile
        return Assessment.objects.filter(client=profile.client).prefetch_related(
            'scoped_items__operating_system',
            'evidence_files__uploaded_by',
            'logs__user',
            # --- Workflow: Prefetch workflow steps and related data ---
            'workflow_steps__step_definition', # Gets the definition for each step
            'workflow_steps__completed_by',   # Gets the user who completed the step
            # --- End Workflow ---
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()

        # --- Keep existing context data ---
        context['can_edit_scope'] = assessment.status == 'Scoping_Client'
        context['downloadable_evidence'] = assessment.evidence_files.all()
        context['logs'] = assessment.logs.all()[:20] # Limit log entries

        # --- Scope Summary Logic (keep your existing implementation) ---
        # Using the previously provided logic for scope summary
        scope_summary_data = {
            'servers': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'workstations': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'mobiles': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'network_devices': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'cloud_services': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'other': {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})},
            'total_items': 0,
            'has_unsupported_or_eol': False
        }
        scope_summary_data['total_items'] = assessment.scoped_items.count()
        all_items_qs = assessment.scoped_items.select_related('operating_system').all()
        today = date.today()
        for item in all_items_qs:
            os_name_str, vendor_hint_str, is_supported, is_eol = "Unknown OS", "unknown", True, False
            if item.operating_system:
                os_name_str = str(item.operating_system)
                vendor_hint_str = item.operating_system.vendor.lower() if item.operating_system.vendor else "unknown"
                is_supported = item.operating_system.is_supported
                if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                    is_eol = True; is_supported = False
            os_info_key = (os_name_str, vendor_hint_str)
            group_dict = None
            if item.item_type == 'Server': group_dict = scope_summary_data['servers']
            elif item.item_type in ['Laptop', 'Desktop']: group_dict = scope_summary_data['workstations']
            elif item.item_type == 'Mobile': group_dict = scope_summary_data['mobiles']
            elif item.item_type in ['Firewall', 'Router', 'Switch', 'IP']: group_dict = scope_summary_data['network_devices']
            elif item.item_type in ['SaaS', 'PaaS', 'IaaS']: group_dict = scope_summary_data['cloud_services']
            else: group_dict = scope_summary_data['other']
            if group_dict is not None:
                group_dict['count'] += 1
                os_data = group_dict['os_types'][os_info_key]
                os_data['count'] += 1
                if not is_supported: os_data['is_supported'] = False
                if is_eol: os_data['is_eol'] = True
                if not is_supported or is_eol: scope_summary_data['has_unsupported_or_eol'] = True
        final_scope_summary = {'total_items': scope_summary_data['total_items'], 'has_unsupported_or_eol': scope_summary_data['has_unsupported_or_eol']}
        for category, data in scope_summary_data.items():
             if category not in ['total_items', 'has_unsupported_or_eol']:
                 final_scope_summary[category] = {'count': data['count'], 'os_types': {key: dict(val) for key, val in data['os_types'].items()}}
        context['scope_summary'] = final_scope_summary
        # --- End Scope Summary Logic ---

        # --- CE+ Sample Item Logic (keep your existing implementation) ---
        # Using the previously provided logic for sample items
        if assessment.assessment_type == 'CE+':
            sample_items_with_status = []
            raw_sample_items = assessment.scoped_items.filter(is_in_ce_plus_sample=True).select_related('operating_system').order_by('item_type', 'operating_system__name', 'id')
            for item in raw_sample_items:
                item.eol_status = 'ok'
                if item.operating_system:
                    if not item.operating_system.is_supported: item.eol_status = 'unsupported'
                    if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today: item.eol_status = 'eol'
                elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other', 'IP']: item.eol_status = 'unknown'
                sample_items_with_status.append(item)
            context['ce_plus_sample_items'] = sample_items_with_status
        else:
            context['ce_plus_sample_items'] = None
        # --- End CE+ Sample Item Logic ---


        # --- Workflow: Fetch and Add Workflow Context ---
        # Use the prefetched data from get_queryset
        # Ensure AssessmentWorkflowStep model has correct ordering in Meta ('step_definition__step_order')
        workflow_steps = list(assessment.workflow_steps.all())
        current_step = None
        workflow_steps = list(assessment.workflow_steps.all())  # Get all steps
        current_step = None
        steps_with_permission = []  # Create a new list to hold steps with permission flag

        # --- NEW: Iterate and check permission for each step ---
        for step in workflow_steps:
            # Calculate permission using the request user
            step.can_update = step.is_update_allowed(self.request.user)  # Add the result as a new attribute
            steps_with_permission.append(step)  # Add the modified step to the new list

            # Determine the current step (first non-complete one)
            if step.status != AssessmentWorkflowStep.Status.COMPLETE and current_step is None:
                current_step = step
        # --- END NEW ---

        # Add the processed steps and current step to the context
        context['workflow_steps'] = steps_with_permission  # Use the list with the added 'can_update' attribute
        context['current_step'] = current_step
        # --- End Workflow ---

        # --- Workflow: Add Debug Prints ---
        print("-" * 20)
        print(f"DEBUG VIEW ({self.__class__.__name__}): Assessment ID = {assessment.id}")
        print(f"DEBUG VIEW: Found {len(steps_with_permission)} workflow_steps in context (with permissions checked).")
        # Optionally print permissions:
        # for s in steps_with_permission:
        #     print(f"  Step {s.step_definition.step_order}: can_update={s.can_update}")
        print(f"DEBUG VIEW: Current Step object in context = {current_step}")
        print("-" * 20)
        # --- End Workflow Debug Prints ---
        return context
class ScopeItemManageView(ClientRequiredMixin, View):
    """
    Handles GET and POST requests for the client scope management page.
    GET: Displays categorized scope items and the add item form.
    POST: Handles adding new scope items.
    """
    template_name = 'tracker/client/scope_manage.html'
    # Pagination removed for now, handled per category if needed later

    def setup(self, request, *args, **kwargs):
        """Get assessment object early."""
        super().setup(request, *args, **kwargs)
        self.assessment = self.get_assessment_object(kwargs.get('assessment_pk'))

    def get_assessment_object(self, assessment_pk):
        """Helper to get assessment and check client ownership."""
        # Ensure user profile and client link exist (handled by ClientRequiredMixin)
        profile = self.request.user.userprofile
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if assessment.client != profile.client:
            raise PermissionDenied("You do not have permission to view this assessment's scope.")
        return assessment

    def get_context_data(self, form=None, **kwargs):
        """Prepares context: categorized items, OS data for JS, form, permissions."""
        # Fetch all items efficiently, including related OS and Network
        all_items = list(
            self.assessment.scoped_items.select_related('operating_system', 'network')
                                          .order_by('item_type', 'operating_system__name', 'identifier', 'id')
        )

        # --- Categorize Items ---
        categorized_items = {
            'user_devices': [], # Laptops, Desktops, Mobiles
            'servers': [],      # Servers
            'network_devices': [], # Firewalls, Routers, Switches, IPs
            'cloud_services': [], # SaaS, PaaS, IaaS
            'other_items': []    # Other
        }
        for item in all_items:
            if item.item_type in ['Laptop', 'Desktop', 'Mobile']:
                categorized_items['user_devices'].append(item)
            elif item.item_type == 'Server':
                categorized_items['servers'].append(item)
            elif item.item_type in ['Firewall', 'Router', 'Switch', 'IP']:
                categorized_items['network_devices'].append(item)
            elif item.item_type in ['SaaS', 'PaaS', 'IaaS']:
                categorized_items['cloud_services'].append(item)
            else: # 'Other' type
                categorized_items['other_items'].append(item)
        # --- End Categorization ---

        # --- Fetch OS Data for JS Filtering ---
        all_operating_systems = OperatingSystem.objects.filter(
             # is_supported=True # Optional: Only show supported OS in dropdown?
        ).order_by('name', 'version')
        os_data_for_js = []
        for os in all_operating_systems:
            os_data_for_js.append({
                'id': os.pk,
                'name': str(os),
                'category': os.category or ''
            })
        # --- End Fetch OS Data ---

        # Prepare form if not passed in (e.g., on GET request or POST failure)
        if form is None:
            form = ScopedItemForm(assessment=self.assessment) # Pass assessment for network filtering

        # Determine editing permissions based *only* on assessment status for clients
        can_edit = self.assessment.status == 'Scoping_Client'
        has_any_items = bool(all_items)

        # --- Prepare Context ---
        context = {
            'assessment': self.assessment,
            'form': form,
            'can_edit': can_edit,
            'can_submit': has_any_items and can_edit, # Can only submit if items exist and editing allowed
             # Pass categorized lists directly
            'user_devices_list': categorized_items['user_devices'],
            'servers_list': categorized_items['servers'],
            'network_devices_list': categorized_items['network_devices'],
            'cloud_services_list': categorized_items['cloud_services'],
            'other_items_list': categorized_items['other_items'],
             # Pass counts for display
            'counts': {
                'user_devices': len(categorized_items['user_devices']),
                'servers': len(categorized_items['servers']),
                'network_devices': len(categorized_items['network_devices']),
                'cloud_services': len(categorized_items['cloud_services']),
                'other_items': len(categorized_items['other_items']),
                'total': len(all_items)
            },
            # Pass OS data to template as JSON
            'os_data_json': json.dumps(os_data_for_js, cls=DjangoJSONEncoder)
        }
        context.update(kwargs)
        return context

    def get(self, request, *args, **kwargs):
        """Handles GET requests, displaying the scope management page."""
        context = self.get_context_data()
        # Display messages based on ability to edit and item existence
        if not context['can_edit'] and context['counts']['total'] == 0:
             messages.info(self.request, "No scope items have been added yet.")
        elif not context['can_edit']:
             messages.warning(self.request, f"Scope editing is locked (Assessment Status: {self.assessment.get_status_display()}).")
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        """Handles POST requests for adding new scope items."""
        # Double-check permission before processing POST
        if self.assessment.status != 'Scoping_Client':
            messages.error(request, f"Cannot add scope items now. Status is '{self.assessment.get_status_display()}'.")
            return redirect('tracker:client_scope_manage', assessment_pk=self.assessment.pk)

        form = ScopedItemForm(request.POST, assessment=self.assessment) # Pass assessment for network choices

        if form.is_valid():
            number_to_add = form.cleaned_data.get('number_to_add', 1)
            if number_to_add < 1: number_to_add = 1 # Ensure at least 1
            items_created_count = 0
            try:
                with transaction.atomic(): # Use a transaction for bulk creation
                    items_to_create = []
                    # Use validated & cleaned data from the form
                    base_data = {
                        'assessment': self.assessment,
                        'item_type': form.cleaned_data.get('item_type'),
                        'identifier': form.cleaned_data.get('identifier'),
                        'operating_system': form.cleaned_data.get('operating_system'),
                        'make_model': form.cleaned_data.get('make_model'),
                        'role_function': form.cleaned_data.get('role_function'),
                        'location': form.cleaned_data.get('location'),
                        'owner': form.cleaned_data.get('owner'),
                        'network': form.cleaned_data.get('network'),
                        'notes': form.cleaned_data.get('notes'),
                    }
                    for i in range(number_to_add):
                        items_to_create.append(ScopedItem(**base_data)) # Create instances

                    ScopedItem.objects.bulk_create(items_to_create) # Efficiently save all
                    items_created_count = len(items_to_create)

                # Logging details after successful transaction
                item_type_display = dict(ScopedItem.ITEM_TYPE_CHOICES).get(base_data.get('item_type'), 'N/A')
                log_event_desc = f"Added {items_created_count} scoped item(s): Type '{item_type_display}'."
                if base_data.get('operating_system'): log_event_desc += f" OS: {base_data.get('operating_system')}."
                # Add other details to log if needed

                log_assessment_event(self.assessment, request.user, log_event_desc)
                messages.success(request, f"{items_created_count} scoped item(s) added successfully.")

            except IntegrityError as e: # Catch potential unique constraint issues if identifier logic changes
                 messages.error(request, f"An error occurred: Could not add item(s). Possible duplicate identifier? Details: {e}")
                 context = self.get_context_data(form=form) # Re-render with original form data and errors
                 return render(request, self.template_name, context)
            except Exception as e: # Catch other potential errors
                messages.error(request, f"An unexpected error occurred while adding items: {e}")
                # Re-render with original form data but maybe without specific errors shown
                context = self.get_context_data(form=form)
                return render(request, self.template_name, context)

            # Redirect on successful creation
            return redirect('tracker:client_scope_manage', assessment_pk=self.assessment.pk)
        else:
            # Form is invalid, re-render the page with the form containing errors
            context = self.get_context_data(form=form) # Pass the invalid form back
            messages.error(request, "Failed to add scope item(s). Please check the form errors below.")
            return render(request, self.template_name, context)
@login_required
# @user_passes_test(is_client) # Handled by ClientRequiredMixin potentially
def scope_item_delete(request, assessment_pk, item_pk):
    # Using ClientRequiredMixin might be cleaner if adapted or used on a Class-based view
    if not is_client(request.user): return HttpResponseForbidden("Client permissions required.")
    profile = request.user.userprofile
    if not profile.client: return HttpResponseForbidden("Client account not linked.")

    assessment = get_object_or_404(Assessment, pk=assessment_pk)
    item = get_object_or_404(ScopedItem, pk=item_pk, assessment=assessment)

    # Permission checks
    if assessment.client != profile.client:
        return HttpResponseForbidden("Permission denied.")
    if assessment.status != 'Scoping_Client':
         messages.error(request, "Scope items can only be deleted when status is 'Scoping (Client Input)'.")
         return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)

    if request.method == 'POST':
        item_identifier = item.identifier
        item_type = item.get_item_type_display()
        item.delete()
        log_assessment_event(assessment, request.user, f"Scoped item deleted: '{item_identifier}' ({item_type}).")
        messages.success(request, f"Scoped item '{item_identifier}' deleted.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
    else:
        messages.warning(request, "Use the delete button on the scope management page.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
@login_required
# @user_passes_test(is_client) # Handled by ClientRequiredMixin potentially
def scope_submit(request, assessment_pk):
    if not is_client(request.user): return HttpResponseForbidden("Client permissions required.")
    profile = request.user.userprofile
    if not profile.client: return HttpResponseForbidden("Client account not linked.")

    assessment = get_object_or_404(Assessment, pk=assessment_pk)

    # Permission checks
    if assessment.client != profile.client:
        return HttpResponseForbidden("Permission denied.")
    if assessment.status != 'Scoping_Client':
         messages.warning(request, "Scope can only be submitted when status is 'Scoping (Client Input)'.")
         return redirect('tracker:client_assessment_detail', pk=assessment_pk)
    if not assessment.scoped_items.exists():
        messages.error(request, "Cannot submit scope with no items defined.")
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)

    if request.method == 'POST':
        assessment.status = 'Scoping_Review'
        assessment.save(update_fields=['status']) # Only update status field
        log_assessment_event(assessment, request.user, "Client submitted scope for review.")
        messages.success(request, "Scope submitted successfully for assessor review.")
        return redirect('tracker:client_assessment_detail', pk=assessment_pk)
    else:
        return redirect('tracker:client_scope_manage', assessment_pk=assessment_pk)
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
class OperatingSystemListView(AssessorOrAdminRequiredMixin, ListView):
    model = OperatingSystem
    template_name = 'tracker/os_management/os_list.html'
    context_object_name = 'operating_systems'
    paginate_by = 20 # Set the number of items per page (e.g., 20)
    ordering = ['vendor', 'name', 'version'] # Ensure consistent ordering for pagination
class OperatingSystemCreateView(AssessorOrAdminRequiredMixin, CreateView):
    model = OperatingSystem
    form_class = OperatingSystemForm
    template_name = 'tracker/os_management/os_form.html'
    success_url = reverse_lazy('tracker:os_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Add New Operating System'
        return context

    def form_valid(self, form):
        messages.success(self.request, f"Operating System '{form.instance}' created successfully.")
        return super().form_valid(form)
class OperatingSystemUpdateView(AssessorOrAdminRequiredMixin, UpdateView):
    model = OperatingSystem
    form_class = OperatingSystemForm
    template_name = 'tracker/os_management/os_form.html'
    success_url = reverse_lazy('tracker:os_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = f'Edit Operating System: {self.object}'
        return context

    def form_valid(self, form):
        messages.success(self.request, f"Operating System '{form.instance}' updated successfully.")
        return super().form_valid(form)
class OperatingSystemDeleteView(AssessorOrAdminRequiredMixin, DeleteView):
    model = OperatingSystem
    template_name = 'tracker/os_management/os_confirm_delete.html'
    success_url = reverse_lazy('tracker:os_list')
    context_object_name = 'os' # Use 'os' in the template

    def delete(self, request, *args, **kwargs):
        """
        Adds a success message. Checks for ProtectedError (though unlikely if
        on_delete=SET_NULL is used on ScopedItem.operating_system).
        """
        os_instance = self.get_object()
        os_name = str(os_instance) # Get name before deleting
        try:
            response = super().delete(request, *args, **kwargs)
            messages.success(request, f"Operating System '{os_name}' deleted successfully.")
            return response
        except ProtectedError:
            # This shouldn't happen if ScopedItem uses SET_NULL, but good practice
            messages.error(request, f"Cannot delete '{os_name}'. It might be referenced elsewhere unexpectedly.")
            return redirect('tracker:os_list')
@login_required
@user_passes_test(lambda u: is_assessor(u) or is_admin(u))
@transaction.atomic
def calculate_and_save_sample(request, assessment_pk):
    assessment = get_object_or_404(Assessment, pk=assessment_pk)

    # Permission check (Assessor assigned or Admin)
    if not (is_admin(request.user) or assessment.assessor == request.user):
         messages.error(request, "You do not have permission to modify the sample for this assessment.")
         return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)

    # Check if assessment type is CE+
    if assessment.assessment_type != 'CE+':
         messages.warning(request, "Sample calculation is only applicable for CE+ assessments.")
         return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)

    # --- Calculation Logic (moved from get_context_data) ---
    scoped_items = list(assessment.scoped_items.select_related('operating_system').all())
    items_to_select_ids = set() # Use a set for efficient ID storage

    # Group items
    grouped_items_dict = defaultdict(list)
    def get_group_key(item):
        os_name = item.operating_system.name if item.operating_system else 'Unknown OS'
        os_version = item.operating_system.version if item.operating_system else ''
        return (item.item_type, os_name, os_version)

    for item in scoped_items:
        key = get_group_key(item)
        grouped_items_dict[key].append(item)

    # Process each group and select items
    for key, items_in_group in grouped_items_dict.items():
        if not items_in_group: continue

        total_in_group = len(items_in_group)
        required_sample_size = calculate_sample_size(total_in_group)

        if required_sample_size >= total_in_group:
            selected_sample_items = items_in_group
        else:
            selected_sample_items = random.sample(items_in_group, required_sample_size)

        # Add the IDs of selected items to the set
        for selected_item in selected_sample_items:
            items_to_select_ids.add(selected_item.id)
    # --- End Calculation Logic ---

    # --- Database Update ---
    # 1. Clear existing sample flags for this assessment
    assessment.scoped_items.update(is_in_ce_plus_sample=False)

    # 2. Set the flag for the newly selected items
    if items_to_select_ids:
        ScopedItem.objects.filter(assessment=assessment, id__in=items_to_select_ids).update(is_in_ce_plus_sample=True)

    messages.success(request, f"Calculated CE+ sample updated successfully. {len(items_to_select_ids)} items selected.")
    # Log this event?
    log_assessment_event(assessment, request.user, f"Calculated CE+ sample regenerated ({len(items_to_select_ids)} items selected).")

    return redirect('tracker:assessor_assessment_detail', pk=assessment.pk)
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
def user_can_manage_assessment_cloud_services(user, assessment):
    """Checks if a user can view/manage cloud services for a given assessment."""
    if not user.is_authenticated: return False
    if is_admin(user): return True
    # Assessors can always view/manage their assigned assessments
    if is_assessor(user) and assessment.assessor == user: return True
    # Clients can view/manage if it's their assessment AND not completed
    if is_client(user) and assessment.client == user.userprofile.client:
        # Decide if clients can manage even when complete (e.g. view proof)
        # For now, allow view/manage unless explicitly forbidden by status if needed
        # return not assessment.status.startswith('Complete_')
        return True # Let clients view even if complete, editing controlled by view logic
    return False


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

class AssessorOrAdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        # Assumes is_admin and is_assessor functions exist
        return is_admin(self.request.user) or is_assessor(self.request.user)

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "Admin or Assessor permissions required.")
        # Redirect non-admins/assessors
        # Assuming client dashboard exists
        if is_client(self.request.user):
            return redirect('tracker:client_dashboard')
        # Fallback for other roles or if dashboards don't exist
        return redirect('login') # Or 'tracker:dashboard'

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
        # Make sure 'json' and 'DjangoJSONEncoder' are imported at the top of views.py
        context['os_data_json'] = json.dumps(os_data_for_js, cls=DjangoJSONEncoder)
        # --- END: Ensure this block is present ---

        return context

    def get_success_url(self):
        """Redirect back to the scope management page."""
        return reverse_lazy('tracker:client_scope_manage', kwargs={'assessment_pk': self.assessment.pk})

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