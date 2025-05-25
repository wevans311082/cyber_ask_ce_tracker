# Standard library
import json
import os
import pprint
import random
import logging
import uuid
from collections import defaultdict
import datetime


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
from tracker.forms import *
from tracker.models import *

from tracker.tasks import *

from tracker.utils import *

from tracker.mixin import *

from .htmx_views import *
logger = logging.getLogger(__name__)






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

class ClientWorkflowVisualPartialView(ClientRequiredMixin, DetailView):
    """ Renders just the workflow visual partial for AJAX updates. """
    model = Assessment
    template_name = 'tracker/partials/client_workflow_visual.html' # Render only the partial
    context_object_name = 'assessment' # The partial expects 'assessment'

    def get_queryset(self):
        """ Ensure client can only access their own assessment's visual """
        # Note: ClientRequiredMixin already ensures user is a client and has profile.client
        profile = self.request.user.userprofile
        if not profile.client:
            # This case should ideally be handled by the mixin, but as a safeguard:
            logger.warning(f"User {self.request.user.username} attempting to access workflow visual but has no linked client.")
            return Assessment.objects.none()

        # Filter assessments for the user's client
        queryset = Assessment.objects.filter(client=profile.client)

        # Prefetch data needed by the client_workflow_visual.html partial
        # Adjust prefetch based on what client_workflow_visual.html actually uses
        queryset = queryset.prefetch_related(
            'workflow_steps__step_definition' # Likely needed to determine current step/status
        )
        return queryset

    def get(self, request, *args, **kwargs):
        """ Handle GET request and render the partial or handle errors. """
        try:
            # get_object will use get_queryset, enforcing client permission
            self.object = self.get_object()
            context = self.get_context_data(object=self.object)

            # Rule 4: Add UTC Debug Print
            now_utc = timezone.now()
            print(f"[DEBUG ClientWorkflowVisualPartialView GET {self.object.pk}] Rendering visual partial. Current UTC time: {now_utc.isoformat()}")

            # Rule 5 & 8: Render the template
            return render(request, self.template_name, context)

        except Http404:
            # Rule 6: Handle foreseeable error (Object not found / Permission via queryset)
            logger.warning(f"User {request.user.username} triggered 404 accessing workflow visual for assessment PK {kwargs.get('pk')}")
            # Return an empty response or simple error message suitable for AJAX replacement
            return HttpResponse("", status=404)
        except Exception as e:
            # Rule 6: Handle other errors
            logger.error(f"Error rendering workflow visual for assessment PK {kwargs.get('pk')}: {e}", exc_info=True)
            # Return an empty response or simple error message suitable for AJAX replacement
            return HttpResponse("", status=500)
@login_required
@user_passes_test(is_client, login_url=reverse_lazy('login'))
def client_dashboard(request):
    profile = request.user.userprofile
    if not profile.client:
        messages.warning(request, "Your client account is not linked to a company.")
        return redirect('logout')  # Ensure 'logout' is a valid URL name

    client = profile.client

    # --- Fetch main list of assessments for display ---
    client_assessments = Assessment.objects.filter(client=client).select_related('assessor').order_by('-created_at')

    # --- Calculate assessment counts and next deadline ---
    completed_statuses = ['Complete_Passed', 'Complete_Failed']

    completed_assessments_count = Assessment.objects.filter(
        client=client,
        status__in=completed_statuses
    ).count()

    active_assessments_count = Assessment.objects.filter(
        client=client
    ).exclude(
        status__in=completed_statuses
    ).count()

    next_deadline_assessment = Assessment.objects.filter(
        client=client,
        date_target_end__isnull=False,
        date_target_end__gte=timezone.now().date()
    ).exclude(
        status__in=completed_statuses
    ).order_by('date_target_end').first()
    next_deadline_val = next_deadline_assessment.date_target_end if next_deadline_assessment else None

    # --- Fetch Nessus Agent URLs ---
    nessus_agent_urls_list = NessusAgentURL.objects.filter(is_valid=True)

    # --- Support Email ---
    support_email_val = "support@cyberask.co.uk"  # Or from settings

    # --- Initialize Context (excluding parts that will be overwritten by Tenable fetch) ---
    context = {
        'client': client,
        'assessments': client_assessments,
        'active_assessments_count': active_assessments_count,
        'completed_assessments_count': completed_assessments_count,
        'next_deadline': next_deadline_val,
        'nessus_agent_urls': nessus_agent_urls_list,
        'support_email': support_email_val,
        'agent_status_summary': None,  # Default
        'tenable_error': None,  # Default
        'tenable_agents_details': [],  # Default
        'tenable_group_name_searched': None,  # Default
        'tenable_group_id_found': None  # Default
    }

    # --- Ensure a Conversation exists for each assessment and prepare for context ---
    # Use a dictionary to map assessment ID to conversation for easy lookup in template
    assessment_conversations_map = {}
    for assessment_item in client_assessments:
        if assessment_item.assessor:  # Only create/update conversation if an assessor is assigned
            conversation, created = Conversation.objects.get_or_create(
                assessment=assessment_item,
                defaults={
                    'client': request.user,  # The client User object
                    'assessor': assessment_item.assessor,  # Assessment.assessor is the User object
                    # 'updated_at' will be set by auto_now on creation
                }
            )
            # If the conversation already existed, check if participants need an update
            if not created:
                needs_save = False
                if conversation.client != request.user:
                    conversation.client = request.user
                    needs_save = True
                if conversation.assessor != assessment_item.assessor:
                    conversation.assessor = assessment_item.assessor
                    needs_save = True

                if needs_save:
                    conversation.updated_at = timezone.now()  # Manually update if participants change
                    conversation.save(update_fields=['client', 'assessor', 'updated_at'])

            assessment_conversations_map[assessment_item.pk] = conversation
        # If no assessor, no conversation is created/fetched for this assessment_item

    context['assessment_conversations_map'] = assessment_conversations_map
    # Now your template can do: `conversations_map.get(assessment.pk)` to get the conversation

    # --- START Tenable Agent Status Fetch (copied from your provided code) ---
    tio = get_tenable_io_client()
    if not tio:
        context['tenable_error'] = "Could not initialize connection to Tenable.io. Check API configuration."
        logger.warning(f"Tenable connection failed for client dashboard: {client.name}")
    else:
        agent_group_name = client.name
        context['tenable_group_name_searched'] = agent_group_name

        agent_group_id = None
        agents_in_group_details = []
        agent_status_summary_dict = defaultdict(int)  # defaultdict should be imported from collections
        agent_status_summary_dict['total'] = 0

        try:
            logger.debug(f"[Client Dashboard {client.name}] Searching for Tenable agent group '{agent_group_name}'")
            # Ensure tio.agent_groups.list() is the correct SDK call
            agent_groups_list_response = tio.agent_groups.list()  # Renamed to avoid conflict
            for group in agent_groups_list_response:  # Iterate over the response
                if group['name'] == agent_group_name:
                    agent_group_id = group.get('id')
                    context['tenable_group_id_found'] = agent_group_id
                    logger.debug(f"[Client Dashboard {client.name}] Found group ID {agent_group_id}")
                    break

            if not agent_group_id:
                logger.warning(
                    f"[Client Dashboard {client.name}] Agent group '{agent_group_name}' not found in Tenable.io.")
            else:
                logger.debug(f"[Client Dashboard {client.name}] Listing agents for group ID {agent_group_id}")
                try:
                    all_agents_iterator = tio.agents.list(
                        limit=1000)  # Ensure this is the correct SDK call and handles pagination if necessary
                    for agent_data in all_agents_iterator:
                        agent_groups_field = agent_data.get('groups', [])  # Renamed to avoid conflict
                        if isinstance(agent_groups_field, list) and any(
                                ag.get('id') == agent_group_id for ag in agent_groups_field):
                            agents_in_group_details.append(agent_data)
                            status = agent_data.get('status', 'unknown').lower()
                            agent_status_summary_dict[status] += 1
                            agent_status_summary_dict['total'] += 1

                    logger.debug(
                        f"[Client Dashboard {client.name}] Found {agent_status_summary_dict['total']} agents. Statuses: {dict(agent_status_summary_dict)}")
                    context['agent_status_summary'] = dict(agent_status_summary_dict)
                    context['tenable_agents_details'] = agents_in_group_details

                except APIError as e:
                    logger.exception(f"[Client Dashboard {client.name}] Tenable API Error listing agents: {e}")
                    context['tenable_error'] = "Error retrieving agent status from Tenable.io."
                except ForbiddenError:
                    logger.exception(f"[Client Dashboard {client.name}] Permission denied listing agents in Tenable.")
                    context['tenable_error'] = "Permission denied retrieving agent status."
                except Exception as e:  # Catch more generic exceptions
                    logger.exception(
                        f"[Client Dashboard {client.name}] Unexpected error listing/processing agents: {e}")
                    context['tenable_error'] = "Unexpected error retrieving agent status."

        except APIError as e:
            logger.exception(f"[Client Dashboard {client.name}] Tenable API Error finding agent group: {e}")
            context['tenable_error'] = "Error accessing Tenable.io agent groups."
        except ForbiddenError:
            logger.exception(f"[Client Dashboard {client.name}] Permission denied finding agent group.")
            context['tenable_error'] = "Permission denied accessing Tenable.io agent groups."
        except Exception as e:  # Catch more generic exceptions
            logger.exception(f"[Client Dashboard {client.name}] Unexpected error finding agent group: {e}")
            context['tenable_error'] = "Unexpected error accessing Tenable.io."
    # --- END Tenable Agent Status Fetch ---

    return render(request, 'tracker/client/client_dashboard.html', context)


def key_to_str(key_tuple):
    return f"{key_tuple[0]} ({key_tuple[1]})"
















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
        # form.instance.created_by = self.request.user # Assign creator if field exists
        response = super().form_valid(form)
        if self.object:
            # Call the RENAMED task
            sync_client_with_tenable.delay(self.object.id) # <-- UPDATED
            messages.info(self.request, f"Client '{self.object.name}' created. Synchronizing Tag & Group with Tenable...")
        return response
class ClientUpdateView(AdminRequiredMixin, UpdateView):
    model = Client
    form_class = ClientForm
    template_name = 'tracker/admin/client_form.html'
    success_url = reverse_lazy('tracker:client_list')

    def form_valid(self, form):
        # --- Existing Companies House Logic ---
        client_instance = self.get_object() # Get the object *before* saving the form
        name_changed = 'name' in form.changed_data
        # NOTE: Assuming 'organization_number' is the correct field name from your form/model
        # Adjust if the field name for the company number is different.
        number_changed = 'organization_number' in form.changed_data # Or 'companies_house_number'? Check your form.

        if (name_changed or number_changed) and client_instance.companies_house_validated:
            # Reset validation status if relevant fields changed
            form.instance.companies_house_validated = False
            form.instance.last_companies_house_validation = None
            form.instance.validated_name = None # Clear tracked validated data
            form.instance.validated_number = None
            messages.warning(self.request, f"Client details changed. Companies House validation status reset for '{form.instance.name}'. Please re-validate.")
        # --- End Existing Companies House Logic ---

        # Call the parent form_valid() method to save the object
        response = super().form_valid(form) # Save happens here, self.object is now updated

        # --- TRIGGER CELERY TASK *AFTER* successful save ---
        if self.object: # Ensure the object exists after saving
            # Trigger the task, passing the PK of the saved object
            create_or_update_tenable_client_tag.delay(self.object.id)
            # Add a message about Tenable sync initiation
            messages.info(self.request, f"Synchronizing client '{self.object.name}' details with Tenable...")
        # --- END TRIGGER ---

        if self.object:
            # Call the RENAMED task
            sync_client_with_tenable.delay(self.object.id)  # <-- UPDATED
            messages.info(self.request,
                          f"Client '{self.object.name}' updated. Synchronizing Tag & Group with Tenable...")
        return response # Return the response from super().form_valid()
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
        profile = self.request.user.userprofile
        if not profile.client:
            return Assessment.objects.none()

        return Assessment.objects.filter(client=profile.client).prefetch_related(
            'scoped_items__operating_system',
            'scoped_items__network',
            'evidence_files__uploaded_by',
            'logs__user',
            'networks',
            'assessment_cloud_services__cloud_service_definition__approved_by',
            'assessment_cloud_services__cloud_service_definition__created_by',
            'assessment_cloud_services__verified_by',
            'external_ips',
            'workflow_steps__step_definition',
            'workflow_steps__completed_by',
            'date_options__proposed_by',
            'tenable_scan_logs__assessment',
        ).select_related('client', 'assessor__userprofile')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        assessment = self.get_object()
        user = self.request.user
        today = date.today()

        # --- Standard Context ---
        context['can_edit_scope'] = assessment.status == 'Scoping_Client'
        context['downloadable_evidence'] = assessment.evidence_files.all()
        context['logs'] = assessment.logs.order_by('-timestamp')[:20]

        # --- CE+ Sample Items Logic ---
        all_scope_items = list(assessment.scoped_items.all())
        ce_plus_sample_items_list = [item for item in all_scope_items if item.is_in_ce_plus_sample]
        context['has_ce_plus_sample'] = assessment.assessment_type == 'CE+' and bool(ce_plus_sample_items_list)

        sample_items_with_status = []
        if assessment.assessment_type == 'CE+':
            for item in ce_plus_sample_items_list:
                item.eol_status = 'ok'
                if item.operating_system:
                    if not item.operating_system.is_supported:
                        item.eol_status = 'unsupported'
                    if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                        item.eol_status = 'eol'
                elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other', 'IP']:
                    item.eol_status = 'unknown'
                sample_items_with_status.append(item)
        context['ce_plus_sample_items'] = sorted(sample_items_with_status,
                                                 key=lambda x: (x.item_type, str(x.operating_system or '')))

        # --- Scope Summary Logic ---
        scope_summary_data = defaultdict(
            lambda: {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})}
        )
        scope_summary_data['total_items'] = len(all_scope_items)
        scope_summary_data['has_unsupported_or_eol'] = False
        for item in all_scope_items:
            os_name_str, vendor_hint_str, is_supported, is_eol = "Unknown OS", "unknown", True, False
            if item.operating_system:
                os_name_str = str(item.operating_system)
                vendor_hint_str = item.operating_system.vendor.lower() if item.operating_system.vendor else "unknown"
                is_supported = item.operating_system.is_supported
                if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                    is_eol = True
                    is_supported = False
            if not is_supported or is_eol:
                scope_summary_data['has_unsupported_or_eol'] = True

            os_info_key = (os_name_str, vendor_hint_str)
            cat_map = {'Server': 'servers', 'Laptop': 'workstations', 'Desktop': 'workstations', 'Mobile': 'mobiles',
                       'Firewall': 'network_devices', 'Router': 'network_devices', 'Switch': 'network_devices',
                       'IP': 'network_devices', 'SaaS': 'cloud_services', 'PaaS': 'cloud_services',
                       'IaaS': 'cloud_services'}
            category_key = cat_map.get(item.item_type, 'other')
            group_dict = scope_summary_data[category_key]
            group_dict['count'] += 1
            os_data = group_dict['os_types'][os_info_key]
            os_data['count'] += 1
            if not is_supported: os_data['is_supported'] = False
            if is_eol: os_data['is_eol'] = True

        final_scope_summary = {'total_items': scope_summary_data['total_items'],
                               'has_unsupported_or_eol': scope_summary_data['has_unsupported_or_eol']}
        for category, data_val in scope_summary_data.items():
            if category not in ['total_items', 'has_unsupported_or_eol']:
                final_scope_summary[category] = {
                    'count': data_val['count'],
                    'os_types': {key_to_str(key): dict(val) for key, val in data_val['os_types'].items()}
                }
        context['scope_summary'] = final_scope_summary

        # --- Workflow Context Logic ---
        workflow_steps_qs = assessment.workflow_steps.select_related('step_definition', 'completed_by').order_by(
            'step_definition__step_order')
        workflow_steps_list = list(workflow_steps_qs)
        current_step = None
        for step_item in workflow_steps_list:
            step_item.can_update = step_item.is_update_allowed(user)
            if step_item.status not in [AssessmentWorkflowStep.Status.COMPLETE,
                                        AssessmentWorkflowStep.Status.SKIPPED] and current_step is None:
                current_step = step_item
        context['workflow_steps'] = workflow_steps_list
        context['current_step'] = current_step

        # --- Initial Card for Dynamic Area ---
        context['initial_card_template'] = None
        context['initial_card_context'] = {}

        initial_step_to_load = context.get('current_step')
        if not initial_step_to_load and context.get('workflow_steps'):
            if context['workflow_steps']:
                initial_step_to_load = context['workflow_steps'][0]
            else:
                initial_step_to_load = None

        if initial_step_to_load and hasattr(initial_step_to_load.step_definition,
                                            'card_template_path') and initial_step_to_load.step_definition.card_template_path:
            context['initial_card_template'] = initial_step_to_load.step_definition.card_template_path

            try:
                card_loader = LoadAssessmentCardContentView()
                card_loader.request = self.request

                context_func_name = card_loader.CONTEXT_FUNCTION_MAP.get(context['initial_card_template'])

                initial_card_base_context = {
                    'assessment': assessment,
                    'workflow_step': initial_step_to_load,
                    'user': self.request.user
                }

                if context_func_name and hasattr(card_loader, context_func_name):
                    context_func = getattr(card_loader, context_func_name)
                    try:
                        specific_context = context_func(assessment, initial_step_to_load,
                                                       self.request)
                        initial_card_base_context.update(specific_context)
                    except Exception as e_ctx_func:
                        logger.error(
                            f"Error in context function '{context_func_name}' for initial card '{context['initial_card_template']}': {e_ctx_func}",
                            exc_info=True)
                        initial_card_base_context['card_error'] = _("Error preparing content for this section.")
                elif context_func_name:
                    logger.error(
                        f"Context function '{context_func_name}' for initial card '{context['initial_card_template']}' not found on LoadAssessmentCardContentView.")
                    initial_card_base_context['card_error'] = _("Page configuration error (context function missing).")
                else:
                    logger.info(
                        f"No specific context function for initial card template {context['initial_card_template']} (Step: {initial_step_to_load.step_definition.name})")

                context['initial_card_context'] = initial_card_base_context
            except NameError:
                logger.error(
                    "LoadAssessmentCardContentView is not imported in ClientAssessmentDetailView. Cannot get initial card context.")
                context['initial_card_template'] = 'tracker/partials/_default_card_content.html'
                context['initial_card_context'] = {'assessment': assessment, 'workflow_step': initial_step_to_load,
                                                   'error_message': _("Page configuration error (view not found).")}
            except AttributeError as e_attr:
                logger.error(
                    f"AttributeError setting up initial card in ClientAssessmentDetailView (likely CONTEXT_FUNCTION_MAP missing or mistyped): {e_attr}", exc_info=True)
                context['initial_card_template'] = 'tracker/partials/_default_card_content.html'
                context['initial_card_context'] = {'assessment': assessment, 'workflow_step': initial_step_to_load,
                                                   'error_message': _("Page loading error (attribute).")}
            except Exception as e_gen:
                logger.error(f"Generic error setting up initial card: {e_gen}", exc_info=True)
                context['initial_card_template'] = 'tracker/partials/_default_card_content.html'
                context['initial_card_context'] = {'assessment': assessment, 'workflow_step': initial_step_to_load,
                                                   'error_message': _("Unexpected page loading error.")}
        else:
            if initial_step_to_load and hasattr(initial_step_to_load.step_definition, 'card_template_path'):
                logger.warning(
                    f"No card_template_path defined in DB for initial step: {initial_step_to_load.step_definition.name}")
            elif initial_step_to_load:
                logger.warning(
                    f"Initial step {initial_step_to_load.step_definition.name} has no 'card_template_path' attribute or it's empty.")
            else:
                logger.warning("No initial workflow step found to determine initial card.")
            context['initial_card_template'] = 'tracker/partials/_default_card_content.html'
            context['initial_card_context'] = {'assessment': assessment, 'workflow_step': initial_step_to_load,
                                               'message': _(                            "Initial content card not configured or no steps available.")}

        # --- Assessment Date Scheduling Context ---
        date_options = list(assessment.date_options.all())
        context['assessment_date_options'] = date_options
        confirmed_date_option = next(
            (opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
        context[
            'display_confirmed_assessment_date'] = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start
        has_explicitly_confirmed_option = confirmed_date_option is not None
        is_before_testing = assessment.status in ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
        context['assessment_allows_date_management'] = is_before_testing and not has_explicitly_confirmed_option

        # ***** THE FIX IS HERE *****
        context['propose_date_form'] = AssessmentDateOptionForm(assessment=assessment,
                                                                user=self.request.user)

        unavailable_dates_json = "[]"
        if assessment.assessor:
            unavailable_dates = AssessorAvailability.objects.filter(assessor=assessment.assessor).values_list(
                'unavailable_date', flat=True)
            unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
            unavailable_dates_json = json.dumps(unavailable_dates_str)
        context['assessor_unavailable_dates_json'] = unavailable_dates_json
        context['ce_plus_window_start_date'] = assessment.date_ce_passed
        context['ce_plus_window_end_date'] = assessment.ce_plus_window_end_date
        context['confirmed_assessment_date'] = context['display_confirmed_assessment_date']

        # --- Timer Date ---
        context['assessment_end_date_iso'] = None
        context['scan_launch_status'] = assessment.can_launch_ce_plus_scan()
        if assessment.date_target_end:
            try:
                # manually construct end-of-day datetime without relying on .max
                end_of_day = datetime.time(23, 59, 59, 999999)
                end_dt = datetime.datetime.combine(assessment.date_target_end, end_of_day)
                end_datetime_utc = timezone.make_aware(end_dt, timezone.utc)
                context['assessment_end_date_iso'] = end_datetime_utc.isoformat()
            except Exception as e:
                logger.warning(
                    f"Could not create datetime for countdown timer from date_target_end: {assessment.date_target_end} for assessment {assessment.pk} — {e}")

        # --- Tenable Scan Logs ---
        tenable_scan_logs_list = list(assessment.tenable_scan_logs.all().order_by('-created_at'))
        context['tenable_scan_logs'] = tenable_scan_logs_list

        return context


@login_required
# @client_required # Uncomment if you have this decorator and it's appropriate
def view_parsed_scan_results(request, assessment_pk: uuid.UUID, log_id: uuid.UUID):
    """
    Displays the detailed parsed results from a Tenable scan log.
    Fetches the scan log, associated assessment, and all asset snapshots
    with their related details (software, AV, services, etc.).
    """
    # [DEBUG] view_parsed_scan_results called at {timezone.now()}
    print(
        f"[VIEW PRINT] view_parsed_scan_results called for assessment_pk: {assessment_pk}, log_id: {log_id} by user: {request.user.username}")
    logger.info(
        f"Attempting to view parsed scan results for assessment_pk: {assessment_pk}, log_id: {log_id} by user: {request.user.username}")

    try:
        # Fetch the assessment first to ensure it exists and for context
        assessment = get_object_or_404(Assessment, pk=assessment_pk)

        # TODO: Implement robust permission checks here.
        # Example:
        # if not (request.user.is_staff or (hasattr(request.user, 'userprofile') and request.user.userprofile.client == assessment.client)):
        #     logger.warning(f"Permission denied for user {request.user.username} to view assessment {assessment_pk}")
        #     raise Http404("Permission denied.")

        # Fetch the specific scan log, ensuring it belongs to the fetched assessment
        scan_log = get_object_or_404(TenableScanLog.objects.select_related('assessment'), pk=log_id,
                                     assessment=assessment)

        print(f"[VIEW PRINT] Fetched Assessment: {assessment.id}, ScanLog: {scan_log.id}")
        logger.info(f"Fetched Assessment: {assessment.id}, ScanLog: {scan_log.id}")

    except Http404 as e:
        logger.warning(f"Http404 encountered: {e} for assessment_pk: {assessment_pk}, log_id: {log_id}")
        # Render a specific error template or re-raise
        # For now, a simple message in the context
        context = {
            'assessment': None,
            'scan_log': None,
            'error_message': f"The requested assessment (ID: {assessment_pk}) or scan log (ID: {log_id}) could not be found, or you do not have permission to view it.",
            'title': "Error: Scan Details Not Found"
        }
        return render(request, 'tracker/client/view_parsed_scan_results.html', context, status=404)
    except Exception as e:
        logger.exception(
            f"Unexpected error fetching assessment/scan_log for assessment_pk: {assessment_pk}, log_id: {log_id}: {e}")
        context = {
            'assessment': None,
            'scan_log': None,
            'error_message': "An unexpected error occurred while trying to load scan details. Please contact support.",
            'title': "Error Loading Scan Results"
        }
        return render(request, 'tracker/client/view_parsed_scan_results.html', context, status=500)

    if not scan_log.data_parsed_at:
        message = ("The data for this scan log has not been processed into detailed models yet. "
                   "Please ensure 'Fetch & Parse Results' has been completed for this scan log on the assessment details page.")
        print(f"[VIEW PRINT] Scan log {log_id} not parsed. Message: {message}")
        logger.info(f"Scan log {log_id} has not been parsed yet.")
        context = {
            'assessment': assessment,
            'scan_log': scan_log,
            'error_message': message,
            'title': f"Scan Not Processed: {scan_log.scan_name or scan_log.id.hex[:8]}"
        }
        return render(request, 'tracker/client/view_parsed_scan_results.html', context)

    # Fetch all asset snapshots for this scan log.
    # Use select_related for ForeignKey fields on AssetScanDataSnapshot and ScopedItem.
    # Use prefetch_related for reverse ForeignKey fields (many-to-one or many-to-many).
    asset_snapshots = AssetScanDataSnapshot.objects.filter(
        scan_log=scan_log
    ).select_related(
        'scoped_item',  # From AssetScanDataSnapshot to ScopedItem
        'scoped_item__operating_system',  # From ScopedItem to OperatingSystem (model name)
        'scoped_item__network'  # From ScopedItem to Network (model name)
    ).prefetch_related(
        'installed_software',  # Reverse FK from AssetInstalledSoftware to AssetScanDataSnapshot
        'antivirus_products',  # Reverse FK from AssetAntivirusDetail to AssetScanDataSnapshot
        'listening_services'  # Reverse FK from AssetListeningService to AssetScanDataSnapshot
    ).order_by('scoped_item__identifier', 'scoped_item__id')  # Consistent ordering

    print(f"[VIEW PRINT] Found {asset_snapshots.count()} asset snapshots for scan_log {log_id}")
    logger.info(f"Found {asset_snapshots.count()} asset snapshots for scan_log {log_id}")

    context = {
        'assessment': assessment,
        'scan_log': scan_log,
        'asset_snapshots': asset_snapshots,
        'title': f"Parsed Scan Results: {scan_log.scan_name or scan_log.id.hex[:8]}"
    }
    return render(request, 'tracker/client/view_parsed_scan_results.html', context)


@require_POST  # Ensure this view only accepts POST requests
@login_required
def save_assessment_info(request, assessment_pk):
    assessment = get_object_or_404(Assessment, pk=assessment_pk)

    # Permission check: can this user edit this assessment?
    # Reuse logic from get_assessment_info_context or define more robust permission check
    can_edit = False
    profile = getattr(request.user, 'userprofile', None)
    if profile:
        if profile.role in ['Assessor', 'Admin']:
            can_edit = True
        elif profile.role == 'Client' and profile.client == assessment.client:
            can_edit = True  # Form __init__ will limit fields for client

    if not can_edit:
        logger.warning(f"User {request.user.username} forbidden to save info for assessment {assessment_pk}")
        # Return the card in view mode with an error message (or just 403)
        context = get_assessment_info_context(assessment, None, request)
        context['card_error'] = _("You do not have permission to save these changes.")
        context['is_edit_mode'] = False  # Force view mode
        html_content = render_to_string('tracker/partials/assessment_info_card.html', context, request=request)
        return HttpResponse(html_content, status=403)

    form = AssessmentInfoForm(request.POST, instance=assessment, user=request.user)

    is_edit_mode_on_save = True  # Keep form displayed if errors
    if form.is_valid():
        form.save()
        logger.info(f"Assessment info for {assessment_pk} saved by {request.user.username}")
        is_edit_mode_on_save = False  # Switch to view mode on success
    else:
        logger.warning(
            f"Assessment info form errors for {assessment_pk} by {request.user.username}: {form.errors.as_json()}")
        # Form is invalid, errors will be in 'form.errors' and 'form.non_field_errors'

    # Re-render the card (either in view mode on success, or edit mode with errors)
    # Get fresh context which will now include the form (with errors if any) or not
    context = get_assessment_info_context(assessment, None, request)  # Get base view context
    if is_edit_mode_on_save:  # If save failed, ensure form is passed for re-render
        context['assessment_info_form'] = form  # Pass the form with errors
        context['is_edit_mode'] = True
    else:  # On success, ensure it's view mode
        context['is_edit_mode'] = False
        context['assessment_info_form'] = None

    html_content = render_to_string('tracker/partials/assessment_info_card.html', context, request=request)
    return HttpResponse(html_content)