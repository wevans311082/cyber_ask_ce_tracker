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
from django.views.generic import *


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
from tracker.mixin import *

logger = logging.getLogger(__name__)



def user_can_manage_assessment_personnel(user, assessment):
    if user.is_superuser or user.userprofile.role == 'Admin':
        return True
    if user.userprofile.role == 'Assessor' and assessment.assessor == user:
        return True
    if user.userprofile.role == 'Client' and assessment.client == user.userprofile.client:
        return True
    return False

@login_required
def assessment_personnel_list_partial(request, assessment_pk):
    """
    Renders a partial HTML snippet for the list of personnel for an assessment.
    Meant to be included in an assessment detail page, possibly via HTMX.
    """
    assessment = get_object_or_404(Assessment, pk=assessment_pk)
    if not user_can_manage_assessment_personnel(request.user, assessment):
        # Or handle HTMX-specific error response
        return HttpResponseForbidden(_("You do not have permission to view personnel for this assessment."))

    personnel_list = AssessmentPersonnel.objects.filter(assessment=assessment).order_by('full_name')
    context = {
        'assessment': assessment,
        'personnel_list': personnel_list,
        'can_manage_personnel': True # Assuming if they can view, they can manage (can be refined)
    }
    return render(request, 'tracker/partials/_assessment_personnel_list.html', context)


class AssessmentPersonnelCreateView(LoginRequiredMixin, View):
    template_name = 'tracker/personnel/assessment_personnel_form.html' # New template

    def get(self, request, assessment_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to add personnel to this assessment."))

        form = AssessmentPersonnelForm()
        return render(request, self.template_name, {'form': form, 'assessment': assessment, 'view_title': _('Add Personnel Contact')})

    def post(self, request, assessment_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to add personnel to this assessment."))

        form = AssessmentPersonnelForm(request.POST)
        if form.is_valid():
            personnel = form.save(commit=False)
            personnel.assessment = assessment
            # Assuming UserProfile is readily available on request.user
            # and your AUTH_USER_MODEL is linked to UserProfile
            if hasattr(request.user, 'userprofile'):
                 personnel.added_by = request.user
            else:
                # Fallback or error if UserProfile isn't found,
                # or if added_by should link to UserProfile instead of User
                # For now, assuming added_by is ForeignKey to AUTH_USER_MODEL as per model
                personnel.added_by = request.user


            # [DEBUG] Adding new assessment personnel at {timezone.now()}
            print(f"[DEBUG] User '{request.user.username}' adding personnel '{personnel.full_name}' to assessment '{assessment.id}' at {timezone.now()}")

            try:
                personnel.save()
                messages.success(request, _(f"Personnel contact '{personnel.full_name}' added successfully."))
                # For HTMX, you might return a partial update or HX-Redirect
                # For now, redirecting to a hypothetical assessment detail page or personnel list
                # We'll need a URL for the personnel list partial or the page it's on.
                # Placeholder redirect, assuming the list partial will be reloaded on assessment detail.
                return redirect(reverse('tracker:assessor_assessment_detail', kwargs={'pk': assessment_pk})) # Adjust redirect as needed
            except Exception as e:
                # Handle potential unique_together constraint violation or other DB errors
                messages.error(request, _(f"Could not add personnel: {e}"))
                # [DEBUG] Error adding personnel: {e} at {timezone.now()}
                print(f"[DEBUG] Error adding personnel to assessment '{assessment.id}': {e} at {timezone.now()}")


        return render(request, self.template_name, {'form': form, 'assessment': assessment, 'view_title': _('Add Personnel Contact')})



class AssessmentPersonnelUpdateView(LoginRequiredMixin, View):
    template_name = 'tracker/personnel/assessment_personnel_form.html' # Same form template

    def get(self, request, assessment_pk, pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to edit personnel for this assessment."))

        form = AssessmentPersonnelForm(instance=personnel)
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel, # Pass the instance for the form and template logic
            'view_title': _('Edit Personnel Contact')
        })

    def post(self, request, assessment_pk, pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to edit personnel for this assessment."))

        form = AssessmentPersonnelForm(request.POST, instance=personnel)
        if form.is_valid():
            updated_personnel = form.save(commit=False)
            # added_by is not changed on update, it's the original creator.
            # If you want to track who last updated, you'd add a 'last_updated_by' field to the model.
            # [DEBUG] Updating assessment personnel at {timezone.now()}
            print(f"[DEBUG] User '{request.user.username}' updating personnel '{updated_personnel.full_name}' (ID: {pk}) for assessment '{assessment.id}' at {timezone.now()}")
            try:
                updated_personnel.save()
                messages.success(request, _(f"Personnel contact '{updated_personnel.full_name}' updated successfully."))
                # For HTMX, return the updated list partial to refresh the section
                # This assumes the form's hx-target points to the list container.
                return assessment_personnel_list_partial(request, assessment_pk)
            except Exception as e:
                messages.error(request, _(f"Could not update personnel: {e}"))
                # [DEBUG] Error updating personnel: {e} at {timezone.now()}
                print(f"[DEBUG] Error updating personnel (ID: {pk}) for assessment '{assessment.id}': {e} at {timezone.now()}")
        else:
            # [DEBUG] Form errors during update for personnel (ID: {pk}) at {timezone.now()}: {form.errors}
            print(f"[DEBUG] Form errors during update for personnel (ID: {pk}) for assessment '{assessment.id}': {form.errors} at {timezone.now()}")


        # If form is invalid, re-render the form page with errors
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'view_title': _('Edit Personnel Contact')
        })


class AssessmentPersonnelDeleteView(LoginRequiredMixin, View):
    def post(self, request, assessment_pk, pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to delete personnel for this assessment."))

        personnel_full_name = personnel.full_name # Get name before deleting for message

        # [DEBUG] Deleting assessment personnel at {timezone.now()}
        print(f"[DEBUG] User '{request.user.username}' deleting personnel '{personnel_full_name}' (ID: {pk}) from assessment '{assessment.id}' at {timezone.now()}")
        try:
            personnel.delete()
            # For HTMX, an empty 200 response will remove the element if hx-swap="outerHTML" is used on the target row.
            # Alternatively, you can return the updated list partial if the hx-target was the list container.
            # The template _assessment_personnel_list.html targets the row with hx-swap="outerHTML".
            # messages.success(request, _(f"Personnel contact '{personnel_full_name}' deleted successfully.")) # Message won't be seen with empty response
            return HttpResponse(status=200) # Empty response, HTMX handles UI update
        except Exception as e:
            # This case is less likely for a simple delete but good for robustness
            messages.error(request, _(f"Could not delete personnel: {e}"))
            # [DEBUG] Error deleting personnel: {e} at {timezone.now()}
            print(f"[DEBUG] Error deleting personnel (ID: {pk}) from assessment '{assessment.id}': {e} at {timezone.now()}")
            # If deletion fails, you might want to return an error status or the list again
            # For HTMX, returning the list partial is a safe fallback to show the error message.
            # However, the hx-confirm and hx-target on the button might expect a specific kind of response.
            # For row deletion, an error here would ideally be handled by an HX-Retarget to an error message display area.
            return assessment_personnel_list_partial(request, assessment_pk) # Re-render list with error message


@login_required
def personnel_cloud_service_access_list_partial(request, assessment_pk, personnel_pk):
    """
    Renders a partial HTML snippet for the list of cloud service accesses
    for a specific AssessmentPersonnel contact.
    """
    assessment = get_object_or_404(Assessment, pk=assessment_pk)
    personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

    # Using the same permission check for now, can be refined if needed
    if not user_can_manage_assessment_personnel(request.user, assessment):
        return HttpResponseForbidden(_("You do not have permission to manage cloud service access for this personnel."))

    access_list = PersonnelCloudServiceAccess.objects.filter(personnel=personnel).select_related(
        'assessment_cloud_service__cloud_service_definition'
    )
    context = {
        'assessment': assessment,
        'personnel': personnel,
        'access_list': access_list,
    }
    # This template will need to be created
    return render(request, 'tracker/partials/_personnel_cloud_service_access_list.html', context)


class PersonnelCloudServiceAccessCreateView(LoginRequiredMixin, View):
    # This template will need to be created
    template_name = 'tracker/personnel/personnel_cloud_service_access_form.html'

    def get(self, request, assessment_pk, personnel_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to add cloud service access."))

        # Pass assessment_pk and personnel_pk to the form for filtering and pre-selection
        form = PersonnelCloudServiceAccessForm(assessment_pk=assessment.pk, personnel_pk=personnel.pk)
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'view_title': _('Add Cloud Service Access for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })

    def post(self, request, assessment_pk, personnel_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):
            return HttpResponseForbidden(_("You do not have permission to add cloud service access."))

        form = PersonnelCloudServiceAccessForm(request.POST, request.FILES, assessment_pk=assessment.pk,
                                               personnel_pk=personnel.pk)

        if form.is_valid():
            access_record = form.save(commit=False)
            # The 'personnel' field in the form is disabled and pre-set if personnel_pk is passed.
            # If it's not disabled and part of the form, ensure it's correctly set or validated.
            # For this setup, form's __init__ should handle setting initial for 'personnel'.
            access_record.personnel = personnel  # Explicitly ensure personnel is set
            access_record.recorded_by = request.user

            # [DEBUG] Adding personnel cloud service access at {timezone.now()}
            print(
                f"[DEBUG] User '{request.user.username}' adding cloud service access for personnel '{personnel.full_name}' to assessment '{assessment.id}' at {timezone.now()}")

            try:
                access_record.save()
                messages.success(request, _("Cloud service access added successfully for %(personnel_name)s.") % {
                    'personnel_name': personnel.full_name})
                # For HTMX, return the updated list of accesses for this person
                return personnel_cloud_service_access_list_partial(request, assessment_pk, personnel_pk)
            except Exception as e:
                messages.error(request, _("Could not add cloud service access: %(error)s") % {'error': e})
                # [DEBUG] Error adding cloud service access: {e} at {timezone.now()}
                print(
                    f"[DEBUG] Error adding cloud service access for personnel '{personnel.full_name}' to assessment '{assessment.id}': {e} at {timezone.now()}")
        else:
            # [DEBUG] Form errors for cloud service access: {form.errors} at {timezone.now()}
            print(
                f"[DEBUG] Form errors for cloud service access for personnel '{personnel.full_name}' to assessment '{assessment.id}': {form.errors} at {timezone.now()}")

        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'view_title': _('Add Cloud Service Access for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })


class PersonnelCloudServiceAccessUpdateView(LoginRequiredMixin, View):
    template_name = 'tracker/personnel/personnel_cloud_service_access_form.html'

    def get(self, request, assessment_pk, personnel_pk, access_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)
        access_record = get_object_or_404(PersonnelCloudServiceAccess, pk=access_pk, personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment): # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to edit this cloud service access."))

        form = PersonnelCloudServiceAccessForm(
            instance=access_record,
            assessment_pk=assessment.pk,
            personnel_pk=personnel.pk # To disable personnel field and filter services
        )
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'access_record': access_record, # Pass the instance for template logic if needed (e.g. for URL in form action)
            'view_title': _('Edit Cloud Service Access for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })

    def post(self, request, assessment_pk, personnel_pk, access_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)
        access_record = get_object_or_404(PersonnelCloudServiceAccess, pk=access_pk, personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment): # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to edit this cloud service access."))

        form = PersonnelCloudServiceAccessForm(
            request.POST, request.FILES,
            instance=access_record,
            assessment_pk=assessment.pk,
            personnel_pk=personnel.pk
        )

        if form.is_valid():
            updated_access_record = form.save(commit=False)
            # recorded_by is usually not changed on update. If you need to track last_modified_by, add a new field.
            # [DEBUG] Updating personnel cloud service access at {timezone.now()}
            print(f"[DEBUG] User '{request.user.username}' updating cloud access (ID: {access_pk}) for personnel '{personnel.full_name}' to assessment '{assessment.id}' at {timezone.now()}")
            try:
                updated_access_record.save()
                messages.success(request, _("Cloud service access updated successfully for %(personnel_name)s.") % {'personnel_name': personnel.full_name})
                # For HTMX, return the updated list partial for this person
                return personnel_cloud_service_access_list_partial(request, assessment_pk, personnel_pk)
            except Exception as e:
                messages.error(request, _("Could not update cloud service access: %(error)s") % {'error': e})
                # [DEBUG] Error updating cloud service access: {e} at {timezone.now()}
                print(f"[DEBUG] Error updating cloud access (ID: {access_pk}) for personnel '{personnel.full_name}' to assessment '{assessment.id}': {e} at {timezone.now()}")
        else:
            # [DEBUG] Form errors for cloud service access update: {form.errors} at {timezone.now()}
            print(f"[DEBUG] Form errors for cloud service access update (ID: {access_pk}) for personnel '{personnel.full_name}' to assessment '{assessment.id}': {form.errors} at {timezone.now()}")


        # If form is invalid, re-render it
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'access_record': access_record,
            'view_title': _('Edit Cloud Service Access for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })


class PersonnelCloudServiceAccessDeleteView(LoginRequiredMixin, View):
    def post(self, request, assessment_pk, personnel_pk, access_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment) # Ensure personnel belongs to assessment
        access_record = get_object_or_404(PersonnelCloudServiceAccess, pk=access_pk, personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment): # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to delete this cloud service access."))

        service_name = access_record.assessment_cloud_service.cloud_service_definition.name
        # [DEBUG] Deleting personnel cloud service access at {timezone.now()}
        print(f"[DEBUG] User '{request.user.username}' deleting cloud access (ID: {access_pk}) for service '{service_name}' for personnel '{personnel.full_name}' for assessment '{assessment.id}' at {timezone.now()}")

        try:
            access_record.delete()
            # For HTMX, an empty 200 response is often used when hx-swap="outerHTML" targets the row to be deleted.
            # The template _personnel_cloud_service_access_list.html uses this for the delete button.
            # messages.success might not be seen if we return an empty response.
            # If you want to show a message, you might need HX-Retarget or return the list partial with the message.
            return HttpResponse(status=200) # Empty response, HTMX handles UI
        except Exception as e:
            messages.error(request, _("Could not delete cloud service access: %(error)s") % {'error': e})
            # [DEBUG] Error deleting cloud service access: {e} at {timezone.now()}
            print(f"[DEBUG] Error deleting cloud access (ID: {access_pk}) for assessment '{assessment.id}': {e} at {timezone.now()}")
            # Fallback: re-render the list, which will show the error message.
            return personnel_cloud_service_access_list_partial(request, assessment_pk, personnel_pk)


@login_required
def personnel_security_test_list_partial(request, assessment_pk, personnel_pk):
    """
    Renders a partial HTML snippet for the list of security tests
    for a specific AssessmentPersonnel contact.
    """
    assessment = get_object_or_404(Assessment, pk=assessment_pk)
    personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

    if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
        return HttpResponseForbidden(_("You do not have permission to manage security tests for this personnel."))

    test_list = PersonnelSecurityTest.objects.filter(assessment_personnel=personnel).select_related(
        'scoped_item', 'evidence'
    ).order_by('-test_date', '-date_recorded')

    context = {
        'assessment': assessment,
        'personnel': personnel,
        'test_list': test_list,
    }
    # This template will need to be created
    return render(request, 'tracker/partials/_personnel_security_test_list.html', context)


class PersonnelSecurityTestCreateView(LoginRequiredMixin, View):
    # This template will need to be created
    template_name = 'tracker/personnel/personnel_security_test_form.html'

    def get(self, request, assessment_pk, personnel_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to add security tests."))

        form = PersonnelSecurityTestForm(assessment_pk=assessment.pk, personnel_pk=personnel.pk)
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'view_title': _('Log Security Test for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })

    def post(self, request, assessment_pk, personnel_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)

        if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to add security tests."))

        form = PersonnelSecurityTestForm(request.POST, assessment_pk=assessment.pk, personnel_pk=personnel.pk)

        if form.is_valid():
            security_test = form.save(commit=False)
            # assessment_personnel is set via form's __init__ and disabled field
            security_test.assessment_personnel = personnel  # Explicitly set
            security_test.recorded_by = request.user

            # [DEBUG] Adding personnel security test at {timezone.now()}
            print(
                f"[DEBUG] User '{request.user.username}' adding security test for personnel '{personnel.full_name}' to assessment '{assessment.id}' at {timezone.now()}")
            try:
                security_test.save()
                messages.success(request, _("Security test logged successfully for %(personnel_name)s.") % {
                    'personnel_name': personnel.full_name})
                # For HTMX, return the updated list of tests for this person
                return personnel_security_test_list_partial(request, assessment_pk, personnel_pk)
            except Exception as e:
                messages.error(request, _("Could not log security test: %(error)s") % {'error': e})
                # [DEBUG] Error logging security test: {e} at {timezone.now()}
                print(
                    f"[DEBUG] Error logging security test for personnel '{personnel.full_name}' to assessment '{assessment.id}': {e} at {timezone.now()}")
        else:
            # [DEBUG] Form errors for security test: {form.errors} at {timezone.now()}
            print(
                f"[DEBUG] Form errors for security test for personnel '{personnel.full_name}' to assessment '{assessment.id}': {form.errors} at {timezone.now()}")

        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'view_title': _('Log Security Test for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })


class PersonnelSecurityTestUpdateView(LoginRequiredMixin, View):
    template_name = 'tracker/personnel/personnel_security_test_form.html'

    def get(self, request, assessment_pk, personnel_pk, test_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)
        security_test = get_object_or_404(PersonnelSecurityTest, pk=test_pk, assessment_personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to edit this security test log."))

        form = PersonnelSecurityTestForm(
            instance=security_test,
            assessment_pk=assessment.pk,
            personnel_pk=personnel.pk  # For filtering dropdowns and disabling personnel field
        )
        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'security_test': security_test,  # Pass the instance for template logic if needed
            'view_title': _('Edit Security Test Log for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })

    def post(self, request, assessment_pk, personnel_pk, test_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)
        security_test = get_object_or_404(PersonnelSecurityTest, pk=test_pk, assessment_personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to edit this security test log."))

        form = PersonnelSecurityTestForm(
            request.POST,  # No request.FILES needed as this form doesn't directly upload, it links to Evidence
            instance=security_test,
            assessment_pk=assessment.pk,
            personnel_pk=personnel.pk
        )

        if form.is_valid():
            updated_security_test = form.save(commit=False)
            # recorded_by is not changed on update.
            # [DEBUG] Updating personnel security test at {timezone.now()}
            print(
                f"[DEBUG] User '{request.user.username}' updating security test (ID: {test_pk}) for personnel '{personnel.full_name}' for assessment '{assessment.id}' at {timezone.now()}")
            try:
                updated_security_test.save()
                messages.success(request, _("Security test log updated successfully for %(personnel_name)s.") % {
                    'personnel_name': personnel.full_name})
                # For HTMX, return the updated list partial for this person
                return personnel_security_test_list_partial(request, assessment_pk, personnel_pk)
            except Exception as e:
                messages.error(request, _("Could not update security test log: %(error)s") % {'error': e})
                # [DEBUG] Error updating security test: {e} at {timezone.now()}
                print(
                    f"[DEBUG] Error updating security test (ID: {test_pk}) for personnel '{personnel.full_name}' for assessment '{assessment.id}': {e} at {timezone.now()}")
        else:
            # [DEBUG] Form errors for security test update: {form.errors} at {timezone.now()}
            print(
                f"[DEBUG] Form errors for security test update (ID: {test_pk}) for personnel '{personnel.full_name}' for assessment '{assessment.id}': {form.errors} at {timezone.now()}")

        return render(request, self.template_name, {
            'form': form,
            'assessment': assessment,
            'personnel': personnel,
            'security_test': security_test,
            'view_title': _('Edit Security Test Log for %(personnel_name)s') % {'personnel_name': personnel.full_name}
        })


class PersonnelSecurityTestDeleteView(LoginRequiredMixin, View):
    def post(self, request, assessment_pk, personnel_pk, test_pk):
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        personnel = get_object_or_404(AssessmentPersonnel, pk=personnel_pk, assessment=assessment)
        security_test = get_object_or_404(PersonnelSecurityTest, pk=test_pk, assessment_personnel=personnel)

        if not user_can_manage_assessment_personnel(request.user, assessment):  # Or a more specific permission
            return HttpResponseForbidden(_("You do not have permission to delete this security test log."))

        test_description_for_log = security_test.test_description or f"Test ID {security_test.pk}"
        # [DEBUG] Deleting personnel security test at {timezone.now()}
        print(
            f"[DEBUG] User '{request.user.username}' deleting security test '{test_description_for_log}' (ID: {test_pk}) for personnel '{personnel.full_name}' for assessment '{assessment.id}' at {timezone.now()}")

        try:
            security_test.delete()
            # For HTMX, an empty 200 response will remove the element if hx-swap="outerHTML" is used on the target row.
            return HttpResponse(status=200)
        except Exception as e:
            messages.error(request, _("Could not delete security test log: %(error)s") % {'error': e})
            # [DEBUG] Error deleting security test: {e} at {timezone.now()}
            print(
                f"[DEBUG] Error deleting security test (ID: {test_pk}) for assessment '{assessment.id}': {e} at {timezone.now()}")
            # Fallback: re-render the list, which will show the error message.
            return personnel_security_test_list_partial(request, assessment_pk, personnel_pk)

