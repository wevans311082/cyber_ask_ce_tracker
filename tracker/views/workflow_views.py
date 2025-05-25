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


@login_required
def update_workflow_step_status(request, assessment_pk, step_pk):
    if request.method == 'POST':
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        # Ensure user has access to this assessment (add your permission logic if needed)
        # Example:
        # profile = request.user.userprofile
        # if not profile or not profile.client or assessment.client != profile.client:
        #     return HttpResponseForbidden("You do not have permission to access this assessment.")

        workflow_step = get_object_or_404(AssessmentWorkflowStep, pk=step_pk, assessment=assessment)

        if not workflow_step.is_update_allowed(request.user):
            logger.warning(
                f"User {request.user.username} forbidden to update step {step_pk} for assessment {assessment_pk}")
            # To give feedback, we should still re-render the row, but with the actions disabled or an error.
            # For simplicity, we'll just prevent the change and re-render the existing state.
            # Ideally, you'd pass an error message to the row template.
            workflow_step.can_update_by_current_user = False  # Override for template
            html_content = render_to_string(
                'tracker/partials/workflow_checklist_row.html',
                {
                    'assessment': assessment,  # Needed for URLs in common_step_actions
                    'step_item': workflow_step,
                    'status_choices': AssessmentWorkflowStep.Status,
                    # 'can_update_step' will be taken from step_item.can_update_by_current_user
                },
                request=request
            )
            return HttpResponse(html_content, status=403)  # Return 403 with the current row

        new_status = request.POST.get('new_status')
        if new_status not in workflow_step.Status.values:
            logger.warning(f"Invalid status value '{new_status}' received for step {step_pk}.")
            # Re-render row with an error (more advanced) or just current state
            workflow_step.can_update_by_current_user = workflow_step.is_update_allowed(request.user)  # Recalculate
            html_content = render_to_string(
                'tracker/partials/workflow_checklist_row.html',
                {
                    'assessment': assessment,
                    'step_item': workflow_step,
                    'status_choices': AssessmentWorkflowStep.Status,
                },
                request=request
            )
            return HttpResponse(html_content, status=400)

        workflow_step.status = new_status
        if new_status == workflow_step.Status.COMPLETE:
            workflow_step.completed_at = timezone.now()
            workflow_step.completed_by = request.user
        elif workflow_step.status != workflow_step.Status.COMPLETE:  # If reopened etc.
            workflow_step.completed_at = None
            workflow_step.completed_by = None

        if new_status == workflow_step.Status.SKIPPED and not workflow_step.step_definition.skippable:
            logger.warning(f"Attempt to skip non-skippable step {step_pk} by user {request.user.username}.")
            # Re-render row with an error
            workflow_step.can_update_by_current_user = workflow_step.is_update_allowed(request.user)
            html_content = render_to_string(
                'tracker/partials/workflow_checklist_row.html',
                {
                    'assessment': assessment,
                    'step_item': workflow_step,
                    'status_choices': AssessmentWorkflowStep.Status,
                    # 'error_message_for_row': "This step cannot be skipped." # (You'd need to handle this in the row template)
                },
                request=request
            )
            return HttpResponse(html_content, status=403)

        workflow_step.save()

        # --- Re-render THE SINGLE ROW ---
        # Prepare context for the row partial
        workflow_step.can_update_by_current_user = workflow_step.is_update_allowed(
            request.user)  # Recalculate for the template

        row_context = {
            'assessment': assessment,  # For URLs in common_step_actions
            'step_item': workflow_step,
            'status_choices': AssessmentWorkflowStep.Status,
            # The common_step_actions partial expects 'can_update_step', which will be
            # derived from step_item.can_update_by_current_user within the row partial's include
        }

        html_content = render_to_string('tracker/partials/workflow_checklist_row.html', row_context, request=request)

        response = HttpResponse(html_content)
        # Send event to update main navigation or other parts of the page if necessary
        response['HX-Trigger-After-Swap'] = json.dumps({
            'updateNavActiveState': {'stepPk': workflow_step.pk, 'newStatus': new_status},
            # If nav needs to reflect status
            'assessmentStepUpdated': {'stepPk': workflow_step.pk, 'newStatus': new_status,
                                      'assessmentPk': assessment.pk}
        })
        return response

    logger.warning(f"update_workflow_step_status called with method {request.method}, only POST allowed.")
    return HttpResponseBadRequest("Only POST requests are allowed.")
