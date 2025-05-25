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