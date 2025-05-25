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
from tracker.forms import *
from tracker.models import *

from tracker.tasks import *


from tracker.utils import *



from tracker.mixin import *


logger = logging.getLogger(__name__)


def browser_versions_view(request):
    browsers = Browser.objects.all().order_by('name')

    icon_map = {
        'Chrome': 'https://upload.wikimedia.org/wikipedia/commons/8/87/Google_Chrome_icon_%282023%29.svg',
        'Edge': 'https://upload.wikimedia.org/wikipedia/commons/9/98/Microsoft_Edge_logo_%282019%29.svg',
        'Firefox': 'https://upload.wikimedia.org/wikipedia/commons/9/96/Firefox_logo%2C_2019.svg',
        'Safari': 'https://upload.wikimedia.org/wikipedia/commons/5/52/Safari_browser_logo.svg',
        'Safari on iOS': 'https://upload.wikimedia.org/wikipedia/commons/5/52/Safari_browser_logo.svg',
        'Firefox for Android': 'https://upload.wikimedia.org/wikipedia/commons/9/96/Firefox_logo%2C_2019.svg',
        'Chrome Android': 'https://upload.wikimedia.org/wikipedia/commons/8/87/Google_Chrome_icon_%282023%29.svg',
        'Samsung Internet': 'https://upload.wikimedia.org/wikipedia/commons/3/31/Samsung_Internet_logo_2022.svg',
    }

    return render(request, 'tracker/admin/browser_versions.html', {
        'browsers': browsers,
        'icon_map': icon_map
    })



@staff_member_required
def add_manual_browser(request):
    if request.method == "POST":
        form = BrowserForm(request.POST)
        if form.is_valid():
            browser = form.save(commit=False)
            browser.manually_added = True
            browser.save()
            return redirect('admin:index')  # or wherever appropriate
    else:
        form = BrowserForm()
    return render(request, "browsers/add_browser.html", {"form": form})






@staff_member_required(login_url=reverse_lazy('login'))
def critical_error_detail_view(request, pk):
    print(f"--- [DEBUG] critical_error_detail_view entered. Request method: {request.method}, PK: {pk} ---")

    try:
        # Instead of get_object_or_404, we'll do it manually for more debug output
        error_log = CriticalErrorLog.objects.get(pk=pk)
        print(f"--- [DEBUG] Successfully fetched CriticalErrorLog with pk: {pk}. Object: {error_log} ---")
    except CriticalErrorLog.DoesNotExist:
        print(f"--- [DEBUG] CriticalErrorLog with pk: {pk} DOES NOT EXIST in the database. Raising Http404. ---")
        raise Http404(f"CriticalErrorLog matching query does not exist for pk: {pk}")
    except Exception as e:
        # Catch any other potential errors during fetch
        print(f"--- [DEBUG] An unexpected error occurred while fetching CriticalErrorLog with pk: {pk}. Error: {e} ---")
        raise  # Re-raise the exception to see the full traceback

    if request.method == 'POST':
        print(f"--- [DEBUG] POST request received for error_log pk: {pk} ---")
        if 'acknowledge_error' in request.POST and not error_log.is_acknowledged:
            print(f"--- [DEBUG] 'acknowledge_error' action detected. ---")
            error_log.is_acknowledged = True
            error_log.acknowledged_at = timezone.now()
            error_log.acknowledged_by = request.user
            error_log.save()
            messages.success(request, f"Error log (ID: {error_log.pk}) has been acknowledged.")
            print(f"--- [DEBUG] Error log pk: {pk} acknowledged. Redirecting to 'tracker:admin_dashboard'. ---")
            return redirect('tracker:admin_dashboard')  # Ensure 'tracker:admin_dashboard' is a valid URL name
        elif 'unacknowledge_error' in request.POST and error_log.is_acknowledged:
            print(f"--- [DEBUG] 'unacknowledge_error' action detected. ---")
            # Optional: Allow unacknowledging if needed
            error_log.is_acknowledged = False
            error_log.acknowledged_at = None
            error_log.acknowledged_by = None
            error_log.save()
            messages.info(request, f"Error log (ID: {error_log.pk}) has been marked as unacknowledged.")
            print(f"--- [DEBUG] Error log pk: {pk} unacknowledged. Redirecting to its detail page. ---")
            return redirect('tracker:critical_error_detail', pk=error_log.pk)
        else:
            print(
                f"--- [DEBUG] POST request received but no matching action ('acknowledge_error' or 'unacknowledge_error') found or conditions not met. ---")
            print(f"--- [DEBUG] request.POST content: {request.POST} ---")
            print(f"--- [DEBUG] error_log.is_acknowledged: {error_log.is_acknowledged} ---")

    # Note: You define 'context' here but don't use it in the render call.
    # context_data_for_template = {
    # 'error_log': error_log,
    # 'active_nav': 'admin_dashboard', # Or a more specific active_nav if you have one
    # }
    # For consistency, let's use what you had, but be aware.

    print(f"--- [DEBUG] Rendering template 'tracker/admin/critical_error_detail.html' for error_log pk: {pk} ---")
    return render(request, 'tracker/admin/critical_error_detail.html', {
        'error_log': error_log,
        # If you intend to use 'active_nav', it should be in this dictionary too:
        # 'active_nav': 'admin_dashboard',
    })
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


@login_required # or appropriate permission
def eol_product_cycle_modal_view(request, product_slug):
    product = get_object_or_404(EOLProduct.objects.prefetch_related('cycles'), slug=product_slug)
    # Order cycles, e.g., by release date descending
    cycles = product.cycles.all().order_by('-release_date', '-cycle_slug')
    context = {
        'product': product,
        'cycles': cycles,
        # Pass a dynamic title for the modal (optional, can also be done with JS)
        'dynamic_modal_title': _("Cycle Details for %(product_name)s") % {'product_name': product.name}
    }
    # This new partial template will display the table of cycles
    return render(request, 'tracker/partials/_eol_product_cycles_table.html', context)


class EOLProductDashboardView(AdminRequiredMixin, ListView):
    model = EOLProduct
    template_name = 'tracker/admin/eol_product_dashboard.html' # New template
    context_object_name = 'products'
    paginate_by = 24 # Show 24 cards per page (adjust as needed for layout)

    def get_queryset(self):
        # Prefetch related cycles to efficiently get the count of cycles per product
        return EOLProduct.objects.all().prefetch_related('cycles').order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['view_title'] = _('EndOfLife.date Product Dashboard')
        return context