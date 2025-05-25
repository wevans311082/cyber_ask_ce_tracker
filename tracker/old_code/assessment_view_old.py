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
    NessusAgentURL
)
from tracker.pdf_extractor import extract_ce_data_from_pdf
from tracker.tasks import apply_tenable_tag_to_assets, create_or_update_tenable_client_tag

from tracker.tasks import (
    sync_client_with_tenable, apply_tenable_tag_to_assets, # Use the new/renamed tasks
    scrape_nessus_agent_urls, validate_agent_urls # Keep others if needed
)
from tracker.tenable_client import get_tenable_io_client



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
ClientRequiredMixin,
AdminRequiredMixin,
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin

)

logger = logging.getLogger(__name__)

