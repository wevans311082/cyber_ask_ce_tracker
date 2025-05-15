
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from django.utils import timezone
import socket
import os
import uuid

def mfa_proof_upload_path(instance, filename):
    assessment_id = instance.assessment.id if instance.assessment else 'unknown_assessment'
    service_def_id = instance.cloud_service_definition.id if instance.cloud_service_definition else 'unknown_service'
    ext = filename.split('.')[-1]
    unique_filename = f"{uuid.uuid4()}.{ext}"
    # --- Ensure this path structure is what you expect ---
    path_components = ['mfa_proof', f'assessment_{assessment_id}', f'service_{service_def_id}', unique_filename]
    return os.path.join(*path_components)
    # --- Previously it might have missed the service_def_id folder ---
    # return f'mfa_proof/assessment_{assessment_id}/{unique_filename}' # Old version?
def ce_report_upload_path(instance, filename):
    # Generates a path like: ce_reports/assessment_123/some_random_uuid_filename.pdf
    assessment_id = instance.assessment.id if instance.assessment else 'unlinked'
    ext = filename.split('.')[-1]
    unique_filename = f"{uuid.uuid4()}.{ext}"
    return f'ce_reports/assessment_{assessment_id}/{unique_filename}'
def validate_ip_or_hostname(value):
    try:
        # Check if it's a valid IP address first
        validate_ipv46_address(value)
        return # It's a valid IP
    except ValidationError:
        # If not a valid IP, try resolving as a hostname
        try:
            # Attempt to resolve the hostname. This doesn't guarantee reachability
            # but checks if the name *could* be valid according to DNS rules/local hosts.
            # Using getaddrinfo is generally preferred over gethostbyname.
            socket.getaddrinfo(value, None)
            return # Looks like a potentially valid hostname
        except (socket.gaierror, UnicodeError, ValueError):
             # socket.gaierror: Name or service not known (or other resolution error)
             # UnicodeError/ValueError: For invalid characters in hostname
             raise ValidationError(
                 f"'{value}' is not a valid IP address or resolvable hostname.",
                 code='invalid_ip_or_hostname'
             )
class ScanStatus(models.TextChoices):
    PENDING = 'Pending', _('Pending Scan')
    SCANNED_OK = 'ScannedOK', _('Scanned - OK')
    SCANNED_ISSUES = 'ScannedIssues', _('Scanned - Issues Found')
    REMEDIATED = 'Remediated', _('Issues Remediated')
    EXCLUDED = 'Excluded', _('Excluded from Scan')
class OperatingSystem(models.Model):
    name = models.CharField(max_length=100, help_text="E.g., Windows 11 Pro, macOS, Ubuntu Linux")
    version = models.CharField(max_length=50, blank=True, help_text="E.g., 23H2, Sonoma 14.4, 22.04 LTS")
    vendor = models.CharField(max_length=100, blank=True)
    vendor_website = models.URLField(max_length=255, blank=True, verbose_name="Vendor Website")
    end_of_life_date = models.DateField(null=True, blank=True, help_text="Approximate End-of-Life or End-of-Support date")
    is_supported = models.BooleanField(default=True, help_text="Is this OS version currently supported?")
    notes = models.TextField(blank=True)

    # --- NEW: OS Category ---
    OS_CATEGORY_CHOICES = (
        ('Desktop', _('Desktop (Windows, macOS, Linux)')),
        ('Server', _('Server (Windows Server, Linux Server, ESXi)')),
        ('Mobile', _('Mobile (iOS, Android)')),
        ('Other', _('Other/Appliance')),
    )
    category = models.CharField(
        max_length=10,
        choices=OS_CATEGORY_CHOICES,
        blank=True, # Allow blank/null initially for existing entries
        null=True,  # Allow null initially
        help_text="General category this OS applies to (used for form filtering)."
    )
    # --- END NEW ---

    class Meta:
        ordering = ['vendor', 'name', 'version']
        unique_together = ('name', 'version')

    def __str__(self):
        version_str = f" {self.version}" if self.version else ""
        vendor_str = f" ({self.vendor})" if self.vendor else ""
        # Optionally add category display here if useful
        # category_str = f" [{self.get_category_display()}]" if self.category else ""
        return f"{self.name}{version_str}{vendor_str}"
class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('Admin', 'Administrator'),
        ('Assessor', 'Assessor'),
        ('Client', 'Client'),
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    client = models.ForeignKey(
        'Client', # Use string 'Client' if Client model is defined later in the file
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Required only if role is 'Client'"
    )
    phone_number = models.CharField(
        _("Phone Number"),
        max_length=20,
        blank=True,
        help_text=_("Optional: Your contact phone number.")
    )
    mfa_enabled = models.BooleanField(
        _("MFA Enabled"),
        default=False,
        help_text=_("Enable Multi-Factor Authentication for your account.")
    )

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"
class Client(models.Model):
    name = models.CharField(max_length=200, unique=True)
    address = models.TextField(blank=True)
    contact_person = models.CharField(max_length=100)
    contact_email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    organization_number = models.CharField(_("UK Companies House Number"), max_length=20, blank=True, null=True, help_text="Optional: UK Companies House registration number.")
    website_address = models.URLField(_("Website Address"), max_length=255, blank=True, null=True)
    companies_house_validated = models.BooleanField(_("Companies House Validated"), default=False, help_text="Indicates if details were successfully validated against Companies House.")
    last_companies_house_validation = models.DateTimeField(_("Last Validation Timestamp"), null=True, blank=True, help_text="When the details were last successfully validated.")
    # Internal fields to track data used for validation check
    validated_name = models.CharField(max_length=200, blank=True, null=True, editable=False, help_text="Internal: Name used for last validation.")
    validated_number = models.CharField(max_length=20, blank=True, null=True, editable=False, help_text="Internal: Number used for last validation.")
    tenable_tag_uuid = models.UUIDField(
        _("Tenable Tag UUID"),
        blank=True,
        null=True,
        help_text=_("UUID of the tag in Tenable.io used to identify assets for this client.")
    )
    tenable_agent_group_id = models.IntegerField(
        _("Tenable Agent Group ID"),
        blank=True,
        null=True,
        help_text=_("Integer ID of the Tenable.io agent group for this client.")
    )
    tenable_agent_group_uuid = models.CharField(
        _("Tenable Agent Group UUID"),
        max_length=36,  # Standard UUID length (e.g., "a1b2c3d4-e5f6-7788-9900-aabbccddeeff")
        blank=True,
        null=True,
        help_text=_("UUID (string) of the Tenable.io agent group, fetched from Tenable.io based on the Agent Group ID.")
    )
    tenable_agent_group_target_name = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="The exact name of the Tenable.io Agent Group to use for this client's scans (e.g., 'TEST WE')."
    )
    user_profile = models.OneToOneField(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='client_profile'
    )



    def __str__(self): return self.name
class Assessment(models.Model):
    STATUS_CHOICES = (('Draft', 'Draft'),('Scoping_Client', 'Scoping (Client Input)'),('Scoping_Review', 'Scoping (Assessor Review)'),('Testing', 'Testing'),('Remediation', 'Remediation'),('Report_Pending', 'Report Pending'),('Complete_Passed', 'Complete (Passed)'),('Complete_Failed', 'Complete (Failed)'),)
    ASSESSMENT_TYPES = (('CE', 'Cyber Essentials'),('CE+', 'Cyber Essentials Plus'),)
    SCOPE_TYPES = (('Whole_Org', 'Whole Organisation'),('Sub_Set', 'Sub-Set'),)
    OUTCOME_CHOICES = (('Pass', 'Pass'),('Fail', 'Fail'),)
    client = models.ForeignKey(Client, on_delete=models.PROTECT, related_name='assessments')
    assessor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_assessments', limit_choices_to={'userprofile__role': 'Assessor'})
    assessment_type = models.CharField(max_length=3, choices=ASSESSMENT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Draft')
    scope_description = models.TextField(blank=True, help_text="Brief description of the scope boundary.")
    scope_type = models.CharField(max_length=10, choices=SCOPE_TYPES, default='Whole_Org')
    date_start = models.DateField(null=True, blank=True)
    date_target_end = models.DateField(null=True, blank=True, verbose_name="Target End Date")
    date_actual_end = models.DateField(null=True, blank=True, verbose_name="Actual End Date")
    date_cert_issued = models.DateField(null=True, blank=True, verbose_name="Certificate Issued Date")
    date_cert_expiry = models.DateField(null=True, blank=True, verbose_name="Certificate Expiry Date")
    date_ce_passed = models.DateField(null=True, blank=True, verbose_name="CE Self-Assessment Pass Date", help_text="Date the basic Cyber Essentials self-assessment was passed (for CE+ window).")
    ce_self_assessment_ref = models.CharField(max_length=100, blank=True, verbose_name="CE Self-Assessment Ref")
    final_outcome = models.CharField(max_length=4, choices=OUTCOME_CHOICES, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    tenable_scan_uuid = models.UUIDField(
        null=True,
        blank=True,
        unique=False,  # Can re-launch / create new scans for same assessment
        verbose_name="Tenable Scan UUID",
        help_text="UUID of the last launched Tenable scan for this assessment"
    )
    SCAN_NONE = 'none'
    SCAN_PENDING = 'pending_launch'  # <<< THIS IS LIKELY MISSING OR COMMENTED OUT
    SCAN_LAUNCHED = 'launched'
    SCAN_COMPLETED = 'completed'
    SCAN_PROCESSING = 'processing'
    SCAN_IMPORTED = 'imported'
    SCAN_ERROR = 'error'
    SCAN_TIMEOUT = 'timeout'

    SCAN_STATUS_CHOICES = [
        (SCAN_NONE, 'Not Scanned'),
        (SCAN_PENDING, 'Scan Pending Launch'), # <<< AND MISSING HERE
        (SCAN_LAUNCHED, 'Scan Launched'),
        (SCAN_COMPLETED, 'Scan Completed by Tenable'),
        (SCAN_PROCESSING, 'Processing Results'),
        (SCAN_IMPORTED, 'Scan Results Imported'),
        (SCAN_ERROR, 'Error During Scan Operations'),
        (SCAN_TIMEOUT, 'Scan Operation Timed Out'),
    ]

    scan_status = models.CharField(
        max_length=30,
        choices=SCAN_STATUS_CHOICES,
        default=SCAN_NONE,
        verbose_name="Tenable Scan Status"
    )
    scan_status_message = models.TextField(blank=True, null=True, verbose_name="Scan Status Message")
    tenable_scan_id = models.IntegerField(null=True, blank=True, verbose_name="Tenable Scan Integer ID")
    def get_scan_status_display(self):  # Ensure this method exists if used in logs/templates
        return dict(self.SCAN_STATUS_CHOICES).get(self.scan_status, self.scan_status)

    def __str__(self): return f"{self.client.name} - {self.get_assessment_type_display()} ({self.id})"

    @property
    def ce_plus_window_end_date(self):
        if self.assessment_type == 'CE+' and self.date_ce_passed:
            try:
                # Calculate 90 days from the CE pass date
                return self.date_ce_passed + timezone.timedelta(days=90)
            except TypeError:  # Handle potential None or invalid date
                return None
        return None

    def can_launch_ce_plus_scan(self) -> dict:
        """
        Checks if conditions are met to enable the 'Launch Scan' button for CE+.
        Returns a dictionary: {'can_launch': bool, 'reason': str}
        """
        print(f"[DEBUG Assessment.can_launch_ce_plus_scan] Checking for Assessment {self.id}")  # DEBUG

        if self.assessment_type != 'CE+':
            print("[DEBUG Assessment.can_launch_ce_plus_scan] Result: False (Not CE+)")  # DEBUG
            return {'can_launch': False, 'reason': _("Scan launch is only applicable for CE+ assessments.")}

        # Get relevant sampled items (prefetching might optimize this if called often)
        # Using related name 'scoped_items' from ScopedItem model
        sampled_items = self.scoped_items.filter(is_in_ce_plus_sample=True)

        if not sampled_items.exists():
            print("[DEBUG Assessment.can_launch_ce_plus_scan] Result: False (No sample items)")  # DEBUG
            return {'can_launch': False, 'reason': _("No items found in the CE+ sample.")}

        # Identify item types that require agent linking for scanning
        item_types_requiring_link = ['Laptop', 'Desktop', 'Server']
        items_requiring_link = sampled_items.filter(item_type__in=item_types_requiring_link)

        if not items_requiring_link.exists():
            # If no laptops/desktops/servers are in the sample, scan can technically proceed
            # (e.g., sample only contains mobile devices or network devices)
            print(
                "[DEBUG Assessment.can_launch_ce_plus_scan] Result: True (No sample items require agent linking)")  # DEBUG
            return {'can_launch': True, 'reason': _("Scan can be launched (no sampled items require agent linking).")}

        # Check if ALL items requiring a link actually have one
        all_items_linked = items_requiring_link.filter(
            linked_tenable_agent_uuid__isnull=False).count() == items_requiring_link.count()

        if not all_items_linked:
            unlinked_count = items_requiring_link.filter(linked_tenable_agent_uuid__isnull=True).count()
            reason = _(
                "Cannot launch scan: {count} sampled device(s) (Laptop/Desktop/Server) still need a Tenable Agent linked.").format(
                count=unlinked_count)
            print(
                f"[DEBUG Assessment.can_launch_ce_plus_scan] Result: False ({unlinked_count} items not linked)")  # DEBUG
            return {'can_launch': False, 'reason': reason}

        # All checks passed
        print("[DEBUG Assessment.can_launch_ce_plus_scan] Result: True (All checks passed)")  # DEBUG
        return {'can_launch': True, 'reason': _("Ready to launch scan.")}
    # CHANGES END
class Evidence(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='evidence_files')
    file = models.FileField(upload_to='evidence/%Y/%m/%d/')
    description = models.CharField(max_length=255, help_text="E.g., Final Report, Certificate")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    def __str__(self): return f"{self.description} for Assessment {self.assessment.id}"
    @property
    def filename(self): import os; return os.path.basename(self.file.name)
class AssessmentLog(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    event = models.TextField()
    class Meta: ordering = ['-timestamp']
    def __str__(self): user_str = self.user.username if self.user else "System"; return f"{self.timestamp.strftime('%Y-%m-%d %H:%M')} - {user_str}: {self.event}"
class Network(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='networks')
    name = models.CharField(max_length=150, help_text="e.g., 'Office LAN', 'Guest WiFi', 'Azure Production VNet'")
    description = models.TextField(blank=True, help_text="Optional description of the network's purpose or location.")
    ip_range = models.CharField(max_length=100, blank=True, verbose_name="IP Range / Subnet", help_text="e.g., 192.168.1.0/24, 10.0.0.0/8")
    vlan_id = models.IntegerField(null=True, blank=True, verbose_name="VLAN ID")
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['assessment', 'name']
        # Prevent duplicate network names within the same assessment
        unique_together = ('assessment', 'name')

    def __str__(self):
        details = []
        if self.ip_range:
            details.append(f"IP: {self.ip_range}")
        if self.vlan_id is not None: # Check for None, as 0 could be a valid VLAN ID
            details.append(f"VLAN: {self.vlan_id}")

        if details:
            return f"{self.name} ({', '.join(details)})"
        else:
            # Fallback if no IP or VLAN is set
            return f"{self.name}"
class ScopedItem(models.Model):
    ITEM_TYPE_CHOICES = (('Laptop', 'Laptop'),('Desktop', 'Desktop'),('Server', 'Server'),('Mobile', 'Mobile Device'),('IP', 'Network Device (IP)'),('SaaS', 'Software as a Service'),('PaaS', 'Platform as a Service'),('IaaS', 'Infrastructure as a Service'),('Firewall', 'Firewall'),('Router', 'Router'),('Switch', 'Switch'),('Other', 'Other'),)
    OWNER_CHOICES = (('Organisation', 'Organisation Owned'),('BYOD', 'Bring Your Own Device'),)

    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='scoped_items')
    item_type = models.CharField(max_length=10, choices=ITEM_TYPE_CHOICES)
    identifier = models.CharField(
        max_length=200,
        help_text="E.g., Hostname, Asset Tag (Can be added/edited later if creating multiple)",
        blank=True,
        null=True
    )
    operating_system = models.ForeignKey(OperatingSystem, on_delete=models.SET_NULL, null=True, blank=True, related_name='scoped_items', verbose_name="Operating System / Version")
    make_model = models.CharField(max_length=100, blank=True, verbose_name="Make/Model")
    role_function = models.TextField(blank=True, help_text="Purpose within the business.")
    location = models.CharField(max_length=100, blank=True)
    owner = models.CharField(max_length=15, choices=OWNER_CHOICES, blank=True)
    notes = models.TextField(blank=True)

    # --- NEW FIELD ---
    is_in_ce_plus_sample = models.BooleanField(
        default=False,
        verbose_name="In CE+ Sample",
        help_text="Marked by assessor as part of the CE+ test sample."
    )
    network = models.ForeignKey(
        Network,
        on_delete=models.SET_NULL,  # If network is deleted, don't delete the item, just nullify the link
        null=True,
        blank=True,
        related_name='scoped_items',
        verbose_name="Associated Network"
    )
    linked_tenable_agent_uuid = models.UUIDField(
        null=True,
        blank=True,
        # unique=True, # Decided against unique=True for now, might be too restrictive.
        help_text="UUID of the Tenable Nessus Agent linked to this item (if applicable)"
    )

    # --- END NEW FIELD ---

    def __str__(self):
        ident_str = self.identifier if self.identifier else f"Item ID: {self.id}"
        return f"{self.get_item_type_display()}: {ident_str} (Assessment: {self.assessment.id})"
class CloudServiceDefinition(models.Model):
    name = models.CharField(max_length=200, unique=True, help_text="Common name of the cloud service (e.g., Microsoft 365 Business Premium)")
    vendor = models.CharField(max_length=100, blank=True)
    service_url = models.URLField(max_length=255, blank=True, verbose_name="Service Login/Info URL")
    description = models.TextField(blank=True, help_text="Brief description of the service.")
    requires_mfa_for_ce = models.BooleanField(default=True, verbose_name="MFA Required for CE", help_text="Does Cyber Essentials mandate MFA for this type of service?")
    is_globally_approved = models.BooleanField(default=False, help_text="Approved by Admin/Assessor for selection by clients.")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='suggested_cloud_services', on_delete=models.SET_NULL, null=True, blank=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='approved_cloud_services', on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['vendor', 'name']
        verbose_name = "Cloud Service Definition"
        verbose_name_plural = "Cloud Service Definitions"

    def __str__(self):
        return f"{self.name}" + (f" ({self.vendor})" if self.vendor else "")
class AssessmentCloudService(models.Model):
    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='assessment_cloud_services')
    cloud_service_definition = models.ForeignKey(CloudServiceDefinition, on_delete=models.PROTECT, related_name='assessment_instances', verbose_name="Cloud Service") # Protect definitions
    client_notes = models.TextField(blank=True, verbose_name="Client Usage Notes")
    mfa_admin_proof = models.FileField(upload_to=mfa_proof_upload_path, null=True, blank=True, verbose_name="Admin MFA Proof")
    mfa_user_proof = models.FileField(upload_to=mfa_proof_upload_path, null=True, blank=True, verbose_name="User MFA Proof")
    mfa_admin_verified = models.BooleanField(default=False, verbose_name="Admin MFA Verified")
    mfa_user_verified = models.BooleanField(default=False, verbose_name="User MFA Verified")
    is_compliant = models.BooleanField(default=False, verbose_name="MFA Compliant")
    assessor_notes = models.TextField(blank=True, verbose_name="Assessor Verification Notes")
    added_at = models.DateTimeField(auto_now_add=True)
    last_verified_at = models.DateTimeField(null=True, blank=True) # Track when assessor last verified
    verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='verified_cloud_services', on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['assessment', 'cloud_service_definition__name']
        unique_together = ('assessment', 'cloud_service_definition') # Only one instance of each service definition per assessment
        verbose_name = "Assessment Cloud Service"
        verbose_name_plural = "Assessment Cloud Services"

    def __str__(self):
        return f"{self.cloud_service_definition.name} for Assessment {self.assessment.id}"

    @property
    def admin_proof_filename(self):
        return os.path.basename(self.mfa_admin_proof.name) if self.mfa_admin_proof else None

    @property
    def user_proof_filename(self):
        return os.path.basename(self.mfa_user_proof.name) if self.mfa_user_proof else None
class WorkflowStepDefinition(models.Model):
    """Defines a standard step in the CE+ assessment workflow."""
    ASSIGNEE_CHOICES = (
        ('Applicant', 'Applicant (Client)'), # Matched display text to previous usage
        ('Assessor', 'Assessor (Internal Staff)'), # Matched display text to previous usage
        ('Both', 'Both (Client and Assessor)'), # Matched display text to previous usage
    )

    step_order = models.PositiveIntegerField(unique=True, help_text="Order in which the step appears.")
    name = models.CharField(max_length=100, help_text="Short name/identifier for the step.")
    description = models.TextField(help_text="Full description of the step requirement.")

    # Add this field:
    template_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="e.g., 'step_contact_details.html' or 'info_step.html'"
    )

    assignee_type = models.CharField(
        max_length=10,
        choices=ASSIGNEE_CHOICES,
        default='Both' # Note: Migration 0007 had 'Applicant' as default, your current model has 'Both'. This is fine, just an observation.
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Is this step currently part of the standard workflow?"
    )

    # Add this field (from migration 0007):
    skippable = models.BooleanField(
        default=False,
        help_text="Can this step be skipped by the assignee?"
    )

    class Meta:
        ordering = ['step_order']

    def __str__(self):
        return f"{self.step_order}. {self.name}"

class AssessmentWorkflowStep(models.Model):
    """Tracks the status of a specific workflow step for an assessment."""
    class Status(models.TextChoices):
        NOT_STARTED = 'NotStarted', _('Not Started')
        IN_PROGRESS = 'InProgress', _('In Progress')
        COMPLETE = 'Complete', _('Complete')
        # --- Add this line ---
        HELP_NEEDED = 'HelpNeeded', _('Help Needed')
        # --- End Add ---
        SKIPPED = 'Skipped', _('Skipped / Not Applicable')

    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='workflow_steps')
    step_definition = models.ForeignKey(WorkflowStepDefinition, on_delete=models.PROTECT, related_name='assessment_steps')
    # Increase max_length slightly if needed for new choice, although 'HelpNeeded' fits in 20
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NOT_STARTED)
    notes = models.TextField(blank=True, help_text="Notes specific to this step for this assessment.")
    completed_at = models.DateTimeField(null=True, blank=True)
    completed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+') # '+' prevents reverse accessor

    class Meta:
        ordering = ['assessment', 'step_definition__step_order']
        unique_together = ('assessment', 'step_definition') # Only one instance per step per assessment

    def __str__(self):
        return f"Assessment {self.assessment.id} - Step {self.step_definition.step_order}: {self.get_status_display()}"

    def is_update_allowed(self, user):
        """Check if the given user can update this step's status."""
        # Added print at the very start of the method call
        print(f"--- METHOD CALL: is_update_allowed called for Step {self.step_definition.step_order}, User {user.username} ---")
        if not user.is_authenticated:
            print(f"DEBUG (is_update_allowed): User not authenticated. Returning False.")
            return False

        assignee_type = self.step_definition.assignee_type
        # Use getattr for safer access to userprofile
        profile = getattr(user, 'userprofile', None)
        if not profile:
            print(f"DEBUG (is_update_allowed): User {user.username} has no profile. Returning False.") # Added print
            return False # User needs a profile

        # Added print statements inside the logic
        if assignee_type == 'Applicant':
            # Explicitly check components
            role_match = profile.role == 'Client'
            # Ensure profile.client and self.assessment.client are not None before comparing
            client_match = profile.client is not None and self.assessment.client is not None and self.assessment.client == profile.client
            result = role_match and client_match
            print(f"DEBUG (is_update_allowed): StepAssignee=Applicant, UserRole={profile.role}(Match={role_match}), ClientMatch={client_match} [AssessmentClientID={self.assessment.client.id if self.assessment.client else 'None'}, UserClientID={profile.client.id if profile.client else 'None'}], Result={result}")
            return result
        elif assignee_type == 'Assessor':
            # Explicitly check components
            is_assessor_match = profile.role == 'Assessor' and self.assessment.assessor == user
            is_admin_role = profile.role == 'Admin'
            result = is_assessor_match or is_admin_role
            print(f"DEBUG (is_update_allowed): StepAssignee=Assessor, UserRole={profile.role}, IsAssessorMatch={is_assessor_match}, IsAdmin={is_admin_role}, Result={result}")
            return result
        elif assignee_type == 'Both':
            # Explicitly check components
            is_client_user = profile.role == 'Client' and profile.client is not None and self.assessment.client is not None and self.assessment.client == profile.client
            is_assessor_match = profile.role == 'Assessor' and self.assessment.assessor == user
            is_admin_role = profile.role == 'Admin'
            is_assessor_admin = is_assessor_match or is_admin_role
            result = is_client_user or is_assessor_admin
            print(f"DEBUG (is_update_allowed): StepAssignee=Both, IsClient={is_client_user}, IsAssessorAdmin={is_assessor_admin}, Result={result}")
            return result

        print(f"DEBUG (is_update_allowed): Unknown AssigneeType '{assignee_type}', returning False.") # Added print
        return False
class ExternalIP(models.Model):
    """
    Represents an external IP address or hostname in scope for scanning.
    """
    # --- Check spelling of this field ---
    assessment = models.ForeignKey(
        Assessment,
        on_delete=models.CASCADE,
        related_name='external_ips'
    )
    # --- Check spelling of this field ---
    ip_address_or_hostname = models.CharField(
        max_length=255,
        verbose_name="IP Address or Hostname",
        help_text="Enter a valid IPv4, IPv6 address, or a resolvable hostname.",
        validators=[validate_ip_or_hostname]
    )
    description = models.TextField(
        blank=True,
        help_text="Optional description (e.g., 'Primary Web Server', 'Mail Gateway', 'Client VPN Endpoint')."
    )
    scan_status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        blank=True
    )
    assessor_notes = models.TextField(
        blank=True,
        verbose_name="Assessor Scan Notes",
        help_text="Notes regarding scan results or remediation for this IP/hostname."
    )
    added_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    # Consent Fields
    consent_given = models.BooleanField(
        default=False,
        verbose_name="Consent to Scan Provided",
        help_text="Indicates if explicit consent was provided to scan this target."
    )
    consented_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='consented_external_ips',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Consented By User"
    )
    consent_timestamp = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Consent Timestamp"
    )

    class Meta:
        # --- Check spelling in these two lines matches the fields above EXACTLY ---
        ordering = ['assessment', 'ip_address_or_hostname']
        unique_together = ('assessment', 'ip_address_or_hostname')
        # --- End check ---
        verbose_name = "External IP / Hostname"
        verbose_name_plural = "External IPs / Hostnames"

    def __str__(self):
        return f"{self.ip_address_or_hostname} (Assessment: {self.assessment.id})"
class UploadedReport(models.Model):
    """Stores uploaded Cyber Essentials report files and extracted data."""
    assessment = models.ForeignKey(
        Assessment,
        on_delete=models.SET_NULL, # Or CASCADE if reports should be deleted with assessment
        null=True,
        blank=True, # Allow unlinked uploads initially? Or link on upload?
        related_name='uploaded_reports'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    report_file = models.FileField(
        upload_to=ce_report_upload_path,
        verbose_name="CE Report PDF"
    )
    # Store extracted data - JSONField is good if using PostgreSQL, otherwise use TextField
    # extracted_data = models.JSONField(null=True, blank=True, verbose_name="Extracted Data")
    extracted_data_text = models.TextField(null=True, blank=True, verbose_name="Extracted Data (Text)")
    extraction_status = models.CharField(max_length=50, default="Pending", blank=True)
    report_date = models.DateField(null=True, blank=True) # Store key extracted fields if useful
    certificate_number = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        filename = os.path.basename(self.report_file.name) if self.report_file else 'No file'
        return f"Report {filename} for Assessment {self.assessment_id} (Uploaded: {self.uploaded_at.strftime('%Y-%m-%d')})"

    @property
    def filename(self):
        return os.path.basename(self.report_file.name) if self.report_file else None
class NessusAgentURL(models.Model):
    os_name = models.CharField(max_length=50, help_text="e.g., Windows, Debian, CentOS, macOS")
    architecture = models.CharField(max_length=20, help_text="e.g., x64, amd64, arm64")
    os_version_details = models.CharField(max_length=100, blank=True, help_text="e.g., 10 / 11, 11 / 12, 7 / 8 / 9") # Store details from page if available
    agent_version = models.CharField(max_length=30, blank=True, help_text="e.g., 10.7.1")
    download_url = models.URLField(max_length=1024, unique=True)
    file_name = models.CharField(max_length=255, blank=True) # Store filename if easily parsable
    last_scraped = models.DateTimeField(default=timezone.now)
    last_validated = models.DateTimeField(null=True, blank=True)
    is_valid = models.BooleanField(default=True)

    class Meta:
        ordering = ['os_name', 'architecture', '-agent_version'] # Show latest versions first
        verbose_name = "Nessus Agent Download URL"
        verbose_name_plural = "Nessus Agent Download URLs"
        indexes = [
            models.Index(fields=['os_name', 'architecture']),
        ]


    def __str__(self):
        return f"{self.os_name} ({self.architecture}) - {self.agent_version or 'Unknown Version'} - {'Valid' if self.is_valid else 'Invalid'}"
class AssessmentDateOption(models.Model):
    class Status(models.TextChoices):
        SUGGESTED = 'Suggested', _('Suggested')
        CLIENT_PREFERRED = 'ClientPreferred', _('Client Preferred')
        CONFIRMED = 'Confirmed', _('Confirmed by Assessor')
        REJECTED = 'Rejected', _('Rejected')

    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name='date_options')
    proposed_date = models.DateField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.SUGGESTED)
    proposed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, # Keep the record even if user is deleted
        null=True, blank=True,
        related_name='proposed_dates'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['assessment', 'proposed_date']
        # Prevent proposing the exact same date for the same assessment twice
        unique_together = ('assessment', 'proposed_date')
        verbose_name = "Assessment Date Option"
        verbose_name_plural = "Assessment Date Options"

    def __str__(self):
        proposer = f" by {self.proposed_by.username}" if self.proposed_by else ""
        return f"{self.proposed_date.strftime('%Y-%m-%d')} ({self.get_status_display()}){proposer} for Assessment {self.assessment.id}"
class AssessorAvailability(models.Model):
    assessor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE, # If assessor user deleted, their availability is gone
        related_name='unavailable_dates',
        limit_choices_to={'userprofile__role': 'Assessor'} # Ensure only assessors are selected
    )
    unavailable_date = models.DateField(verbose_name="Date Unavailable")
    reason = models.CharField(max_length=255, blank=True, help_text="Optional reason (e.g., Holiday, Training)")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['assessor', 'unavailable_date']
        # Assessor can only block a specific date once
        unique_together = ('assessor', 'unavailable_date')
        verbose_name = "Assessor Unavailable Date"
        verbose_name_plural = "Assessor Unavailable Dates"

    def __str__(self):
        return f"Assessor {self.assessor.username} unavailable on {self.unavailable_date.strftime('%Y-%m-%d')}"
class CriticalErrorLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    level = models.CharField(max_length=50, default='CRITICAL')
    module = models.CharField(max_length=255, blank=True, null=True)
    function = models.CharField(max_length=255, blank=True, null=True)
    line_number = models.PositiveIntegerField(blank=True, null=True)
    message = models.TextField()
    traceback = models.TextField(blank=True, null=True)

    # New fields for acknowledgment
    is_acknowledged = models.BooleanField(default=False, db_index=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, # Keeps the log if the user is deleted
        blank=True,
        null=True,
        related_name='acknowledged_critical_errors',
        verbose_name="Acknowledged By"
    )

    def __str__(self):
        ack_status = "Acknowledged" if self.is_acknowledged else "Pending"
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M')} - {self.message[:70]}... ({ack_status})"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Critical Error Log"
        verbose_name_plural = "Critical Error Logs"






