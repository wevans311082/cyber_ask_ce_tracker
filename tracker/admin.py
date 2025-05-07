# tracker/admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.urls import reverse # Import reverse for links
from .views import tenable_policy_template_list_view, tenable_scanner_list_view
from django.urls import path

# --- Import ALL necessary models ---
from .models import (
    Client, UserProfile, Assessment, ScopedItem, Evidence, AssessmentLog,
    OperatingSystem, Network, CloudServiceDefinition, AssessmentCloudService,
    WorkflowStepDefinition, AssessmentWorkflowStep, ExternalIP, UploadedReport,
    NessusAgentURL,
    AssessmentDateOption,  # <-- Required
    AssessorAvailability   # <-- Required
)


original_get_urls = admin.site.get_urls

def get_urls():
    urls = original_get_urls()
    custom_urls = [
        # The path remains the same, but the view points to the imported function
        path(
            'tracker/tenable-policies/',
            admin.site.admin_view(tenable_policy_template_list_view), # Wrap view with admin_view
            name='tenable_policy_list'
        ),
        path(
            'tracker/tenable-scanners/',
            admin.site.admin_view(tenable_scanner_list_view),
            name='tenable_scanner_list'
        )


    ] # <--- CHANGES END (View Source)
    return custom_urls + urls

admin.site.get_urls = get_urls



# --- User Admin (with profile inline) ---
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

class CustomUserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_role')
    list_select_related = ('userprofile',) # Optimize query

    @admin.display(description='Role')
    def get_role(self, instance):
        if hasattr(instance, 'userprofile') and instance.userprofile:
            return instance.userprofile.get_role_display()
        return 'No Profile'

    # Prevent errors when creating a new user before profile exists
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

# --- Client Admin ---
@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
    list_display = ('name', 'contact_person', 'contact_email', 'created_at', 'companies_house_validated', 'last_companies_house_validation') # Added validation fields
    search_fields = ('name', 'contact_person', 'contact_email', 'organization_number')
    list_filter = ('companies_house_validated',)


# --- OperatingSystem Admin ---
@admin.register(OperatingSystem)
class OperatingSystemAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'vendor', 'category', 'end_of_life_date', 'is_supported') # Added category
    list_filter = ('is_supported', 'vendor', 'category', 'name') # Added category
    search_fields = ('name', 'version', 'vendor')


# --- Network Admin ---
@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'assessment_link', 'ip_range', 'vlan_id', 'updated_at') # Use link function
    list_filter = ('assessment__client__name', )
    search_fields = ('name', 'ip_range', 'assessment__client__name', 'assessment__id')
    list_select_related = ('assessment__client',) # Optimise query

    # Helper to link to assessment in admin
    @admin.display(description='Assessment')
    def assessment_link(self, obj):
        if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")
        return "N/A"

# --- Inlines for Assessment Admin (Define BEFORE AssessmentAdmin) ---

class ScopedItemInline(admin.TabularInline):
    model = ScopedItem
    extra = 0 # Don't show empty rows by default
    fields = ('item_type', 'identifier', 'operating_system', 'network', 'make_model', 'role_function', 'owner', 'is_in_ce_plus_sample')
    readonly_fields = ('is_in_ce_plus_sample',) # Assessor sets this via button usually
    autocomplete_fields = ['operating_system', 'network']
    verbose_name = "Scoped Item"
    verbose_name_plural = "Scope Items"

    # Filter network choices based on the Assessment being edited
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "network":
            assessment_id = None
            resolver_match = request.resolver_match
            if resolver_match and 'object_id' in resolver_match.kwargs:
                 try:
                     assessment_id = int(resolver_match.kwargs['object_id'])
                 except (ValueError, TypeError):
                      pass # Ignore if not an integer

            if assessment_id:
                 kwargs["queryset"] = Network.objects.filter(assessment_id=assessment_id).order_by('name')
            else:
                 kwargs["queryset"] = Network.objects.none() # No assessment context yet
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

class EvidenceInline(admin.TabularInline):
    model = Evidence
    extra = 0
    fields = ('file', 'description', 'uploaded_at', 'uploaded_by')
    readonly_fields = ('uploaded_at', 'uploaded_by')

class AssessmentLogInline(admin.TabularInline):
    model = AssessmentLog
    extra = 0
    readonly_fields = ('timestamp', 'user', 'event')
    can_delete = False
    ordering = ('-timestamp',)

# --- Assessment Date Option Inline (Defined BEFORE AssessmentAdmin) ---
class AssessmentDateOptionInline(admin.TabularInline):
    model = AssessmentDateOption
    extra = 0 # Don't show blank rows by default
    fields = ('proposed_date', 'status', 'proposed_by', 'notes', 'created_at', 'updated_at')
    readonly_fields = ('proposed_by', 'created_at', 'updated_at')
    ordering = ('proposed_date',)
    verbose_name = "Proposed Assessment Date"
    verbose_name_plural = "Proposed Assessment Dates"

# --- Assessment Admin (Now uses defined Inlines) ---
@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ('id', 'client', 'assessment_type', 'status', 'assessor_link', 'date_target_end', 'date_ce_passed', 'final_outcome', 'tenable_scan_uuid') # Added date_ce_passed
    list_filter = ('status', 'assessment_type', 'final_outcome', 'client', 'assessor')
    search_fields = ('client__name', 'id', 'assessor__username')
    list_select_related = ('client', 'assessor') # assessor is needed for link
    date_hierarchy = 'created_at' # Add date hierarchy

    fieldsets = (
        (None, {'fields': ('client', 'assessor', 'assessment_type')}),
        ('Scope', {'fields': ('scope_type', 'scope_description')}),
        ('Status & Outcome', {'fields': ('status', 'final_outcome', 'ce_self_assessment_ref')}),
        ('Dates', {'fields': (
        'date_ce_passed', 'date_start', 'date_target_end', 'date_actual_end', 'date_cert_issued', 'date_cert_expiry')}),
        # Field remains in the Integrations fieldset
        ('Integrations', {
            'fields': ('tenable_scan_uuid',),
            'classes': ('collapse',),
        }),
    )
    # --- Use the INLINE classes defined above ---
    inlines = [AssessmentDateOptionInline, ScopedItemInline, EvidenceInline, AssessmentLogInline]
    # --- END ---
    autocomplete_fields = ['client', 'assessor'] # Make FKs searchable

    @admin.display(description='Assessor')
    def assessor_link(self, obj):
        if obj.assessor:
            link = reverse("admin:auth_user_change", args=[obj.assessor.id])
            return format_html('<a href="{}">{}</a>', link, obj.assessor.username)
        return "-"

    def save_formset(self, request, form, formset, change):
        instances = formset.save(commit=False)
        for instance in instances:
            # Set uploaded_by for Evidence if new
            if isinstance(instance, Evidence) and not instance.pk:
                instance.uploaded_by = request.user
            # Set proposed_by for AssessmentDateOption if new and added via *inline*
            if isinstance(instance, AssessmentDateOption) and not instance.pk and not instance.proposed_by:
                 instance.proposed_by = request.user # Assumes admin proposes via inline
            instance.save()
        formset.save_m2m() # Important for M2M fields if any


# --- Cloud Service Definition Admin ---
@admin.register(CloudServiceDefinition)
class CloudServiceDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'is_globally_approved', 'requires_mfa_for_ce', 'updated_at')
    list_filter = ('is_globally_approved', 'requires_mfa_for_ce', 'vendor')
    search_fields = ('name', 'vendor', 'description')
    list_editable = ('is_globally_approved', 'requires_mfa_for_ce')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'approved_by')
    actions = ['approve_selected_definitions']

    @admin.action(description='Approve selected definitions globally')
    def approve_selected_definitions(self, request, queryset):
        updated_count = queryset.update(is_globally_approved=True, approved_by=request.user, updated_at=timezone.now())
        self.message_user(request, f'{updated_count} cloud service definitions approved globally.')


# --- Assessment Cloud Service Admin ---
@admin.register(AssessmentCloudService)
class AssessmentCloudServiceAdmin(admin.ModelAdmin):
    list_display = ('cloud_service_definition', 'assessment_link', 'mfa_admin_verified', 'mfa_user_verified', 'is_compliant', 'added_at')
    list_filter = ('assessment__client__name', 'is_compliant', 'mfa_admin_verified', 'mfa_user_verified', 'cloud_service_definition__vendor')
    search_fields = ('cloud_service_definition__name', 'assessment__client__name', 'assessment__id')
    list_select_related = ('assessment__client', 'cloud_service_definition', 'verified_by')
    list_editable = ('mfa_admin_verified', 'mfa_user_verified', 'is_compliant')
    readonly_fields = ('added_at', 'last_verified_at', 'verified_by', 'admin_proof_preview', 'user_proof_preview')
    fields = (
        'assessment', 'cloud_service_definition', 'client_notes',
        ('mfa_admin_proof', 'admin_proof_preview'),
        ('mfa_user_proof', 'user_proof_preview'),
        ('mfa_admin_verified', 'mfa_user_verified', 'is_compliant'),
        'assessor_notes',
        ('verified_by', 'last_verified_at')
    )
    autocomplete_fields = ['assessment', 'cloud_service_definition']

    @admin.display(description='Assessment')
    def assessment_link(self, obj):
        if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")
        return "N/A"

    @admin.display(description='Admin Proof Preview')
    def admin_proof_preview(self, obj):
         return format_html('<a href="{0}" target="_blank"><img src="{0}" style="max-height: 100px; max-width: 200px;" /></a>', obj.mfa_admin_proof.url) if obj.mfa_admin_proof else '(No file)'

    @admin.display(description='User Proof Preview')
    def user_proof_preview(self, obj):
         return format_html('<a href="{0}" target="_blank"><img src="{0}" style="max-height: 100px; max-width: 200px;" /></a>', obj.mfa_user_proof.url) if obj.mfa_user_proof else '(No file)'

    def save_model(self, request, obj, form, change):
        if change and any(field in form.changed_data for field in ['mfa_admin_verified', 'mfa_user_verified', 'is_compliant']):
            obj.verified_by = request.user
            obj.last_verified_at = timezone.now()
        super().save_model(request, obj, form, change)


# --- Workflow Definitions Admin ---
@admin.register(WorkflowStepDefinition)
class WorkflowStepDefinitionAdmin(admin.ModelAdmin):
    list_display = ('step_order', 'name', 'assignee_type', 'is_active')
    list_editable = ('is_active', 'assignee_type')
    ordering = ('step_order',)

# --- Assessment Workflow Step Admin ---
@admin.register(AssessmentWorkflowStep)
class AssessmentWorkflowStepAdmin(admin.ModelAdmin):
    list_display = ('assessment_link', 'step_definition', 'status', 'completed_by', 'completed_at')
    list_filter = ('assessment__client__name', 'status', 'step_definition')
    search_fields = ('assessment__id', 'assessment__client__name', 'step_definition__name')
    readonly_fields = ('assessment', 'step_definition', 'completed_by', 'completed_at')
    list_select_related = ('assessment__client', 'step_definition', 'completed_by')
    list_editable = ('status',) # Allow status changes here? Be careful with side effects.

    @admin.display(description='Assessment')
    def assessment_link(self, obj):
         if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")
         return "N/A"

# --- External IP Admin ---
@admin.register(ExternalIP)
class ExternalIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address_or_hostname', 'assessment_link', 'scan_status', 'consent_given', 'last_scanned_at')
    list_filter = ('assessment__client__name', 'scan_status', 'consent_given')
    search_fields = ('ip_address_or_hostname', 'assessment__id', 'assessment__client__name')
    readonly_fields = ('added_at', 'last_scanned_at', 'consented_by', 'consent_timestamp')
    list_select_related = ('assessment__client', 'consented_by')
    list_editable = ('scan_status', 'consent_given')

    @admin.display(description='Assessment')
    def assessment_link(self, obj):
         if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")
         return "N/A"

# --- Uploaded Report Admin ---
@admin.register(UploadedReport)
class UploadedReportAdmin(admin.ModelAdmin):
    list_display = ('report_file', 'assessment_link', 'uploaded_by', 'uploaded_at', 'extraction_status', 'report_date', 'certificate_number')
    list_filter = ('assessment__client__name', 'extraction_status', 'uploaded_by')
    search_fields = ('report_file', 'assessment__id', 'assessment__client__name', 'certificate_number')
    readonly_fields = ('uploaded_at', 'uploaded_by', 'extracted_data_text', 'extraction_status', 'report_date', 'certificate_number')
    list_select_related = ('assessment__client', 'uploaded_by')
    autocomplete_fields = ['assessment']

    @admin.display(description='Assessment')
    def assessment_link(self, obj):
        if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")
        return "(Not Linked)"

# --- Nessus Agent URL Admin ---
@admin.register(NessusAgentURL)
class NessusAgentURLAdmin(admin.ModelAdmin):
    list_display = ('os_name', 'architecture', 'agent_version', 'file_name', 'is_valid', 'last_scraped', 'last_validated')
    list_filter = ('is_valid', 'os_name', 'architecture')
    search_fields = ('os_name', 'architecture', 'agent_version', 'file_name', 'download_url')
    readonly_fields = ('last_scraped', 'last_validated')
    list_editable = ('is_valid',)


# --- Assessment Date Option Admin (Standalone Registration) ---
@admin.register(AssessmentDateOption)
class AssessmentDateOptionAdmin(admin.ModelAdmin):
    list_display = ('assessment_link', 'proposed_date', 'status', 'proposed_by', 'created_at')
    list_filter = ('status', 'assessment__client__name', 'assessment__assessment_type', ('proposed_date', admin.DateFieldListFilter))
    search_fields = ('assessment__id', 'assessment__client__name', 'notes', 'proposed_by__username')
    list_select_related = ('assessment__client', 'proposed_by')
    readonly_fields = ('created_at', 'updated_at')
    # list_editable = ('status',) # Keep commented out to prevent bypassing view logic
    autocomplete_fields = ['assessment', 'proposed_by']

    @admin.display(ordering='assessment__id', description='Assessment')
    def assessment_link(self, obj):
         if obj.assessment:
            link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
            client_name = obj.assessment.client.name if obj.assessment.client else "No Client"
            return format_html('<a href="{}">#{} ({})</a>', link, obj.assessment.id, client_name)
         return "N/A"

# --- Assessor Availability Admin (Standalone Registration) ---
@admin.register(AssessorAvailability)
class AssessorAvailabilityAdmin(admin.ModelAdmin):
    list_display = ('assessor', 'unavailable_date', 'reason', 'created_at')
    list_filter = ('assessor', ('unavailable_date', admin.DateFieldListFilter))
    search_fields = ('assessor__username', 'reason')
    autocomplete_fields = ['assessor']