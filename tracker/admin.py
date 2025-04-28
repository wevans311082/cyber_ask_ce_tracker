# tracker/admin.py
from django.contrib import admin
# --- Ensure OperatingSystem is imported ---
from .models import (
    Client, UserProfile, Assessment, ScopedItem, Evidence, AssessmentLog,
    OperatingSystem, Network,  CloudServiceDefinition, AssessmentCloudService # Ensure it's here
)
# --- End Ensure ---
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.utils.html import format_html
from django.utils import timezone

# ... (CustomUserAdmin, ClientAdmin remain the same) ...
class UserProfileInline(admin.StackedInline): model = UserProfile; can_delete = False; verbose_name_plural = 'Profile'; fk_name = 'user'
class CustomUserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,); list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_role'); list_select_related = ('userprofile',)
    def get_role(self, instance):
        if hasattr(instance, 'userprofile') and instance.userprofile: return instance.userprofile.get_role_display()
        return 'No Profile'
    get_role.short_description = 'Role'
    def get_inline_instances(self, request, obj=None):
        if not obj: return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)
admin.site.unregister(User); admin.site.register(User, CustomUserAdmin)
@admin.register(Client)
class ClientAdmin(admin.ModelAdmin): list_display = ('name', 'contact_person', 'contact_email', 'created_at'); search_fields = ('name', 'contact_person', 'contact_email')

@admin.register(OperatingSystem)
class OperatingSystemAdmin(admin.ModelAdmin):
    # --- UPDATED list_display and added list_filter/search_fields ---
    list_display = ('name', 'version', 'vendor', 'end_of_life_date', 'is_supported')
    list_filter = ('is_supported', 'vendor', 'name')
    search_fields = ('name', 'version', 'vendor')
    # --- END UPDATE ---

# ... (ScopedItemInline needs to use operating_system, EvidenceInline, AssessmentLogInline remain the same) ...
@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'assessment', 'ip_range', 'vlan_id', 'updated_at')
    list_filter = ('assessment__client', ) # Filter by client via assessment
    search_fields = ('name', 'ip_range', 'assessment__client__name')
    list_select_related = ('assessment__client',) # Optimise query
    # Make assessment selectable but read-only after creation if desired
    # readonly_fields = ('assessment',) # Be careful if using this

# --- ScopedItemInline (MODIFIED) ---
class ScopedItemInline(admin.TabularInline):
    model = ScopedItem
    extra = 1
    # --- Add 'network' to fields ---
    fields = ('item_type', 'identifier', 'operating_system', 'network', 'make_model', 'role_function', 'owner') # Added network
    autocomplete_fields = ['operating_system', 'network'] # Add network here too
    # --- Filter network choices based on the Assessment being edited ---
    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "network":
            # Get the current assessment object ID from the request URL if available
            # This relies on the admin URL structure (e.g., /admin/tracker/assessment/1/change/)
            assessment_id = None
            try:
                # Extract assessment ID from the path
                path_parts = request.path.strip('/').split('/')
                if 'tracker' in path_parts and 'assessment' in path_parts:
                    assessment_id = int(path_parts[path_parts.index('assessment') + 1])
            except (ValueError, IndexError):
                 pass # Ignore if ID cannot be parsed

            if assessment_id:
                 kwargs["queryset"] = Network.objects.filter(assessment_id=assessment_id)
            else:
                 # Show no networks if assessment context isn't clear (e.g., on add assessment page)
                 kwargs["queryset"] = Network.objects.none()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

class EvidenceInline(admin.TabularInline): model = Evidence; extra = 1; fields = ('file', 'description', 'uploaded_at', 'uploaded_by'); readonly_fields = ('uploaded_at', 'uploaded_by')
class AssessmentLogInline(admin.TabularInline): model = AssessmentLog; extra = 0; readonly_fields = ('timestamp', 'user', 'event'); can_delete = False

@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    # ... (AssessmentAdmin code remains the same) ...
    list_display = ('id', 'client', 'assessment_type', 'status', 'assessor', 'date_target_end', 'final_outcome'); list_filter = ('status', 'assessment_type', 'final_outcome', 'client', 'assessor'); search_fields = ('client__name', 'id', 'assessor__username'); list_select_related = ('client', 'assessor')
    fieldsets = ((None, {'fields': ('client', 'assessor', 'assessment_type', 'scope_type', 'scope_description')}),('Status & Outcome', {'fields': ('status', 'final_outcome', 'ce_self_assessment_ref')}),('Dates', {'fields': ('date_start', 'date_target_end', 'date_actual_end', 'date_cert_issued', 'date_cert_expiry')}),)
    inlines = [ScopedItemInline, EvidenceInline, AssessmentLogInline]
    def save_formset(self, request, form, formset, change):
        if formset.model == Evidence:
            instances = formset.save(commit=False);
            for instance in instances:
                if not instance.pk and hasattr(request, 'user') and request.user.is_authenticated: instance.uploaded_by = request.user
                instance.save()
            formset.save_m2m()
        elif formset.model == AssessmentLog: pass
        else: super().save_formset(request, form, formset, change)
# Simple registration for other models if needed


@admin.register(CloudServiceDefinition)
class CloudServiceDefinitionAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'is_globally_approved', 'requires_mfa_for_ce', 'updated_at')
    list_filter = ('is_globally_approved', 'requires_mfa_for_ce', 'vendor')
    search_fields = ('name', 'vendor', 'description')
    list_editable = ('is_globally_approved', 'requires_mfa_for_ce') # Allow quick editing in list view
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'approved_by')
    actions = ['approve_selected_definitions']

    @admin.action(description='Approve selected definitions globally')
    def approve_selected_definitions(self, request, queryset):
        updated_count = queryset.update(is_globally_approved=True, approved_by=request.user)
        self.message_user(request, f'{updated_count} cloud service definitions approved globally.')

# --- END NEW ---


# --- NEW: Assessment Cloud Service Admin ---
# Registering standalone for now, could be an inline for AssessmentAdmin later
@admin.register(AssessmentCloudService)
class AssessmentCloudServiceAdmin(admin.ModelAdmin):
    list_display = ('cloud_service_definition', 'assessment_link', 'mfa_admin_verified', 'mfa_user_verified', 'is_compliant', 'added_at')
    list_filter = ('assessment__client', 'is_compliant', 'mfa_admin_verified', 'mfa_user_verified', 'cloud_service_definition__vendor')
    search_fields = ('cloud_service_definition__name', 'assessment__client__name', 'assessment__id')
    list_select_related = ('assessment__client', 'cloud_service_definition')
    # Make verification fields editable in list view for assessors
    list_editable = ('mfa_admin_verified', 'mfa_user_verified', 'is_compliant')
    readonly_fields = ('added_at', 'last_verified_at', 'verified_by', 'admin_proof_preview', 'user_proof_preview') # Add previews
    fields = ( # Define field order and sections in edit view
        'assessment', 'cloud_service_definition', 'client_notes',
        ('mfa_admin_proof', 'admin_proof_preview'),
        ('mfa_user_proof', 'user_proof_preview'),
        ('mfa_admin_verified', 'mfa_user_verified', 'is_compliant'),
        'assessor_notes',
        ('verified_by', 'last_verified_at')
    )

    # Helper to link to assessment in admin
    @admin.display(description='Assessment')
    def assessment_link(self, obj):
        from django.urls import reverse
        link = reverse("admin:tracker_assessment_change", args=[obj.assessment.id])
        return format_html('<a href="{}">{}</a>', link, f"#{obj.assessment.id} ({obj.assessment.client.name})")

    # Helpers for previewing images (basic)
    @admin.display(description='Admin Proof Preview')
    def admin_proof_preview(self, obj):
         return format_html('<img src="{}" style="max-height: 100px; max-width: 200px;" />', obj.mfa_admin_proof.url) if obj.mfa_admin_proof else '(No file)'

    @admin.display(description='User Proof Preview')
    def user_proof_preview(self, obj):
         return format_html('<img src="{}" style="max-height: 100px; max-width: 200px;" />', obj.mfa_user_proof.url) if obj.mfa_user_proof else '(No file)'

    # Auto-set verified_by when assessor changes verification status
    def save_model(self, request, obj, form, change):
        # Check if verification status fields have changed
        if change and any(field in form.changed_data for field in ['mfa_admin_verified', 'mfa_user_verified', 'is_compliant']):
            obj.verified_by = request.user
            obj.last_verified_at = timezone.now() # Make sure to import timezone
        super().save_model(request, obj, form, change)

# --- END NEW ---




admin.site.register(ScopedItem) # Not needed if using inline
admin.site.register(Evidence)   # Not needed if using inline
admin.site.register(AssessmentLog) # Not needed if using inline
admin.site.register(UserProfile) # Not needed if using inline with User