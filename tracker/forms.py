from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
# Ensure ValidationError is imported if needed, though forms.ValidationError works
# from django.core.exceptions import ValidationError
import ipaddress
from django.core.exceptions import ValidationError
from .models import (
    Client, UserProfile, Assessment, ScopedItem, Evidence, AssessmentLog,
    OperatingSystem, Network, CloudServiceDefinition, AssessmentCloudService, ExternalIP, UploadedReport  # Ensure this is imported
)

# --- User/Profile Forms ---

class CustomUserCreationForm(UserCreationForm):
    role = forms.ChoiceField(choices=UserProfile.ROLE_CHOICES, required=True)
    client = forms.ModelChoiceField(queryset=Client.objects.all(), required=False,
                                    help_text="Required only if role is 'Client'.")

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('first_name', 'last_name', 'email',)

    def clean(self):
        """
        Validate that a Client company is selected if the role is Client.
        """
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        client = cleaned_data.get('client')

        if role == 'Client' and not client:
            # Raise validation error associated with the 'client' field
            raise forms.ValidationError(
                {'client': "A Client company must be selected if the Role is 'Client'."}
            )
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            # Use cleaned_data which has passed validation
            profile_client = self.cleaned_data.get('client') # Already validated that this exists if role is Client
            UserProfile.objects.create(
                user=user,
                role=self.cleaned_data.get('role'),
                client=profile_client
            )
        return user

class CustomUserChangeForm(UserChangeForm):
    role = forms.ChoiceField(choices=UserProfile.ROLE_CHOICES, required=True)
    client = forms.ModelChoiceField(queryset=Client.objects.all(), required=False,
                                    help_text="Required only if role is 'Client'.")

    class Meta(UserChangeForm.Meta):
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'is_active', 'is_staff')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        profile_fields = ['role', 'client']
        if self.instance and hasattr(self.instance, 'userprofile'):
            profile = self.instance.userprofile
            for field_name in profile_fields:
                 if field_name in self.fields:
                    self.fields[field_name].initial = getattr(profile, field_name)
        if 'password' in self.fields:
            del self.fields['password']

    def clean(self):
        """
        Validate that a Client company is selected if the role is Client.
        """
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        client = cleaned_data.get('client')

        if role == 'Client' and not client:
            # Raise validation error associated with the 'client' field
            raise forms.ValidationError(
                {'client': "A Client company must be selected if the Role is 'Client'."}
            )
        # Ensure client field is cleared if role is not Client
        # (Although the save method also handles this, cleaning here is good practice)
        if role != 'Client' and client:
             cleaned_data['client'] = None

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit and hasattr(user, 'userprofile'):
            profile = user.userprofile
            # Use cleaned_data which has passed validation
            profile.role = self.cleaned_data['role']
            profile.client = self.cleaned_data.get('client') # Already validated/cleaned
            profile.save()
        return user

# --- Client Form ---

class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        # The fields list now includes the new ones
        fields = ['name', 'address', 'contact_person', 'contact_email', 'organization_number', 'website_address']
        # Widgets define how fields look in HTML
        widgets = {
            'address': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}), # Added class for consistency
            'contact_person': forms.TextInput(attrs={'class': 'form-control'}), # Added class
            'contact_email': forms.EmailInput(attrs={'class': 'form-control'}), # Added class
            'name': forms.TextInput(attrs={'class': 'form-control'}), # Added class
            # Widgets for the new fields
            'organization_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., 01234567'}),
            'website_address': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://www.example.com'}),
        }

# --- Assessment Forms ---

class AssessmentCloudServiceUpdateForm(forms.ModelForm):
    """
    Form for Clients to update notes and MFA proof for an existing AssessmentCloudService.
    """
    class Meta:
        model = AssessmentCloudService
        # Only include fields Clients should edit during an update
        fields = [
            'client_notes',
            'mfa_admin_proof',
            'mfa_user_proof',
        ]
        widgets = {
            'client_notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            # Ensure widget attributes provide necessary classes if not using crispy
            'mfa_admin_proof': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'mfa_user_proof': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }
        labels = {
             'client_notes': 'Your Notes (Optional)', # Adjust label if needed
             'mfa_admin_proof': "Admin MFA Proof (Screenshot/File)",
             'mfa_user_proof': "User MFA Proof (Screenshot/File)",
        }
        help_texts = {
             'client_notes': "Update any notes about how this service is used.",
             'mfa_admin_proof': "Upload new evidence if needed. Check 'Clear' to remove.",
             'mfa_user_proof': "Upload new evidence if needed. Check 'Clear' to remove.",
        }

class AssessmentCloudServiceAssessorForm(forms.ModelForm):
    class Meta:
        model = AssessmentCloudService
        fields = [
            'mfa_admin_verified',
            'mfa_user_verified',
            'is_compliant',
            'assessor_notes',
        ]
        widgets = {
            # Add form-check-input class for checkboxes if needed
            'mfa_admin_verified': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'mfa_user_verified': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_compliant': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
             # Add form-control class for textarea if needed
            'assessor_notes': forms.Textarea(attrs={'rows': 4, 'class': 'form-control'}),
        }
        labels = { # Ensure labels match template
            'mfa_admin_verified': "Admin MFA Verified by Assessor?",
            'mfa_user_verified': "User MFA Verified by Assessor?",
            'is_compliant': "Overall Service Compliant?",
            'assessor_notes': "Assessor Verification Notes",
        }

class AssessmentCreateForm(forms.ModelForm):
    class Meta:
        model = Assessment
        fields = ['client', 'assessor', 'assessment_type', 'scope_type', 'scope_description', 'date_target_end']
        widgets = {
            'date_target_end': forms.DateInput(attrs={'type': 'date'}),
             'scope_description': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assessor'].queryset = User.objects.filter(userprofile__role='Assessor')


class AssessmentStatusUpdateForm(forms.ModelForm):
    class Meta:
        model = Assessment
        fields = ['status', 'final_outcome', 'date_actual_end', 'date_cert_issued', 'date_cert_expiry', 'ce_self_assessment_ref']
        widgets = {
            'date_actual_end': forms.DateInput(attrs={'type': 'date'}),
            'date_cert_issued': forms.DateInput(attrs={'type': 'date'}),
            'date_cert_expiry': forms.DateInput(attrs={'type': 'date'}),
        }

# --- Scoped Item Form ---
# Including the refinements from the previous step for completeness

class ScopedItemForm(forms.ModelForm):
    number_to_add = forms.IntegerField(
        min_value=1, initial=1, required=True, label="Number to Add",
        help_text="How many identical items with these details do you want to add?",
        widget=forms.NumberInput(attrs={'class': 'form-control', 'style': 'max-width: 100px;'})
    )
    network = forms.ModelChoiceField(
        queryset=Network.objects.none(), required=False, label="Associated Network",
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta:
        model = ScopedItem
        exclude = ['assessment', 'is_in_ce_plus_sample'] # Exclude fields set in view or by assessor
        labels = { # Define labels for clarity
            'item_type': 'Item Type*',
            'operating_system': 'Operating System / Version',
            'identifier': 'Identifier (Hostname/Asset Tag)',
            'make_model': 'Make & Model',
            'role_function': 'Purpose / User Role',
            'owner': 'Ownership',
            'network': 'Associated Network (Optional)',
        }
        help_texts = { # Add or refine help texts
             'item_type': 'Select the primary type of this item or group of items.',
             'operating_system': 'Required for Laptops, Desktops, Servers, Mobiles.',
             'identifier': 'Optional: A unique name or tag for this item (e.g., WKSTN-001, SRV-WEB-01). If adding multiple, leave blank or add later individually.',
             # ... other help texts ...
        }
        widgets = { # Ensure widgets are appropriate
            'role_function': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
            'item_type': forms.Select(attrs={'class': 'form-select'}),
            'identifier': forms.TextInput(attrs={'class': 'form-control'}),
            'operating_system': forms.Select(attrs={'class': 'form-select'}), # Needs JS for filtering
            'make_model': forms.TextInput(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control'}),
            'owner': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        assessment_instance = kwargs.pop('assessment', None)
        super().__init__(*args, **kwargs)
        if assessment_instance:
            self.fields['network'].queryset = Network.objects.filter(assessment=assessment_instance).order_by('name')
        else:
            self.fields['network'].queryset = Network.objects.none()
        # Future: Could filter OS here initially if editing an existing item
        # or based on a passed 'initial_item_type' if desired.

    # --- NEW/UPDATED clean method ---
    def clean(self):
        cleaned_data = super().clean()
        item_type = cleaned_data.get("item_type")
        operating_system = cleaned_data.get("operating_system")

        # --- OS Required Validation ---
        required_os_types = ['Laptop', 'Desktop', 'Server', 'Mobile']
        optional_os_types = ['Firewall', 'Router', 'Switch', 'Other'] # Types where OS *might* be relevant but isn't strictly needed from our list
        no_os_types = ['IP', 'SaaS', 'PaaS', 'IaaS'] # Types that don't use an OS from our list

        if item_type in required_os_types and not operating_system:
             self.add_error('operating_system', f"Operating System selection is required for item type '{item_type}'.")
        elif item_type in no_os_types and operating_system:
             self.add_error('operating_system', f"Operating System should not be selected for item type '{item_type}'. Please clear the selection.")

        # --- OS Category Validation (only if an OS is selected) ---
        if operating_system:
            # Define mapping from ScopedItem.item_type to expected OperatingSystem.category
            type_to_os_category = {
                'Laptop': ['Desktop'], # Laptops use Desktop OS
                'Desktop': ['Desktop'],
                'Server': ['Server'],
                'Mobile': ['Mobile'],
                'Firewall': ['Other'],   # Firewalls might have specific OS categorized as 'Other'
                'Router': ['Other'],     # Routers might have specific OS categorized as 'Other'
                'Switch': ['Other'],     # Switches might have specific OS categorized as 'Other'
                'Other': ['Desktop', 'Server', 'Mobile', 'Other'], # Allow any for 'Other' scope item type
                # Types in no_os_types are handled above
            }

            expected_categories = type_to_os_category.get(item_type) # Might be None if type not in map (e.g., IP, SaaS)

            if expected_categories is not None: # Check only if OS is expected for this type
                if not operating_system.category:
                    # Warn but allow if the selected OS itself is missing a category in the DB
                    # You could raise an error instead:
                    # self.add_error('operating_system', f"Category is not set for the selected OS '{operating_system}'. Please ask an Admin/Assessor to categorize it.")
                    pass # For now, allow OS records that haven't been categorized yet
                elif operating_system.category not in expected_categories:
                     allowed_cats_str = ", ".join(expected_categories)
                     # Use get_FIELD_display() for choice fields
                     os_cat_display = operating_system.get_category_display()
                     self.add_error('operating_system', f"OS '{operating_system}' (Category: {os_cat_display}) is not valid for item type '{item_type}'. Expected category: {allowed_cats_str}.")

        # --- Clear irrelevant fields based on type (Optional but good practice) ---
        fields_to_clear = {}
        # Example: Clear OS, Make/Model, Owner for Cloud/IP types
        if item_type in ['IP', 'SaaS', 'PaaS', 'IaaS']:
            fields_to_clear.update({'operating_system': None, 'make_model': '', 'owner': ''})
        # Example: Clear 'owner' unless it's an end-user device
        if item_type not in ['Laptop', 'Desktop', 'Mobile']:
             fields_to_clear['owner'] = ''

        for field_name, clear_value in fields_to_clear.items():
            # Check if field exists in form and its value needs clearing
            if field_name in cleaned_data and cleaned_data[field_name] is not None and cleaned_data[field_name] != '':
                # print(f"Clearing field '{field_name}' for item_type '{item_type}'") # Debug print
                cleaned_data[field_name] = clear_value
                # Clear the field in the form instance as well if needed, although usually
                # saving the cleaned_data is sufficient.
                field_instance = self.fields.get(field_name)
                if field_instance:
                    # Attempt to set initial might work for display on re-render,
                    # but clearing cleaned_data is key for saving.
                    # field_instance.initial = clear_value
                    pass


        return cleaned_data


# --- END Scoped Item Form ---

class ScopedItemUpdateForm(ScopedItemForm): # Inherit from the base form
    class Meta(ScopedItemForm.Meta): # Inherit Meta too
         pass # Keep same model and exclude fields

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the 'number_to_add' field as it's not needed for updating
        if 'number_to_add' in self.fields:
            del self.fields['number_to_add']

# --- Evidence Form ---

class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ['file', 'description']
        widgets = {
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'description': forms.TextInput(attrs={'placeholder': 'E.g., Final Report PDF, Certificate PNG', 'class': 'form-control'}),
        }

class OperatingSystemForm(forms.ModelForm):
    class Meta:
        model = OperatingSystem
        fields = [
            'name', 'version', 'vendor', 'vendor_website',
            'end_of_life_date', 'is_supported', 'notes'
        ]
        widgets = {
            'end_of_life_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'version': forms.TextInput(attrs={'class': 'form-control'}),
            'vendor': forms.TextInput(attrs={'class': 'form-control'}),
            'vendor_website': forms.URLInput(attrs={'class': 'form-control'}),
            'is_supported': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }
        labels = {
            'end_of_life_date': 'End of Life / Support Date',
            'is_supported': 'Currently Supported?',
        }


class NetworkForm(forms.ModelForm):
    class Meta:
        model = Network
        exclude = ['assessment', 'created_at', 'updated_at']
        labels = {
            'ip_range': 'IP Range / Subnet',
            'vlan_id': 'VLAN ID (Optional)',
        }
        help_texts = {
            'name': "A descriptive name for the network (e.g., 'Office LAN', 'DMZ').",
            'ip_range': "Enter a valid IPv4 or IPv6 network address with CIDR prefix (e.g., 192.168.1.0/24) or a single IP (e.g., 10.0.0.1). Leave blank if not applicable.",
        }
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
            'ip_range': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., 192.168.1.0/24'}),
            'vlan_id': forms.NumberInput(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
        }

    # --- NEW: Validation method for ip_range ---
    def clean_ip_range(self):
        ip_range_value = self.cleaned_data.get('ip_range')

        # Allow blank values
        if not ip_range_value:
            return ip_range_value # Return None or empty string

        try:
            # Use ipaddress.ip_network to validate.
            # strict=False allows single IPs (parsed as /32 or /128 networks)
            # and doesn't require the host bits to be zero.
            ipaddress.ip_network(ip_range_value, strict=False)
            # Return the original string value if valid
            return ip_range_value
        except ValueError:
            # Raise validation error if parsing fails
            raise ValidationError(
                "Invalid IP network format. Please use CIDR notation (e.g., 192.168.1.0/24, 2001:db8::/32) or a single valid IP address.",
                code='invalid_ip_network'
            )


class CloudServiceDefinitionForm(forms.ModelForm):
    class Meta:
        model = CloudServiceDefinition
        # Exclude fields set automatically or requiring specific permissions
        exclude = ['created_by', 'approved_by', 'created_at', 'updated_at']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'vendor': forms.TextInput(attrs={'class': 'form-control'}),
            'service_url': forms.URLInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'requires_mfa_for_ce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_globally_approved': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
        help_texts = {
            'is_globally_approved': "Check this box to make this service available for selection by all clients.",
            'requires_mfa_for_ce': "Should MFA be enforced for this service according to Cyber Essentials rules?",
        }
# --- END NEW ---


# --- NEW: Assessment Cloud Service Form (Initial version for Client/Assessor) ---
class AssessmentCloudServiceForm(forms.ModelForm):
    # --- Make existing field not required ---
    cloud_service_definition = forms.ModelChoiceField(
        queryset=CloudServiceDefinition.objects.filter(is_globally_approved=True),
        label="Select Existing Approved Service", # Changed label
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False, # <--- NOT required initially
        help_text="Select a service if it's already approved and listed."
    )

    # --- Add fields for suggesting a NEW service ---
    add_new_service = forms.BooleanField(
        label="Or, suggest a new service not on the list",
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input', 'id': 'id_add_new_service_toggle'})
    )
    new_service_name = forms.CharField(
        label="New Service Name",
        max_length=200,
        required=False, # Required only if add_new_service is checked (handled in clean)
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    new_service_vendor = forms.CharField(
        label="Vendor (Optional)",
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    new_service_url = forms.URLField(
        label="Service Login/Info URL (Optional)",
        max_length=255,
        required=False,
        widget=forms.URLInput(attrs={'class': 'form-control'})
    )
    new_service_description = forms.CharField(
        label="Description (Optional)",
        required=False,
        widget=forms.Textarea(attrs={'rows': 2, 'class': 'form-control'})
    )
    # Client suggests if MFA is likely required based on CE rules
    new_service_requires_mfa = forms.BooleanField(
        label="Does this service likely require MFA for CE compliance?",
        required=False, # Important: Make this False initially
        initial=True, # Default to True as most services do
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        help_text="e.g., Accesses organisational data or requires login."
    )
    # --- End new service fields ---


    def __init__(self, *args, **kwargs):
        self.assessment = kwargs.pop('assessment', None)
        super().__init__(*args, **kwargs)
        if not self.assessment and not self.instance.pk:
             raise ValueError("Assessment instance must be provided to AssessmentCloudServiceForm on create.")

    class Meta:
        model = AssessmentCloudService
        # Only include fields directly related to the AssessmentCloudService instance itself
        # cloud_service_definition is handled above. New service fields are separate form fields.
        fields = [
            # 'cloud_service_definition', # Handled above
            'client_notes',
            'mfa_admin_proof',
            'mfa_user_proof',
        ]
        widgets = {
            'client_notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'mfa_admin_proof': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'mfa_user_proof': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }
        labels = {
            'mfa_admin_proof': "Admin MFA Proof (Screenshot/File)",
            'mfa_user_proof': "User MFA Proof (Screenshot/File)",
        }
        help_texts = {
            'client_notes': "Add any notes about how this service is used (optional).",
            'mfa_admin_proof': "Upload evidence showing MFA enabled for an administrator account.",
            'mfa_user_proof': "Upload evidence showing MFA enabled for a standard user account.",
        }

    def clean(self):
        cleaned_data = super().clean()
        existing_service = cleaned_data.get('cloud_service_definition')
        add_new = cleaned_data.get('add_new_service')
        new_name = cleaned_data.get('new_service_name')

        if add_new:
            # Adding a new service suggestion
            if existing_service:
                self.add_error('cloud_service_definition', "Please clear this selection if suggesting a new service.")
            if not new_name:
                self.add_error('new_service_name', "Service Name is required when suggesting a new service.")
            # Check if a service with this name ALREADY exists (approved or not)
            elif CloudServiceDefinition.objects.filter(name__iexact=new_name).exists():
                 self.add_error('new_service_name', f"A cloud service definition with the name '{new_name}' already exists. Please select it from the list above if appropriate, or choose a slightly different name.")

        elif existing_service:
            # Using an existing service
            if new_name: # User shouldn't fill both
                 self.add_error('new_service_name', "Please clear the new service details if selecting an existing service.")
            # Check for duplicate AssessmentCloudService instance (moved from previous step)
            if self.assessment and not self.instance.pk: # Only on create
                if AssessmentCloudService.objects.filter(assessment=self.assessment, cloud_service_definition=existing_service).exists():
                    self.add_error('cloud_service_definition', f"The service '{existing_service.name}' has already been added to this assessment.")

        else:
            # Neither option chosen
            raise ValidationError("You must either select an existing service or provide details for a new service suggestion.", code='no_service_selected_or_added')

        return cleaned_data

class AssessmentCloudServiceAssessorForm(forms.ModelForm):
    class Meta:
        model = AssessmentCloudService
        # Include fields relevant for assessor verification
        fields = [
            # Client fields might be included as readonly or excluded
            # 'client_notes', # Maybe show read-only?
            'mfa_admin_verified',
            'mfa_user_verified',
            'is_compliant',
            'assessor_notes',
        ]
        widgets = {
            # Use checkboxes for boolean fields
            'mfa_admin_verified': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'mfa_user_verified': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_compliant': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'assessor_notes': forms.Textarea(attrs={'rows': 4, 'class': 'form-control'}),
            # Widget for client_notes if included as readonly
            # 'client_notes': forms.Textarea(attrs={'readonly': 'readonly', 'rows': 3, 'class': 'form-control-plaintext'}),
        }
        labels = {
            'mfa_admin_verified': "Admin MFA Verified by Assessor?",
            'mfa_user_verified': "User MFA Verified by Assessor?",
            'is_compliant': "Overall Service Compliant?",
            'assessor_notes': "Assessor Verification Notes",
        }

class ExternalIPForm(forms.ModelForm):
    """
    Form for Clients/Assessors to add/edit External IPs/Hostnames.
    Includes consent confirmation.
    """
    # Consent Checkbox (Not part of the model fields directly)
    confirm_consent = forms.BooleanField(
        required=True, # Make it mandatory to add/edit the IP/Hostname field
        label="Scan Permission Confirmation",
        help_text="By checking this box, I confirm that I have the necessary authority to grant permission for this IP address or hostname to be externally scanned as part of this Cyber Essentials assessment, and I explicitly provide that permission.",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    class Meta:
        model = ExternalIP
        # Exclude fields set automatically, managed by Assessors separately, or handled by the checkbox
        exclude = [
            'assessment',
            'scan_status',
            'assessor_notes',
            'added_at',
            'last_scanned_at',
            'consent_given',
            'consented_by',
            'consent_timestamp'
        ]
        labels = {
            'ip_address_or_hostname': 'IP Address or Hostname',
            'description': 'Description / Purpose',
        }
        widgets = {
            'ip_address_or_hostname': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., 8.8.8.8 or www.example.com'}),
            'description': forms.Textarea(attrs={'rows': 2, 'class': 'form-control'}),
        }

    # Keep the validation for the IP/Hostname format (uses validator on model)
    # Optional: Add validation to prevent private IPs
    def clean_ip_address_or_hostname(self):
        ip_or_host = self.cleaned_data.get('ip_address_or_hostname')
        if ip_or_host:
            try:
                # Check if it's an IP address first
                ip_addr = ipaddress.ip_address(ip_or_host)
                # Prevent private IPs if needed
                if ip_addr.is_private:
                    raise forms.ValidationError("Private IP addresses cannot be added as external scan targets.")
            except ValueError:
                # If it's not an IP, assume it's a hostname (model validator checks resolvability)
                pass
        return ip_or_host

# --- Optional: Form for Assessor Scan Updates ---
class ExternalIPScanUpdateForm(forms.ModelForm):
    """ Form specifically for Assessors to update scan status and notes """
    class Meta:
        model = ExternalIP
        fields = [
            'scan_status',
            'assessor_notes',
            # last_scanned_at is usually set automatically in the view
        ]
        widgets = {
            'scan_status': forms.Select(attrs={'class': 'form-select'}),
            'assessor_notes': forms.Textarea(attrs={'rows': 4, 'class': 'form-control'}),
        }
        labels = {
            'scan_status': 'Scan Status',
            'assessor_notes': 'Assessor Scan Notes / Remediation Details',
        }

class UploadReportForm(forms.ModelForm):
    # Optional: Add a field to link to an assessment during upload
    # assessment = forms.ModelChoiceField(
    #     queryset=Assessment.objects.all(), # Filter as needed (e.g., by client/assessor)
    #     required=False, # Or True if linking must happen on upload
    #     label="Link to Assessment (Optional)"
    # )

    class Meta:
        model = UploadedReport
        fields = ['report_file'] # Only include the file field for upload initially
        # If adding the assessment link field above, include it here:
        # fields = ['assessment', 'report_file']
        widgets = {
            'report_file': forms.ClearableFileInput(attrs={'class': 'form-control', 'accept': '.pdf'}),
        }
        labels = {
            'report_file': 'Select CE Report PDF to Upload',
        }