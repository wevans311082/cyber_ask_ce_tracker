import json

from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import User
# Ensure ValidationError is imported if needed, though forms.ValidationError works
# from django.core.exceptions import ValidationError
import ipaddress
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.exceptions import ValidationError
from .models import *


User = get_user_model()







class BrowserForm(forms.ModelForm):
    class Meta:
        model = Browser
        fields = ['name', 'version', 'release_date', 'release_notes', 'status', 'engine', 'engine_version']





class AssessmentInfoFormRefined(forms.ModelForm): # Or your exact form class name
    class Meta:
        model = Assessment
        fields = [ # Ensure this list contains at least one valid field from your Assessment model
            'scope_description',
            # 'ce_self_assessment_ref', # Keep a minimal valid field list for this test
        ]
        # You can comment out widgets for this minimal test if you suspect them

    def __init__(self, *args, **kwargs):
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! ENTERED AssessmentInfoFormRefined.__init__ IN tracker/forms.py !!!")
        print(f"!!! ARGS: {args}")
        print(f"!!! KWARGS: {kwargs}")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        # Pop user *after* printing kwargs if you want to see it in kwargs
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # For now, comment out ALL other logic in __init__ to isolate the print
        # self.fields.clear() # Example: if you want to force a blank form for testing this __init__ call
        print(f"--- Form fields after super init & any clearing: {list(self.fields.keys())} ---")




class AccountSettingsForm(forms.ModelForm):
    """
    Form for users to update their account settings.
    Handles fields from both the User model and UserProfile model.
    """
    # Fields from the User model
    first_name = forms.CharField(
        label=_("First Name"),
        max_length=150,
        required=False,  # Standard User model allows blank first_name
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=150,
        required=False,  # Standard User model allows blank last_name
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    email = forms.EmailField(
        label=_("Email Address"),
        required=True,  # Email is typically required
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )

    # Fields from the UserProfile model
    phone_number = forms.CharField(
        label=_("Phone Number"),
        max_length=20,
        required=False,  # As defined in the model (blank=True)
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': _('e.g., +44 7700 900000')})
    )
    mfa_enabled = forms.BooleanField(
        label=_("Enable Multi-Factor Authentication"),
        required=False,  # CheckboxInput handles boolean
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    class Meta:
        # We specify UserProfile here because it's the "primary" model for this form
        # in terms of unique fields we added. We'll handle User model fields manually.
        # However, since we are not directly using ModelForm's automatic field generation
        # for User fields, the 'model' and 'fields' in Meta are more for UserProfile.
        model = UserProfile
        fields = ['phone_number', 'mfa_enabled']  # Only UserProfile specific fields listed here

    def __init__(self, *args, **kwargs):
        """
        Initialize the form with instance data for both User and UserProfile.
        The 'instance' kwarg here is expected to be the UserProfile instance.
        """
        self.user_instance = kwargs.pop('user_instance', None)  # Pop user_instance if passed
        super().__init__(*args, **kwargs)

        if self.user_instance:
            # Populate User model fields
            self.fields['first_name'].initial = self.user_instance.first_name
            self.fields['last_name'].initial = self.user_instance.last_name
            self.fields['email'].initial = self.user_instance.email

        # If UserProfile instance is provided (self.instance), ModelForm handles its fields.
        # If not (e.g., creating a new UserProfile for a user who doesn't have one),
        # initial values for phone_number and mfa_enabled will be blank/default.

    def clean_email(self):
        """
        Validate that the email is unique, excluding the current user's email.
        """
        email = self.cleaned_data.get('email')
        if self.user_instance and User.objects.filter(email=email).exclude(pk=self.user_instance.pk).exists():
            raise forms.ValidationError(_("This email address is already in use by another account."))
        return email

    def save(self, commit=True):
        """
        Save the form data to both User and UserProfile models.
        """
        # The UserProfile instance is self.instance (from ModelForm)
        profile = super().save(commit=False)  # Save UserProfile fields

        if self.user_instance:
            # Update User model fields
            self.user_instance.first_name = self.cleaned_data.get('first_name', self.user_instance.first_name)
            self.user_instance.last_name = self.cleaned_data.get('last_name', self.user_instance.last_name)
            self.user_instance.email = self.cleaned_data.get('email', self.user_instance.email)

            if commit:
                self.user_instance.save()

        # Ensure the profile is linked to the user_instance if it's a new profile
        # (though for an account settings page, profile should always exist)
        if hasattr(profile, 'user') and not profile.user and self.user_instance:
            profile.user = self.user_instance

        if commit:
            profile.save()

        return profile

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

# --- NEW Assessment Date Option Form ---
class AssessmentDateOptionForm(forms.ModelForm):
    # Keep your existing DateInput widget and other field definitions
    proposed_date = forms.DateField(
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'form-control',
                'min': timezone.now().strftime('%Y-%m-%d')  # Example: min date today
            }
        ),
        help_text=_("Select a date for the assessment.")
    )

    class Meta:
        model = AssessmentDateOption
        fields = ['proposed_date', 'notes']
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        # Pop custom kwargs before calling super().__init__()
        self.assessment = kwargs.pop('assessment', None)
        self.user = kwargs.pop('user', None)  # Accept and pop the 'user' kwarg

        super().__init__(*args, **kwargs)

        if not self.assessment:
            # This should ideally not happen if the form is always instantiated with an assessment
            # but it's a good safeguard.
            self.fields['proposed_date'].disabled = True
            self.add_error(None, _("Assessment context is missing for this form."))
            return

        # Set min_date dynamically based on today or CE+ pass date
        min_date_val = timezone.now().date()
        if self.assessment.assessment_type == 'CE+' and self.assessment.date_ce_passed:
            # For CE+, proposed date cannot be before the CE pass date.
            min_date_val = max(min_date_val, self.assessment.date_ce_passed)

        self.fields['proposed_date'].widget.attrs['min'] = min_date_val.strftime('%Y-%m-%d')

        # Disable dates if the assessor has marked them as unavailable (if assessor is known)
        # This part is more for display/client-side validation; server-side validation is still key.
        unavailable_dates_str = []
        if self.assessment.assessor:
            unavailable_dates = AssessorAvailability.objects.filter(
                assessor=self.assessment.assessor
            ).values_list('unavailable_date', flat=True)
            unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]

        # This data attribute can be used by a JavaScript date picker to disable dates
        self.fields['proposed_date'].widget.attrs['data-unavailable-dates'] = json.dumps(unavailable_dates_str)

    def clean_proposed_date(self):
        proposed_date = self.cleaned_data.get('proposed_date')
        today = timezone.now().date()

        if not proposed_date:  # Should be caught by field 'required' but good to check
            raise ValidationError(_("Proposed date is required."))

        if proposed_date < today:
            raise ValidationError(_("Proposed date cannot be in the past."))

        if self.assessment:  # Ensure assessment context is available
            if self.assessment.assessment_type == 'CE+':
                if self.assessment.date_ce_passed:
                    if proposed_date < self.assessment.date_ce_passed:
                        raise ValidationError(
                            _("For CE+ assessments, the proposed date cannot be before the CE Self-Assessment pass date (%(ce_pass_date)s).") % {
                                'ce_pass_date': self.assessment.date_ce_passed.strftime('%Y-%m-%d')}
                        )

                    # Check against 90-day window end date
                    ce_plus_deadline = self.assessment.ce_plus_window_end_date
                    if ce_plus_deadline and proposed_date > ce_plus_deadline:
                        raise ValidationError(
                            _("For CE+, proposed date must be within 90 days of CE pass date (by %(deadline)s).") % {
                                'deadline': ce_plus_deadline.strftime('%Y-%m-%d')}
                        )
                else:

                    pass

                    # Check if assessor is unavailable on the proposed date
            if self.assessment.assessor:
                if AssessorAvailability.objects.filter(assessor=self.assessment.assessor,
                                                       unavailable_date=proposed_date).exists():
                    raise ValidationError(
                        _("The assigned assessor is unavailable on %(date)s. Please choose another date.") % {
                            'date': proposed_date.strftime('%Y-%m-%d')}
                    )

        # Check if this exact date has already been proposed for this assessment
        # (unique_together on model handles DB level, this gives cleaner form error)
        # Exclude self if instance is being updated
        # query = AssessmentDateOption.objects.filter(assessment=self.assessment, proposed_date=proposed_date)
        # if self.instance and self.instance.pk:
        #     query = query.exclude(pk=self.instance.pk)
        # if query.exists():
        #     raise ValidationError(_("This date has already been proposed for this assessment."))

        return proposed_date

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.assessment:
            instance.assessment = self.assessment
        if self.user and not instance.pk:  # Set proposed_by only on creation and if user is provided
            instance.proposed_by = self.user

        # Default status if not already set (though model has default)
        if not instance.status:
            instance.status = AssessmentDateOption.Status.SUGGESTED

        if commit:
            instance.save()
        return instance

# --- NEW Assessor Availability Form ---
class AssessorAvailabilityForm(forms.ModelForm):
    unavailable_date = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        label="Block Out Date"
    )

    class Meta:
        model = AssessorAvailability
        fields = ['unavailable_date', 'reason']
        widgets = {
            'reason': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional: e.g., Holiday, Conference'})
        }

    def clean_unavailable_date(self):
        """Ensure the date is not in the past."""
        date_to_block = self.cleaned_data.get('unavailable_date')
        today = timezone.now().date()
        if date_to_block and date_to_block < today:
            raise ValidationError("Cannot block out a date in the past.")
        # Note: unique_together check ('assessor', 'unavailable_date') is handled by Django
        return date_to_block


class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['content']
        widgets = {
            'content': forms.Textarea(
                attrs={
                    'class': 'form-control',  # Standard Bootstrap class
                    'rows': 3,
                    'placeholder': _('Type your message...'),  # Make placeholder translatable
                    'aria-label': _('Message content')  # For accessibility
                }
            )
        }
        labels = {
            'content': ''  # Hide the label, placeholder is used
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['content'].required = True


class AssessmentInfoForm(forms.ModelForm):
    class Meta:
        model = Assessment
        # These fields will be dynamically set in __init__ based on user role
        fields = []

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)  # Get the user passed from the view
        assessment = kwargs.get('instance', None)  # Get the assessment instance

        super().__init__(*args, **kwargs)

        # Define fields that are generally editable
        common_fields = [
            'scope_description',
            'ce_self_assessment_ref',
            'primary_contact_name',
            'primary_contact_email',
            'primary_contact_phone',
        ]

        assessor_admin_fields = [
            # Add fields only assessors/admins can edit from this card, e.g.:
            # 'scheduled_date',
            # 'date_target_end',
            # 'status', # Be careful with status changes, might need separate workflow
            # 'final_outcome',
            # 'assessor', # Assigning an assessor
            # Ensure these fields exist on your Assessment model
        ]

        # Determine which fields to show based on user role
        # This assumes user.userprofile.role exists
        profile = getattr(user, 'userprofile', None)

        if profile and profile.role in ['Assessor', 'Admin']:
            self.Meta.fields = common_fields + assessor_admin_fields
        elif profile and profile.role == 'Client' and assessment and profile.client == assessment.client:
            self.Meta.fields = common_fields
        else:
            # No fields if user has no permission or role, or form is misused
            # Or raise an error, or only show read-only if that's a state.
            # For now, an empty field list means no fields will be rendered by {{ form }}.
            self.Meta.fields = []

        # Apply widget attributes for Bootstrap styling (optional, but good for consistency)
        for field_name in self.fields:
            field = self.fields[field_name]
            # Add a general class for styling
            current_class = field.widget.attrs.get('class', '')
            field.widget.attrs['class'] = f'{current_class} form-control form-control-sm'.strip()

            if isinstance(field.widget, forms.Textarea):
                field.widget.attrs['rows'] = 3
            if isinstance(field.widget, forms.DateInput):
                field.widget.attrs['type'] = 'date'  # Ensure HTML5 date picker
            # Add more specific widget customizations if needed
            # Example: field.widget.attrs['placeholder'] = _('Enter details...')

        # Ensure all specified fields actually exist on the Assessment model
        # This helps catch errors if model fields change.
        model_field_names = [f.name for f in Assessment._meta.get_fields()]
        valid_fields = [f for f in self.Meta.fields if f in model_field_names]
        self.Meta.fields = valid_fields

        # Re-initialize fields with the final list
        # This is important because self.fields is populated based on Meta.fields at super().__init__
        # If Meta.fields is changed after super().__init__, self.fields might not reflect it
        # unless we re-initialize or directly manipulate self.fields.
        # A cleaner way is to determine Meta.fields *before* super().__init__ if possible,
        # or to explicitly define all possible fields in Meta.fields and then remove unwanted ones from self.fields.

        # Let's refine: define all possible fields in Meta and remove unwanted ones.
        # This is generally safer with ModelForms.






# Refined Form (Alternative __init__ approach):
class AssessmentInfoFormRefined44(forms.ModelForm):  # Or your exact form class name
    class Meta:
        model = Assessment
        fields = [  # Keep this as it was, with correct fields
            'scope_description', 'ce_self_assessment_ref',
            'primary_contact_name', 'primary_contact_email', 'primary_contact_phone',
            'date_start',
            'date_target_end',
            'date_actual_end',
            'date_ce_passed',
            'date_cert_issued',
            'date_cert_expiry',
        ]
        # Keep widgets as they were
        widgets = {
            'scope_description': forms.Textarea(attrs={'rows': 3}),
            'date_start': forms.DateInput(attrs={'type': 'date'}),
            'date_target_end': forms.DateInput(attrs={'type': 'date'}),
            'date_actual_end': forms.DateInput(attrs={'type': 'date'}),
            'date_ce_passed': forms.DateInput(attrs={'type': 'date'}),
            'date_cert_issued': forms.DateInput(attrs={'type': 'date'}),
            'date_cert_expiry': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        # --- TEMPORARY SUPER SIMPLE DEBUG ---
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! ASSESSMENT INFO FORM __INIT__ WAS DEFINITELY CALLED !!!")
        print(
            f"!!! User passed to form: {kwargs.get('user', 'User kwarg not found')} !!!")  # Note: user was popped before super
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        user_arg = kwargs.pop('user', None)  # Pop user here for super()
        super().__init__(*args, **kwargs)  # Call super AFTER the print for this test

        # For this test, comment out ALL other logic in __init__
        # to ensure nothing else interferes or raises an error before prints.

        # client_editable_fields = [
        #     'scope_description',
        #     # ...
        # ]
        # profile = getattr(user_arg, 'userprofile', None)
        # # ... (all your field filtering logic commented out for now) ...

        # print(f"FINAL self.fields after (disabled) filtering: {list(self.fields.keys())}")

        # Just to make sure form has some fields for rendering if __init__ is called
        if not self.fields:
            print("!!! WARNING: self.fields is empty even after commenting out filtering. Check Meta.fields.")

        # Apply widget attributes for Bootstrap styling
        for field_name, field in self.fields.items():
            current_class = field.widget.attrs.get('class', '')
            new_classes = 'form-control form-control-sm'
            field.widget.attrs['class'] = f'{current_class} {new_classes}'.strip()
            if isinstance(field.widget, forms.Textarea):
                field.widget.attrs['rows'] = 3
            if isinstance(field.widget, forms.DateInput) and 'type' not in field.widget.attrs:
                field.widget.attrs['type'] = 'date'
            if not field.required:
                field.label_suffix = mark_safe(
                    f'{field.label_suffix or ""} <span class="text-muted small">({_("optional")})</span>')



class AssessmentPersonnelForm(forms.ModelForm):
    class Meta:
        model = AssessmentPersonnel
        fields = [
            'full_name',
            'email',
            'phone_number',
            'mobile_number',
            'department',
            'role_in_assessment',
            'notes',
            # 'assessment' will be set in the view based on context.
            # 'added_by' will be set in the view to the current user.
        ]
        widgets = {
            'full_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'mobile_number': forms.TextInput(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'role_in_assessment': forms.TextInput(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }
        help_texts = {
            'full_name': _('Full name of the contact person.'),
            'email': _('Email address (optional).'),
            'phone_number': _('Primary contact phone number (optional).'),
            'mobile_number': _('Mobile phone number (optional).'),
            'department': _('Department or team they belong to (optional).'),
            'role_in_assessment': _('Their specific role or responsibility for this assessment (e.g., "Server Admin for SRV01", "Main Point of Contact").'),
            'notes': _('Any additional relevant notes about this contact (optional).'),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make fields not explicitly required by the model also not required in the form
        # if they are blank=True on the model. Model fields handle this by default,
        # but this is an explicit way if needed for further customization.
        self.fields['email'].required = False
        self.fields['phone_number'].required = False
        self.fields['mobile_number'].required = False
        self.fields['department'].required = False
        self.fields['notes'].required = False



class PersonnelCloudServiceAccessForm(forms.ModelForm):
    class Meta:
        model = PersonnelCloudServiceAccess
        fields = [
            'personnel',
            'assessment_cloud_service',
            'access_level',
            'is_admin_access',
            'mfa_enabled_for_personnel',
            'personnel_mfa_proof', # Added new field
            'notes',
            # 'recorded_by' will be set in the view.
        ]
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}), # Added form-control
            'personnel': forms.Select(attrs={'class': 'form-select'}),
            'assessment_cloud_service': forms.Select(attrs={'class': 'form-select'}),
            'access_level': forms.TextInput(attrs={'class': 'form-control'}),
            'is_admin_access': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'mfa_enabled_for_personnel': forms.Select(
                choices=[('', _('Unknown')), (True, _('Yes')), (False, _('No'))],
                attrs={'class': 'form-select'}
            ),
            'personnel_mfa_proof': forms.ClearableFileInput(attrs={'class': 'form-control'}), # Added widget for styling
        }
        help_texts = {
            'personnel': _("The contact person from this assessment."),
            'assessment_cloud_service': _("The specific cloud service within this assessment."),
            'access_level': _("Describe the person's role or permission level (e.g., 'Global Admin', 'Standard User')."),
            'is_admin_access': _("Does this person have administrative rights on this service?"),
            'mfa_enabled_for_personnel': _("Is MFA confirmed as enabled for this person on this service?"),
            'personnel_mfa_proof': _("Optional: Screenshot or file proving MFA is active for this person on this service. Current file will be shown if one exists."),
            'notes': _("Any verification details, specific permission notes, or MFA observations."),
        }

    def __init__(self, *args, **kwargs):
        assessment_pk = kwargs.pop('assessment_pk', None)
        personnel_pk = kwargs.pop('personnel_pk', None)

        super().__init__(*args, **kwargs)

        if assessment_pk:
            try:
                assessment = Assessment.objects.get(pk=assessment_pk)
                self.fields['assessment_cloud_service'].queryset = AssessmentCloudService.objects.filter(
                    assessment=assessment
                ).select_related('cloud_service_definition')
                self.fields['personnel'].queryset = AssessmentPersonnel.objects.filter(
                    assessment=assessment
                )
            except Assessment.DoesNotExist: # Handle case where assessment_pk is invalid
                self.fields['assessment_cloud_service'].queryset = AssessmentCloudService.objects.none()
                self.fields['personnel'].queryset = AssessmentPersonnel.objects.none()

        else:
            self.fields['assessment_cloud_service'].queryset = AssessmentCloudService.objects.none()
            self.fields['personnel'].queryset = AssessmentPersonnel.objects.none()

        if personnel_pk and assessment_pk: # Ensure assessment_pk is also present for safety
            try:
                personnel_instance = AssessmentPersonnel.objects.get(pk=personnel_pk, assessment_id=assessment_pk)
                self.fields['personnel'].initial = personnel_instance
                self.fields['personnel'].disabled = True
            except AssessmentPersonnel.DoesNotExist:
                pass # Or raise an error if personnel_pk must be valid

        # Ensure all fields have appropriate Bootstrap classes if not specified above
        # CheckboxInput and ClearableFileInput might need specific handling by your CSS
        # or you might rely on Bootstrap's default rendering for them when they have 'form-control'.
        # For file inputs, 'form-control' helps with sizing and appearance.
        # For checkboxes, 'form-check-input' is standard.


class PersonnelSecurityTestForm(forms.ModelForm):
    class Meta:
        model = PersonnelSecurityTest
        fields = [
            'assessment_personnel', # Will likely be pre-set and disabled in the view
            'scoped_item',
            'test_type',
            'test_description',
            'test_date',
            'outcome',
            'malware_sample_name',
            'notes',
            'evidence',
            # 'recorded_by' will be set in the view.
        ]
        widgets = {
            'assessment_personnel': forms.Select(attrs={'class': 'form-select'}),
            'scoped_item': forms.Select(attrs={'class': 'form-select'}),
            'test_type': forms.Select(attrs={'class': 'form-select'}),
            'test_description': forms.TextInput(attrs={'class': 'form-control'}),
            'test_date': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'outcome': forms.Select(attrs={'class': 'form-select'}),
            'malware_sample_name': forms.TextInput(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'evidence': forms.Select(attrs={'class': 'form-select'}), # ForeignKey to Evidence model
        }
        help_texts = {
            'assessment_personnel': _("The personnel contact involved in this test."),
            'scoped_item': _("Optional: The specific scoped device involved in the test."),
            'test_type': _("Select the type of security test performed."),
            'test_description': _("Brief description or scenario of the test (e.g., 'EICAR.zip via email to user')."),
            'test_date': _("Date and time the test was conducted."),
            'outcome': _("Select the outcome of the test."),
            'malware_sample_name': _("Name or identifier of the malware sample used (e.g., 'EICAR test file')."),
            'notes': _("Detailed observations, user actions, system responses, etc."),
            'evidence': _("Optional: Link to existing uploaded evidence supporting the test outcome."),
        }

    def __init__(self, *args, **kwargs):
        assessment_pk = kwargs.pop('assessment_pk', None)
        personnel_pk = kwargs.pop('personnel_pk', None)
        super().__init__(*args, **kwargs)

        if assessment_pk:
            try:
                assessment = Assessment.objects.get(pk=assessment_pk)
                # Filter ScopedItem choices to those belonging to the current assessment
                self.fields['scoped_item'].queryset = ScopedItem.objects.filter(
                    assessment=assessment
                )
                # Filter Evidence choices to those belonging to the current assessment
                # This assumes Evidence model has an 'assessment' ForeignKey.
                # From tracker/models.py, Evidence.assessment is a ForeignKey to Assessment.
                self.fields['evidence'].queryset = Evidence.objects.filter(
                    assessment=assessment
                ).order_by('-uploaded_at')

                # Filter personnel to only those belonging to this assessment for safety,
                # though it will be pre-set by personnel_pk.
                self.fields['assessment_personnel'].queryset = AssessmentPersonnel.objects.filter(
                    assessment=assessment
                )
            except Assessment.DoesNotExist:
                self.fields['scoped_item'].queryset = ScopedItem.objects.none()
                self.fields['evidence'].queryset = Evidence.objects.none()
                self.fields['assessment_personnel'].queryset = AssessmentPersonnel.objects.none()
        else:
            # No assessment_pk, so no relevant choices.
            self.fields['scoped_item'].queryset = ScopedItem.objects.none()
            self.fields['evidence'].queryset = Evidence.objects.none()
            self.fields['assessment_personnel'].queryset = AssessmentPersonnel.objects.none()

        if personnel_pk and assessment_pk:
            try:
                personnel_instance = AssessmentPersonnel.objects.get(pk=personnel_pk, assessment_id=assessment_pk)
                self.fields['assessment_personnel'].initial = personnel_instance
                self.fields['assessment_personnel'].disabled = True # Disable as it's context-set
            except AssessmentPersonnel.DoesNotExist:
                pass # Or handle error if personnel_pk must be valid
