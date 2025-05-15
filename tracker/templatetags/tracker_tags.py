# File: tracker/templatetags/tracker_tags.py
# CHANGES BEGIN - Added JSON filters and ensured imports
import json
import os
from datetime import timezone

from django import template
from django.db.models import Q, QuerySet
from django.forms.models import model_to_dict # For jsonify_model
from typing import Dict, Any, List, Optional
from ..models import AssessmentWorkflowStep, WorkflowStepDefinition, NessusAgentURL, OperatingSystem
# Assuming your models are in tracker.models
# Adjust the import path if your models are located elsewhere.
try:
    from tracker.models import Assessment, WorkflowStepDefinition, AssessmentWorkflowStep
except ImportError:
    print("[WARN] tracker.models could not be imported directly in tracker_tags.py.")
    Assessment = None
    WorkflowStepDefinition = None
    AssessmentWorkflowStep = None

register = template.Library()

@register.simple_tag(takes_context=True)
def get_workflow_steps_for_assessment(context, assessment: Assessment) -> Dict[str, Any]:
    """
    Prepares a context dictionary with all workflow step definitions
    and the current assessment's actual steps mapped to them.
    """
    if not Assessment or not WorkflowStepDefinition or not AssessmentWorkflowStep:
        print("[ERROR] Models not available in get_workflow_steps_for_assessment.")
        return {'all_definitions': [], 'steps_map': {}, 'current_definition': None, 'current_assessment_step': None}

    # Get all step definitions, ordered by 'step_order'.
    # Ensure 'assessment_type' field exists on WorkflowStepDefinition if filtering is needed.
    all_definitions = WorkflowStepDefinition.objects.all().order_by('step_order')
    # If filtering by type is needed and model field exists:
    # all_definitions = WorkflowStepDefinition.objects.filter(
    #     Q(assessment_type=assessment.assessment_type) | Q(assessment_type__isnull=True)
    # ).order_by('step_order')

    assessment_steps_qs = AssessmentWorkflowStep.objects.filter(assessment=assessment).select_related('step_definition')
    steps_map: Dict[int, AssessmentWorkflowStep] = {step.step_definition_id: step for step in assessment_steps_qs}

    current_assessment_step: Optional[AssessmentWorkflowStep] = None
    current_definition: Optional[WorkflowStepDefinition] = None

    # Determine current step
    for step_def in all_definitions:
        associated_assessment_step = steps_map.get(step_def.id)
        if associated_assessment_step:
            # Ensure Status enum/choices are correctly referenced
            if associated_assessment_step.status not in [AssessmentWorkflowStep.Status.COMPLETE, AssessmentWorkflowStep.Status.SKIPPED]:
                current_assessment_step = associated_assessment_step
                current_definition = step_def
                break
        else:
            current_definition = step_def
            break

    if not current_definition and all_definitions.exists():
        last_completed_or_skipped_def = None
        last_completed_or_skipped_step = None
        for step_def in reversed(all_definitions):
            associated_assessment_step = steps_map.get(step_def.id)
            if associated_assessment_step and associated_assessment_step.status in [AssessmentWorkflowStep.Status.COMPLETE, AssessmentWorkflowStep.Status.SKIPPED]:
                last_completed_or_skipped_def = step_def
                last_completed_or_skipped_step = associated_assessment_step
                break
        if last_completed_or_skipped_def:
            current_definition = last_completed_or_skipped_def
            current_assessment_step = last_completed_or_skipped_step
        elif all_definitions:
            current_definition = all_definitions.first()
            current_assessment_step = steps_map.get(current_definition.id)

    return {
        'all_definitions': all_definitions,
        'steps_map': steps_map,
        'current_definition': current_definition,
        'current_assessment_step': current_assessment_step,
    }

@register.filter(name='filename_only')
def filename_only(value):
    """
    Returns the base name of a filepath string.
    e.g., 'uploads/file.pdf' -> 'file.pdf'
    """
    if hasattr(value, 'name'): # Handles Django FileField
        return os.path.basename(value.name)
    if isinstance(value, str):
        return os.path.basename(value)
    return value


@register.filter
def get_item(dictionary: Optional[Dict[Any, Any]], key: Any) -> Any:
    """Access dictionary items safely."""
    if dictionary is None:
        return None
    return dictionary.get(key)


@register.filter
def filter_steps_by_definition(workflow_steps: Optional[List[AssessmentWorkflowStep]], definition_id: int) -> List[AssessmentWorkflowStep]:
    """Filters AssessmentWorkflowStep list by step_definition_id."""
    if not workflow_steps:
        return []
    return [step for step in workflow_steps if hasattr(step, 'step_definition_id') and step.step_definition_id == definition_id]


# --- JSON Serialization Filters ---

@register.filter(is_safe=True)
def jsonify_queryset(queryset):
    """
    Serializes a queryset to a JSON string list of dictionaries.
    Only includes specific fields needed by the JavaScript.
    """
    if isinstance(queryset, QuerySet):
        # Define the fields you absolutely need in the JS context object
        fields_needed = ['id', 'step_order', 'name', 'description', 'default_assigned_to']
        try:
            # Use values() for efficiency and safety
            data_list = list(queryset.values(*fields_needed))
            # Rename 'id' to 'pk' to match JS expectations if needed (JS uses .pk often)
            for item in data_list:
                item['pk'] = item.pop('id')
            return json.dumps(data_list)
        except Exception as e:
            print(f"[ERROR] jsonify_queryset failed: {e}")
            return json.dumps([]) # Return empty list on error
    return json.dumps([])

@register.filter(is_safe=True)
def jsonify_model(model_instance):
    """
    Serializes a single model instance to a JSON string dictionary.
    Only includes specific fields needed by the JavaScript.
    """
    if hasattr(model_instance, '_meta'): # Check if it's a Django model instance
        # Define fields needed for current_assessment_step in JS
        fields_needed = ['id', 'status', 'instructions_for_applicant', 'notes', 'step_definition_id']
        try:
            data = {field: getattr(model_instance, field, None) for field in fields_needed}
            # Add display value for status if available
            if 'status' in data and hasattr(model_instance, 'get_status_display'):
                 data['status_display'] = model_instance.get_status_display()
            # Rename id to pk if needed
            if 'id' in data:
                 data['pk'] = data.pop('id')
            return json.dumps(data)
        except Exception as e:
            print(f"[ERROR] jsonify_model failed for {model_instance}: {e}")
            return json.dumps(None) # Return null on error
    return json.dumps(None)

@register.filter(is_safe=True)
def jsonify_stepsmap(steps_map_dict):
    """
    Serializes the steps_map dictionary (mapping def_id -> step_instance) to JSON.
    Only includes specific fields needed by the JavaScript.
    """
    if not isinstance(steps_map_dict, dict):
        return json.dumps({})

    serialized_map = {}
    # Define fields needed for step instances within the map in JS
    # CHANGES BEGIN: Added 'status_display'
    fields_needed = ['id', 'status', 'status_display', 'instructions_for_applicant', 'notes', 'step_definition_id']
    # CHANGES END
    try:
        for def_id, step_instance in steps_map_dict.items():
            if hasattr(step_instance, '_meta'):
                data = {}
                for field in fields_needed:
                    if field == 'status_display' and hasattr(step_instance, 'get_status_display'):
                        data[field] = step_instance.get_status_display()
                    elif hasattr(step_instance, field):
                         data[field] = getattr(step_instance, field, None)

                if 'id' in data:
                     data['pk'] = data.pop('id')
                serialized_map[str(def_id)] = data # Ensure key is string for JSON
            else:
                serialized_map[str(def_id)] = None
        return json.dumps(serialized_map)
    except Exception as e:
        print(f"[ERROR] jsonify_stepsmap failed: {e}")
        return json.dumps({})

# CHANGES END
@register.inclusion_tag('tracker/partials/os_icon.html') # Make sure this path is correct!
def os_icon(os_name_or_object):
    # This is just an example logic, adapt it to your needs
    os_name_str = str(os_name_or_object).lower()
    icon_class = "fas fa-question-circle" # Default icon

    if "windows" in os_name_str:
        icon_class = "fab fa-windows"
    elif "linux" in os_name_str:
        icon_class = "fab fa-linux"
    elif "macos" in os_name_str or "apple" in os_name_str: # Check for macos or apple
        icon_class = "fab fa-apple"
    elif "android" in os_name_str:
        icon_class = "fab fa-android"
    # Add more OS checks as needed
    else:
        icon_class = "fas fa-desktop" # A generic desktop/OS icon

    return {'icon_class': icon_class, 'os_name': str(os_name_or_object)}


@register.filter(name='add_class')
def add_class(value, arg):
    """
    Adds a CSS class to a Django form field.
    Usage: {{ form.my_field|add_class:"your-css-class" }}
    """
    if hasattr(value, 'as_widget'):
        attrs = value.field.widget.attrs
        css_classes = attrs.get('class', '')
        if css_classes:
            css_classes = f"{css_classes} {arg}"
        else:
            css_classes = arg
        return value.as_widget(attrs={'class': css_classes})
    return value


@register.filter(name='step_status_to_class')
def step_status_to_class(status_string):
    """
    Converts a step status string to a corresponding CSS class for styling.
    Example: {{ assessment_step.status|step_status_to_class }}
    (Used in your original client_assessment_detail.html sidebar example)
    """
    status_map = {
        'completed': 'step-completed',  # You'd define .step-completed in CSS
        'active': 'step-active',  # Define .step-active
        'pending': 'step-pending',  # Define .step-pending
        'skipped': 'step-skipped',  # Define .step-skipped
        # Add more statuses as needed from your AssessmentWorkflowStep.Status choices
        'NotStarted': 'step-pending',  # Mapping 'NotStarted' from model to 'pending' display
        'InProgress': 'step-active',  # Mapping 'InProgress' to 'active'
        'Complete': 'step-completed',
        'HelpNeeded': 'step-help-needed',  # Define .step-help-needed
    }
    return status_map.get(str(status_string), '')  # Default to empty string if status not in map


@register.filter(name='replace')
def replace_string(value, arg):
    """
    Replaces all occurrences of a substring with another in a string.
    Argument `arg` should be a string in the format "old_substring,new_substring".
    Example: {{ "hello_world"|replace:"_, " }} -> "hello world"
    """
    if not isinstance(value, str):
        value = str(value)  # Ensure value is a string for the .replace() method

    if isinstance(arg, str) and ',' in arg:
        try:
            old_substring, new_substring = arg.split(',', 1)
            return value.replace(old_substring, new_substring)
        except ValueError:
            # In case arg doesn't split correctly, though the check for ',' should prevent this
            return value
    return value  # Return original value if arg is not formatted correctly or not a string

@register.filter(name='get_status_badge_class') # Renamed for clarity, or keep as get_status_badge
def get_status_badge_class(status):
    """
    Returns a Bootstrap badge background class string based on the assessment status.
    Example usage: <span class="badge bg-{{ assessment.status|get_status_badge_class }}">
    """
    status_map = {
        'Pending': 'secondary',
        'Awaiting Client Input': 'info',
        'In Progress': 'primary',
        'Awaiting Assessor Review': 'warning',
        'Remediation Required': 'danger',
        'QA Review': 'info',
        'Report Generation': 'dark',
        'Completed': 'success',
        'Cancelled': 'light', # Ensure this matches model choices if it's a status
        'On Hold': 'light',   # Ensure this matches model choices if it's a status
        'Scheduled': 'primary',
        'Awaiting Scheduling': 'warning',
    }
    # Ensure status is a string for dictionary lookup, and provide a default
    return status_map.get(str(status), 'secondary')


@register.simple_tag(takes_context=True)
def get_current_workflow_step(context, assessment):
    if not assessment:
        return None
    # Attempt to get the assessment instance if only PK is passed (though less likely here)
    # from ..models import Assessment # Local import to avoid circular if needed
    # if isinstance(assessment, int):
    #     try:
    #         assessment = Assessment.objects.get(pk=assessment)
    #     except Assessment.DoesNotExist:
    #         return None

    current_step = AssessmentWorkflowStep.objects.filter(
        assessment=assessment,
        status__in=[AssessmentWorkflowStep.STATUS_IN_PROGRESS,
                    AssessmentWorkflowStep.STATUS_AWAITING_CLIENT,
                    AssessmentWorkflowStep.STATUS_AWAITING_ASSESSOR,
                    AssessmentWorkflowStep.STATUS_BLOCKED] # Consider active/actionable statuses
    ).order_by('workflow_step_definition__order').first()

    if not current_step:
        current_step = AssessmentWorkflowStep.objects.filter(
            assessment=assessment,
            status=AssessmentWorkflowStep.STATUS_PENDING
        ).order_by('workflow_step_definition__order').first()
    return current_step



@register.filter
def get_form_field(form, field_name):
    return form[field_name]




@register.inclusion_tag('tracker/partials/os_icon.html')
def os_icon(os_name_or_object):
    # ... your existing logic ...
    # Ensure 'tracker/partials/os_icon.html' can handle {'icon_class': ..., 'os_name': ...}
    os_name_str = str(os_name_or_object).lower()
    icon_class = "fas fa-question-circle"
    if "windows" in os_name_str: icon_class = "fab fa-windows"
    elif "linux" in os_name_str: icon_class = "fab fa-linux"
    elif "macos" in os_name_str or "apple" in os_name_str: icon_class = "fab fa-apple"
    elif "android" in os_name_str: icon_class = "fab fa-android"
    else: icon_class = "fas fa-desktop"
    return {'icon_class': icon_class, 'os_name': str(os_name_or_object)}

# ... (add_class, step_status_to_class, replace_string, get_status_badge_class) ...

@register.simple_tag(takes_context=True)  # takes_context for consistency, can be removed if context not used
def get_current_workflow_step(context, assessment_obj):  # Renamed to assessment_obj to avoid clash
    tag_name = "get_current_workflow_step"
    from django.utils import timezone as django_timezone
    now_time = django_timezone.now()

    print(f"# [DEBUG TAGS {now_time}] --- {tag_name} called ---")

    if not assessment_obj:
        print(f"# [DEBUG TAGS {now_time}]   {tag_name}: ERROR - Received 'assessment_obj' is None.")
        return None

    if not isinstance(assessment_obj, Assessment):
        print(
            f"# [DEBUG TAGS {now_time}]   {tag_name}: ERROR - 'assessment_obj' (value: {assessment_obj}) is not an Assessment instance (type: {type(assessment_obj)}).")
        return None

    print(f"# [DEBUG TAGS {now_time}]   {tag_name}: Processing for Assessment ID: {assessment_obj.id}")

    try:
        # Using status constants EXACTLY from your AssessmentWorkflowStep.Status model
        actionable_statuses = [
            AssessmentWorkflowStep.Status.IN_PROGRESS,
            AssessmentWorkflowStep.Status.HELP_NEEDED,
            # Add other statuses that you consider "active" or requiring client attention
            # For example, if you have an 'AWAITING_CLIENT' status in your model:
            # AssessmentWorkflowStep.Status.AWAITING_CLIENT,
        ]
        print(f"# [DEBUG TAGS {now_time}]   {tag_name}: Actionable statuses to check: {actionable_statuses}")

        current_step = AssessmentWorkflowStep.objects.filter(
            assessment=assessment_obj,  # Use the passed Assessment instance
            status__in=actionable_statuses
        ).select_related('step_definition').order_by('step_definition__step_order').first()

        if current_step:
            print(
                f"# [DEBUG TAGS {now_time}]   {tag_name}: Found ACTIONABLE step: ID {current_step.id}, Def: '{current_step.step_definition.name if current_step.step_definition else 'N/A'}', Status: '{current_step.status}' for Assessment {assessment_obj.id}")
        else:
            print(
                f"# [DEBUG TAGS {now_time}]   {tag_name}: No actionable step found for Assessment {assessment_obj.id}. Querying for NOT_STARTED step...")
            current_step = AssessmentWorkflowStep.objects.filter(
                assessment=assessment_obj,
                status=AssessmentWorkflowStep.Status.NOT_STARTED
            ).select_related('step_definition').order_by('step_definition__step_order').first()

            if current_step:
                print(
                    f"# [DEBUG TAGS {now_time}]   {tag_name}: Found NOT_STARTED step: ID {current_step.id}, Def: '{current_step.step_definition.name if current_step.step_definition else 'N/A'}', Status: '{current_step.status}' for Assessment {assessment_obj.id}")
            else:
                print(
                    f"# [DEBUG TAGS {now_time}]   {tag_name}: No NOT_STARTED step found either for Assessment {assessment_obj.id}.")

        if current_step:
            print(
                f"# [DEBUG TAGS {now_time}]   {tag_name}: --- Returning step ID: {current_step.id} for Assessment {assessment_obj.id} ---")
        else:
            print(
                f"# [DEBUG TAGS {now_time}]   {tag_name}: --- Returning None (no current step found) for Assessment {assessment_obj.id} ---")

        return current_step

    except AttributeError as e:
        print(
            f"# [CRITICAL ERROR TAGS {now_time}] {tag_name}: AttributeError for assessment {assessment_obj.id}: {e}. LIKELY A MISMATCH between status constants used here (e.g., AssessmentWorkflowStep.Status.IN_PROGRESS) and their definition in your AssessmentWorkflowStep model. VERIFY THEM.")
        if hasattr(AssessmentWorkflowStep, 'Status'):  # Check if Status enum exists
            print(
                f"    Available statuses on AssessmentWorkflowStep.Status for reference: {[(s.name, s.value) for s in AssessmentWorkflowStep.Status]}")
        else:
            print(f"    AssessmentWorkflowStep.Status enum/attribute NOT FOUND.")
        return None
    except Exception as e:
        print(
            f"# [CRITICAL ERROR TAGS {now_time}] {tag_name}: Unexpected error for assessment {assessment_obj.id}: {e}")
        return None


# CORRECTED REGISTRATION FOR os_to_fa_icon
@register.simple_tag
def os_to_fa_icon(agent_url_instance):
    """
    Maps an OS type key (e.g., 'WINDOWS', 'LINUX', 'MACOS') to a Font Awesome icon class.
    Used as a filter: {{ some_value|os_to_fa_icon }}
    """
    # Assumes NessusAgentURL.OS_WINDOWS etc. are constants defined on the NessusAgentURL model
    if not hasattr(agent_url_instance, 'os_name') or not agent_url_instance.os_name:
        return "fas fa-question-circle"  # Default for invalid input

    os_name_lower = agent_url_instance.os_name.lower()

    # Define your icon mappings here
    # Using 'in' for broader matching (e.g., "Windows Server 2022" contains "windows")
    if "windows" in os_name_lower:
        return "fab fa-windows"
    elif "linux" in os_name_lower:  # Covers generic Linux
        return "fab fa-linux"
    elif "debian" in os_name_lower:
        return "fab fa-debian"  # Specific icon if you have one, else fa-linux
    elif "centos" in os_name_lower:
        return "fab fa-centos"  # Specific icon if you have one, else fa-linux
    elif "ubuntu" in os_name_lower:
        return "fab fa-ubuntu"  # Specific icon if you have one, else fa-linux
    elif "fedora" in os_name_lower:
        return "fab fa-fedora"  # Specific icon if you have one, else fa-linux
    elif "redhat" in os_name_lower or "rhel" in os_name_lower:
        return "fab fa-redhat"  # Specific icon if you have one, else fa-linux
    elif "macos" in os_name_lower or "apple" in os_name_lower:  # Covers macOS
        return "fab fa-apple"
    # Add more specific OS checks if needed:
    # elif "android" in os_name_lower:
    #     return "fab fa-android"
    # elif "freebsd" in os_name_lower:
    #     return "fab fa-freebsd"

    # Fallback for less common or unmatched Linux distributions if not caught above
    if any(distro in os_name_lower for distro in ["suse", "arch", "mint"]):
        return "fab fa-linux"

    return "fas fa-desktop"  # A more generic desktop/server icon as a fallback

# ... (get_form_field) ...

@register.inclusion_tag('tracker/partials/os_icon.html')
def display_os_icon(os_instance):
    """
    Renders an OS icon based on the OperatingSystem instance.
    """
    if not isinstance(os_instance, OperatingSystem):
        return {'icon_class': 'fas fa-question-circle', 'tooltip': 'Unknown OS'}

    # Assumes OperatingSystem.OS_CATEGORY_WINDOWS etc. are constants
    category_icon_map = {
        OperatingSystem.OS_CATEGORY_WINDOWS: "fab fa-windows",
        OperatingSystem.OS_CATEGORY_LINUX: "fab fa-linux",
        OperatingSystem.OS_CATEGORY_MACOS: "fab fa-apple",
        OperatingSystem.OS_CATEGORY_MOBILE_ANDROID: "fab fa-android",
        OperatingSystem.OS_CATEGORY_MOBILE_IOS: "fab fa-apple", # Consider "fab fa-mobile-alt" too
        OperatingSystem.OS_CATEGORY_NETWORK: "fas fa-network-wired",
        OperatingSystem.OS_CATEGORY_OTHER: "fas fa-desktop",
    }
    tooltip = os_instance.name
    if os_instance.version:
        tooltip += f" {os_instance.version}"

    return {
        'icon_class': category_icon_map.get(os_instance.category, "fas fa-question-circle"),
        'tooltip': tooltip  # Ensure 'tracker/partials/os_icon.html' can use 'tooltip'
    }


@register.filter(name='get_first_step_by_status')
def get_first_step_by_status(workflow_steps, status_string):
    """
    Returns the first step from a list of workflow steps
    that matches the given status_string.
    Assumes workflow_steps is a list of objects or dictionaries,
    where each item has a 'status' attribute/key.
    """
    if not workflow_steps:
        return None
    for step in workflow_steps:
        current_status = None
        if hasattr(step, 'status'):
            current_status = step.status
        elif isinstance(step, dict) and 'status' in step:
            current_status = step.get('status')

        if current_status == status_string:
            return step
    return None


# Make sure you also have the last_uploaded_report filter if it's not already defined
@register.filter
def last_uploaded_report(uploaded_reports_queryset):
    """
    Returns the most recently uploaded report from a queryset of UploadedReport objects.
    """
    if uploaded_reports_queryset:
        return uploaded_reports_queryset.order_by('-upload_date').first()
    return None