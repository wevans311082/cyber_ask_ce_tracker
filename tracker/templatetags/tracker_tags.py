# File: tracker/templatetags/tracker_tags.py
# CHANGES BEGIN - Added JSON filters and ensured imports
import json
import os
from django import template
from django.db.models import Q, QuerySet
from django.forms.models import model_to_dict # For jsonify_model
from typing import Dict, Any, List, Optional

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