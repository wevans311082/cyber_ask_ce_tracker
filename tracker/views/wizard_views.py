# File: tracker/wizard_views.py
# Corrected version as of 2025-05-14

import pytz  # For UTC timezone handling
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import Http404, HttpResponseForbidden, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone  # Django's timezone utilities
from django.views import View
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


from collections import OrderedDict
from django.conf import settings
from django.http import HttpResponseRedirect
from django.core.exceptions import ValidationError
from formtools.wizard.views import SessionWizardView


from tracker.mixin import (
AssessorRequiredMixin,
AssessorOrAdminRequiredMixin,
AdminRequiredMixin,
UserPassesTestMixin,
ClientRequiredMixin,

)


# Assuming your models are in .models relative to this views file
from tracker.models import Assessment, WorkflowStepDefinition, AssessmentWorkflowStep, UserProfile, Client


# Helper function for user access tests
# Ensure this function correctly reflects your UserProfile and Client model structure
def user_can_access_assessment(user, assessment: Assessment) -> bool:
    """
    Checks if a user has permission to access a given assessment.
    Allows superusers, staff, or the client associated with the assessment.
    """
    print(
        f"[DEBUG UCAA] Checking access for user '{user}' (ID: {user.id}, is_superuser: {user.is_superuser}, is_staff: {user.is_staff}) for Assessment ID: {assessment.id}")

    if user.is_superuser or user.is_staff:
        print(f"[DEBUG UCAA] Access GRANTED: User '{user}' is superuser or staff.")
        return True

    print(f"[DEBUG UCAA] User '{user}' is not admin/staff. Proceeding with client association check.")
    try:
        print(f"[DEBUG UCAA] Attempting to get UserProfile for request.user '{user}' (ID: {user.id}).")
        request_user_profile = UserProfile.objects.get(user=user)
        print(
            f"[DEBUG UCAA] Found UserProfile (ID: {request_user_profile.id}, Role: {request_user_profile.role}) for request.user '{user}'.")

        if assessment.client is None:
            print(
                f"[DEBUG UCAA] Access DENIED: Assessment (ID: {assessment.id}) has no client linked (assessment.client is None).")
            return False

        print(
            f"[DEBUG UCAA] Assessment (ID: {assessment.id}) is linked to Client (ID: {assessment.client.id}, Name: {assessment.client.name if hasattr(assessment.client, 'name') else 'N/A'}).")

        # The Client model links to UserProfile via a OneToOneField named 'user_profile'
        assessment_client_user_profile = assessment.client.user_profile

        if assessment_client_user_profile is None:
            print(
                f"[DEBUG UCAA] Access DENIED: Client (ID: {assessment.client.id}) for Assessment (ID: {assessment.id}) has no UserProfile linked (assessment.client.user_profile is None).")
            return False

        print(
            f"[DEBUG UCAA] Client (ID: {assessment.client.id}) for Assessment (ID: {assessment.id}) is linked to UserProfile (ID: {assessment_client_user_profile.id}, User: {assessment_client_user_profile.user}, Role: {assessment_client_user_profile.role}).")

        # The crucial comparison:
        is_match = (assessment_client_user_profile == request_user_profile)

        if is_match:
            print(
                f"[DEBUG UCAA] Access GRANTED: UserProfile (ID: {request_user_profile.id}) of request.user '{user}' MATCHES UserProfile (ID: {assessment_client_user_profile.id}) of assessment's client.")
            return True
        else:
            print(
                f"[DEBUG UCAA] Access DENIED: UserProfile (ID: {request_user_profile.id}) of request.user '{user}' DOES NOT MATCH UserProfile (ID: {assessment_client_user_profile.id}) of assessment's client.")
            return False

    except UserProfile.DoesNotExist:
        print(
            f"[DEBUG UCAA] Access DENIED: UserProfile.DoesNotExist for request.user '{user}' (ID: {user.id}). Ensure this user has a UserProfile record.")
        return False
    except Client.DoesNotExist:
        # This should ideally not be hit if assessment.client is a mandatory ForeignKey and valid.
        print(
            f"[DEBUG UCAA] Access DENIED: Client.DoesNotExist for assessment '{assessment.id}'. This indicates an issue with assessment.client linkage.")
        return False
    except Exception as e:
        print(
            f"[DEBUG UCAA] Access DENIED: Unexpected error during permission check for user '{user}', assessment '{assessment.id}': {e.__class__.__name__} - {str(e)}")
        return False


class ClientAssessmentWizardView(LoginRequiredMixin, UserPassesTestMixin, View):
    template_name = "tracker/wizard/wizard_base.html"

    def test_func(self) -> bool:
        assessment_id = self.kwargs.get("assessment_id")
        try:
            assessment = Assessment.objects.get(id=assessment_id)
            # Assuming user_can_access_assessment is correctly defined and imported
            # If the ImportError for user_can_access_assessment persists,
            # we'll need the content of tracker/utils.py

            return user_can_access_assessment(self.request.user, assessment)
        except Assessment.DoesNotExist:
            return False
        except ImportError: # Temporarily bypass if util not found, for focusing on current error
            print(f"[DEBUG] ImportError for user_can_access_assessment, test_func bypassed for now. at {timezone.now()}")
            # In a real scenario, this should be fixed. For now, allowing wizard to load.
            # Consider if self.request.user.is_staff or some other check is a temporary placeholder
            return True # Or False, depending on desired behavior during this debug phase


    def handle_no_permission(self):
        assessment_id = self.kwargs.get("assessment_id")
        # [DEBUG] {description} at {timezone.now()}
        print(
            f"[DEBUG] Unauthorized access attempt to wizard for assessment {assessment_id} "
            f"by user {self.request.user} at {timezone.now().astimezone(pytz.utc)}"
        )
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        return HttpResponseForbidden(_("You do not have permission to access this assessment wizard."))

    def get(self, request, assessment_id: int):
        assessment = get_object_or_404(Assessment, id=assessment_id)
        # [DEBUG] {description} at {timezone.now()}
        print(
            f"[DEBUG] ClientAssessmentWizardView GET for Assessment ID: {assessment_id} at UTC: {timezone.now().astimezone(pytz.utc)} by user {request.user}")

        initial_step_url = None

        step_definitions = WorkflowStepDefinition.objects.filter(
            Q(assignee_type=WorkflowStepDefinition.ASSIGNEE_CHOICES[0][0]) | Q(assignee_type=WorkflowStepDefinition.ASSIGNEE_CHOICES[2][0]), # Applicant or Both
            is_active=True
        ).order_by("step_order")

        if not step_definitions.exists():
            # [DEBUG] {description} at {timezone.now()}
            print(f"[DEBUG] No 'Applicant' or 'Both' active workflow step definitions found for wizard. Assessment: {assessment.id} at {timezone.now()}")
        else:
            first_pending_step_order = None
            for step_def in step_definitions:
                assessment_step, _created = AssessmentWorkflowStep.objects.get_or_create(
                    assessment=assessment,
                    step_definition=step_def,
                    defaults={
                        "status": AssessmentWorkflowStep.Status.NOT_STARTED,
                        "last_updated": timezone.now()
                    }
                )
                if _created:
                    # [DEBUG] {description} at {timezone.now()}
                    print(f"[DEBUG] Created AssessmentWorkflowStep (Status: {AssessmentWorkflowStep.Status.NOT_STARTED}) for step_def: {step_def.id} for assessment: {assessment.id} at {timezone.now()}")

                if assessment_step.status not in [
                    AssessmentWorkflowStep.Status.COMPLETE,
                    AssessmentWorkflowStep.Status.SKIPPED,
                ]:
                    first_pending_step_order = step_def.step_order
                    break

            if first_pending_step_order is not None:
                try:
                    initial_step_url = reverse(
                        "tracker:client_assessment_wizard_step_htmx",  # Use namespace
                        kwargs={"assessment_id": assessment.id, "step_order": first_pending_step_order},
                    )
                    # [DEBUG] {description} at {timezone.now()}
                    print(f"[DEBUG] Initial step URL for wizard: {initial_step_url} (Order: {first_pending_step_order}) at {timezone.now()}")
                except Exception as e: # Catch potential NoReverseMatch during development
                    # [DEBUG] {description} at {timezone.now()}
                    print(f"[DEBUG] ERROR generating initial_step_url: {e} at {timezone.now()}")
                    initial_step_url = None # Ensure it's None if reverse fails
            else:
                # [DEBUG] {description} at {timezone.now()}
                print(f"[DEBUG] All 'Applicant' or 'Both' active steps completed or skipped for Assessment ID: {assessment.id} at {timezone.now()}")

        context = {
            "assessment": assessment,
            "initial_step_url": initial_step_url,
            "client": assessment.client,
            "page_title": _("Assessment Wizard"),
            "current_time": timezone.now()
        }
        return render(request, self.template_name, context)


class ClientAssessmentWizardStepView(LoginRequiredMixin, UserPassesTestMixin, View):
    template_name_base = "tracker/wizard/steps/"

    def test_func(self) -> bool:
        assessment_id = self.kwargs.get("assessment_id")
        try:
            assessment = Assessment.objects.get(id=assessment_id)
            # Ensure this check is robust for your application's security model
            if hasattr(self.request.user, 'userprofile') and assessment.client == self.request.user.userprofile.client:
                return True
            # Add other conditions if necessary, e.g., for staff users with specific permissions
            # Consider using the user_can_access_assessment utility if it's robust
            print(
                f"[DEBUG] test_func in ClientAssessmentWizardStepView for assessment {assessment_id}, user {self.request.user}. Defaulting access for now.")
            # return True # Placeholder for more complex logic if needed
            return False  # Default to deny if specific conditions aren't met
        except Assessment.DoesNotExist:
            return False
        except AttributeError:  # Handle if userprofile or client is not found
            return False

    def handle_no_permission(self):
        print(
            f"[DEBUG] Unauthorized access attempt to wizard step by user {self.request.user} at {timezone.now().astimezone(pytz.utc)}"
        )
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        return HttpResponseForbidden(_("You do not have permission to access this assessment step."))

    def get(self, request, assessment_id: int, step_order: int):
        assessment = get_object_or_404(Assessment, id=assessment_id)

        try:
            step_definition = WorkflowStepDefinition.objects.get(
                step_order=step_order,
                is_active=True,
                assignee_type__in=[
                    WorkflowStepDefinition.ASSIGNEE_CHOICES[0][0],  # 'Applicant'
                    WorkflowStepDefinition.ASSIGNEE_CHOICES[2][0]  # 'Both'
                ]
            )
            # THE FIX IS HERE: Changed .title to .name
            print(
                f"[DEBUG] Fetched step_definition: '{step_definition.name}' (Order: {step_definition.step_order}) for wizard step view at {timezone.now()}")

        except WorkflowStepDefinition.DoesNotExist:
            print(
                f"[DEBUG] WorkflowStepDefinition not found for step_order {step_order} (Applicant/Both, Active) for assessment {assessment_id} at {timezone.now()}")
            return render(request, f"{self.template_name_base}_step_not_found.html", {
                "assessment": assessment,
                "step_order": step_order,
                "page_title": _("Step Not Found"),
                "current_time": timezone.now()
            })
        except WorkflowStepDefinition.MultipleObjectsReturned:
            print(
                f"[DEBUG] Multiple WorkflowStepDefinitions found for step_order {step_order} (Applicant/Both, Active) for assessment {assessment_id} at {timezone.now()}")
            return render(request, f"{self.template_name_base}_step_error.html", {
                "assessment": assessment,
                "step_order": step_order,
                "page_title": _("Step Configuration Error"),
                "current_time": timezone.now()
            })

        assessment_step, created = AssessmentWorkflowStep.objects.get_or_create(
            assessment=assessment,
            step_definition=step_definition,
            defaults={
                "status": AssessmentWorkflowStep.Status.NOT_STARTED,
                "last_updated": timezone.now()
            }
        )
        if created:
            print(
                f"[DEBUG] Created AssessmentWorkflowStep for step '{step_definition.name}' in wizard step view at {timezone.now()}")

        step_template_name = f"{self.template_name_base}{step_definition.template_name or f'step_{step_order}.html'}"

        if not step_definition.template_name:
            print(
                f"[DEBUG] No explicit template_name for step_order {step_order}. Falling back to placeholder. at {timezone.now()}")
            step_template_name = f"{self.template_name_base}_step_placeholder.html"

        context = {
            "assessment": assessment,
            "step_definition": step_definition,
            "assessment_step": assessment_step,
            "step_order": step_order,
            # THE FIX IS ALSO HERE: Changed .title to .name
            "page_title": _(f"Step {step_order}: {step_definition.name}"),
            "current_time": timezone.now(),
        }

        print(f"[DEBUG] Rendering template: {step_template_name} for step {step_order} at {timezone.now()}")
        try:
            return render(request, step_template_name, context)
        except Exception as e:
            print(f"[DEBUG] Error rendering template {step_template_name}: {e} at {timezone.now()}")
            # Fallback to a generic error page if the specific step template fails
            return render(request, f"{self.template_name_base}_step_render_error.html", {
                "assessment": assessment,
                "step_order": step_order,
                "error_message": str(e),
                "page_title": _("Error Loading Step"),
                "current_time": timezone.now()
            })

    def post(self, *args, **kwargs):
        management_form = self.get_management_form()
        if not management_form.is_valid():
            # This indicates a problem with the wizard's internal state management form
            # It's usually hidden and should always be valid if generated correctly.
            raise ValueError(_("ManagementForm data is missing or has been tampered with."))

        form = self.get_form(data=self.request.POST, files=self.request.FILES)
        form_kwargs = self.get_form_kwargs(self.steps.current)
        assessment = form_kwargs.get('assessment')  # Assuming assessment is passed to forms

        # Determine which button was pressed
        if "submit_complete_next" in self.request.POST:
            if form.is_valid():
                self.save_step_data(form, assessment, mark_as_complete=True)
                return self.render_next_step(form)  # Advances to the next step
            else:
                return self.render(form)  # Re-render current step with validation errors

        elif "submit_next_only" in self.request.POST:
            # For "Move on to next step (Save Progress)", we might still want to save valid data
            # but mark the step differently or not at all.
            # formtools typically requires a step to be "valid" to move to the next default way.
            # If you want to move on even if the form is not fully "complete" per its validation,
            # this requires more custom handling.

            # Option A: Save if valid, mark as 'In Progress', then move.
            if form.is_valid():
                self.save_step_data(form, assessment, mark_as_complete=False,
                                    status_override=AssessmentWorkflowStep.Status.IN_PROGRESS)
                return self.render_next_step(form)
            else:
                # If you want to allow moving on even with validation errors for this button:
                # This is advanced and bypasses default wizard validation flow for progression.
                # self.storage.current_step = self.steps.next
                # return self.render(self.get_form(step=self.steps.current, data=None, files=None))
                # For now, let's assume it re-renders on error like the other button.
                return self.render(form)

                # Handle other submissions like "Previous" button if it posts, or default submit
        # This would be the path if only one "Save and Continue" button existed.
        # Or if wizard_goto_step is used (e.g., from progress bar clicks).
        # The WizardView.post() method has logic for 'wizard_goto_step'.
        return super().post(*args, **kwargs)  # Fallback to default SessionWizardView post handling

    def save_step_data(self, form, assessment, mark_as_complete=False, status_override=None):
        # Save form data to wizard storage
        self.storage.set_step_data(self.steps.current, self.process_step(form))
        self.storage.set_step_files(self.steps.current, self.process_step_files(form))

        # Update AssessmentWorkflowStep status
        # This requires mapping self.steps.current (e.g. '0', '1') to a WorkflowStepDefinition
        step_key = self.steps.current
        # You need a reliable way to get the WorkflowStepDefinition for the current wizard step key.
        # This mapping depends on how your form_list is constructed.
        # For example, if your forms have a 'step_order' attribute or if form_list keys ARE step_orders:
        try:
            # This is a placeholder - you need a robust way to get the step_def
            # e.g. if your form has an attribute linking it to the step_def or its order
            # current_form_class = self.form_list[step_key]
            # step_order = getattr(current_form_class, 'step_order', None)
            # if step_order is None: # Or if keys are step_orders directly
            step_order_from_url = self.kwargs.get('step_order')  # If 'step_order' is in the URL kwargs for this view

            if step_order_from_url:
                step_def = WorkflowStepDefinition.objects.get(
                    step_order=step_order_from_url,
                    # Add filters for assignee_type if needed, though wizard should only list relevant steps
                )
                aws, _ = AssessmentWorkflowStep.objects.get_or_create(
                    assessment=assessment,
                    step_definition=step_def,
                    defaults={'status': AssessmentWorkflowStep.Status.NOT_STARTED}
                )
                if status_override:
                    aws.status = status_override
                elif mark_as_complete:
                    aws.status = AssessmentWorkflowStep.Status.COMPLETE
                elif aws.status == AssessmentWorkflowStep.Status.NOT_STARTED:  # Only set to In Progress if not already completed/skipped
                    aws.status = AssessmentWorkflowStep.Status.IN_PROGRESS

                aws.last_updated = timezone.now()
                aws.save()
                # [DEBUG] {description} at {timezone.now()}
                print(
                    f"[DEBUG] Step {step_def.name} status updated to {aws.status} for AssID {assessment.id} at {timezone.now()}")
            else:
                # [DEBUG] {description} at {timezone.now()}
                print(
                    f"[WARNING] Could not determine step_order to update AssessmentWorkflowStep status for wizard step {step_key} at {timezone.now()}")

        except WorkflowStepDefinition.DoesNotExist:
            # [DEBUG] {description} at {timezone.now()}
            print(
                f"[ERROR] WorkflowStepDefinition not found for step_order from URL to update status for wizard step {step_key} at {timezone.now()}")
        except Exception as e:
            # [DEBUG] {description} at {timezone.now()}
            print(
                f"[ERROR] Could not update AssessmentWorkflowStep status for wizard step {step_key}: {e} at {timezone.now()}")