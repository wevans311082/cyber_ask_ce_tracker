
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import get_object_or_404, redirect, render


from .utils import (
is_client,
is_assessor,
is_admin,
)


class AdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_admin(self.request.user)

    def handle_no_permission(self):
        # Optional: Customize response for permission denied
        if not self.request.user.is_authenticated:
            return super().handle_no_permission() # Redirect to login
        messages.error(self.request, "Admin permissions required.")
        # Redirect non-admins somewhere appropriate, maybe the main dashboard
        # Check if user has any profile first
        if hasattr(self.request.user, 'userprofile') and self.request.user.userprofile is not None:
            if is_assessor(self.request.user):
                 return redirect('tracker:assessor_dashboard')
            elif is_client(self.request.user):
                 return redirect('tracker:client_dashboard')
        # Fallback if no role or profile
        return redirect('login')
class AssessorRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_assessor(self.request.user)

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "Assessor permissions required.")
        # Redirect non-assessors
        if is_admin(self.request.user):
            return redirect('tracker:admin_dashboard')
        elif is_client(self.request.user):
            return redirect('tracker:client_dashboard')
        return redirect('login')
class ClientRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        # Also check if the client user is linked to a company
        return is_client(self.request.user) and self.request.user.userprofile.client is not None

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()

        # Check if they are a client but just not linked yet
        if is_client(self.request.user) and self.request.user.userprofile.client is None:
            messages.warning(self.request, "Your client account is not yet linked to a company. Please contact an administrator.")
            return redirect('login') # Or an error page/logout

        messages.error(self.request, "Client permissions required.")
        # Redirect non-clients
        if is_admin(self.request.user):
            return redirect('tracker:admin_dashboard')
        elif is_assessor(self.request.user):
            return redirect('tracker:assessor_dashboard')
        return redirect('login')
class AssessorOrAdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return is_admin(self.request.user) or is_assessor(self.request.user)

    def handle_no_permission(self):
        if not self.request.user.is_authenticated:
            return super().handle_no_permission()
        messages.error(self.request, "Admin or Assessor permissions required.")
        if is_client(self.request.user):
            return redirect('tracker:client_dashboard')
        return redirect('login')

