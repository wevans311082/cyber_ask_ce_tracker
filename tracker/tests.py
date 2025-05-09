# File: tracker/tests.py

from django.test import TestCase, Client as TestClient # Renamed Django's client to avoid conflict
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import date, timedelta

# Import your models and forms
from .models import Client, UserProfile, Assessment
from .forms import ClientForm

# Create your tests here.

class ClientModelTest(TestCase):
    """ Tests for the Client model """

    def test_client_str_representation(self):
        """ Test the __str__ method of the Client model """
        client = Client.objects.create(
            name="Test Client Co",
            contact_person="Test Person",
            contact_email="test@example.com"
        )
        self.assertEqual(str(client), "Test Client Co")

class AssessmentModelTest(TestCase):
    """ Tests for the Assessment model """

    def setUp(self):
        """ Set up common data for Assessment tests """
        self.client_obj = Client.objects.create(name="Assessment Test Client")
        self.ce_pass_date = date(2025, 1, 1)

    def test_ce_plus_window_end_date_calculation(self):
        """ Test the ce_plus_window_end_date property calculation """
        assessment = Assessment.objects.create(
            client=self.client_obj,
            assessment_type='CE+',
            date_ce_passed=self.ce_pass_date
        )
        expected_end_date = self.ce_pass_date + timedelta(days=90)
        self.assertEqual(assessment.ce_plus_window_end_date, expected_end_date)

    def test_ce_plus_window_end_date_for_non_ce_plus(self):
        """ Test the property returns None if assessment is not CE+ """
        assessment = Assessment.objects.create(
            client=self.client_obj,
            assessment_type='CE', # Not CE+
            date_ce_passed=self.ce_pass_date
        )
        self.assertIsNone(assessment.ce_plus_window_end_date)

    def test_ce_plus_window_end_date_if_date_missing(self):
        """ Test the property returns None if date_ce_passed is None """
        assessment = Assessment.objects.create(
            client=self.client_obj,
            assessment_type='CE+',
            date_ce_passed=None # Date is missing
        )
        self.assertIsNone(assessment.ce_plus_window_end_date)


class ClientDashboardViewTest(TestCase):
    """ Tests for the Client Dashboard view """

    def setUp(self):
        """ Set up users and clients needed for dashboard tests """
        # Use Django's test client
        self.test_client = TestClient()

        # Create a client user
        self.client_user = User.objects.create_user(username='testclient', password='password123')
        self.client_company = Client.objects.create(name="Client Corp", contact_person="C", contact_email="c@c.com")
        self.client_profile = UserProfile.objects.create(user=self.client_user, role='Client', client=self.client_company)

        # Create an assessor user (for testing access denial)
        self.assessor_user = User.objects.create_user(username='testassessor', password='password123')
        self.assessor_profile = UserProfile.objects.create(user=self.assessor_user, role='Assessor')

        self.dashboard_url = reverse('tracker:client_dashboard')
        self.login_url = reverse('login') # Assuming 'login' is the name of your login URL

    def test_client_can_access_dashboard(self):
        """ Test that an authenticated client user can access their dashboard """
        self.test_client.login(username='testclient', password='password123')
        response = self.test_client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'tracker/client/client_dashboard.html')
        self.assertContains(response, "Client Corp") # Check if client name is present

    def test_unauthenticated_user_redirected(self):
        """ Test that an unauthenticated user is redirected to the login page """
        response = self.test_client.get(self.dashboard_url)
        self.assertEqual(response.status_code, 302) # 302 Found (Redirect)
        self.assertRedirects(response, f'{self.login_url}?next={self.dashboard_url}')

    def test_assessor_cannot_access_client_dashboard(self):
        """ Test that an assessor user is redirected (or forbidden) from client dashboard """
        self.test_client.login(username='testassessor', password='password123')
        response = self.test_client.get(self.dashboard_url)
        # Depending on your @user_passes_test or mixin, this might be 302 redirect or 403 Forbidden
        # If using user_passes_test(is_client, login_url=...), it redirects to login
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.login_url) # Redirects to default login_url


class ClientFormTest(TestCase):
    """ Tests for the ClientForm """

    def test_client_form_valid_data(self):
        """ Test ClientForm with valid data """
        form_data = {
            'name': 'Valid Client Name',
            'contact_person': 'Valid Person',
            'contact_email': 'valid@email.com',
            'organization_number': '12345678', # Optional field example
            'website_address': 'https://example.com', # Optional field example
            'address': '123 Valid Street' # Optional field example
        }
        form = ClientForm(data=form_data)
        self.assertTrue(form.is_valid(), msg=f"Form should be valid, errors: {form.errors.as_json()}")

    def test_client_form_missing_required_fields(self):
        """ Test ClientForm with missing required fields (name, person, email) """
        form_data = {'organization_number': '12345678'} # Missing name, person, email
        form = ClientForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)
        self.assertIn('contact_person', form.errors)
        self.assertIn('contact_email', form.errors)
        self.assertEqual(form.errors['name'], ['This field is required.']) # Check specific error message

    def test_client_form_invalid_email(self):
        """ Test ClientForm with an invalid email address """
        form_data = {
            'name': 'Email Test Client',
            'contact_person': 'Email Person',
            'contact_email': 'invalid-email-format', # Invalid email
        }
        form = ClientForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('contact_email', form.errors)
        self.assertEqual(form.errors['contact_email'], ['Enter a valid email address.'])