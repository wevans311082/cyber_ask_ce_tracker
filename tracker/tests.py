# File: tracker/tests.py

from django.test import TestCase, Client as TestClient # Renamed Django's client to avoid conflict
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import date, timedelta

# Import your models and forms
from .models import Client, UserProfile, Assessment
from .forms import ClientForm


import uuid
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import Assessment, Client, TenableScanLog # Assuming Client model exists
from .tasks import launch_tenable_scan_task

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


MOCK_TENANCY_SCAN_DEFINITION_UUID = str(uuid.uuid4())
MOCK_TENANCY_SCAN_DEFINITION_ID = "12345"

class TenableTasksTests(TestCase):

    def setUp(self):
        # Create a dummy user
        self.user = User.objects.create_user(username='testuser', password='password')
        # Create a dummy client
        self.client = Client.objects.create(name="Test Client Ltd")
        # Create a dummy assessment
        self.assessment = Assessment.objects.create(
            client=self.client,
            # Add any other required fields for Assessment model
            # For example:
            # tenable_scan_uuid=str(uuid.uuid4()) # If assessment had its own scan definition
        )
        self.targets = ["192.168.1.10", "domain.example.com"] # Example targets

    @override_settings(
        TENABLE_ACCESS_KEY="dummy_access_key",
        TENABLE_SECRET_KEY="dummy_secret_key",
        TENABLE_IO_URL="https://dummy.tenable.io",
        TENANCY_SCAN_UUID=MOCK_TENANCY_SCAN_DEFINITION_UUID,
        TENANCY_SCAN_ID=MOCK_TENANCY_SCAN_DEFINITION_ID
    )
    @patch('tracker.tasks.get_tenable_client')
    def test_launch_tenable_scan_task_success(self, mock_get_tenable_client):
        # Mock the TenableIOClient and its launch_scan method
        mock_tio_client = MagicMock()
        mock_scan_run_uuid = str(uuid.uuid4()) # This is the UUID of the scan *instance*
        mock_tio_client.launch_scan.return_value = mock_scan_run_uuid
        mock_get_tenable_client.return_value = mock_tio_client

        # Call the task directly for testing
        # In a real Celery setup, you might use .delay() or .apply_async()
        # and have Celery run in eager mode for tests.
        launch_tenable_scan_task(self.assessment.id, self.targets, self.user.id)

        # 1. Verify TenableIOClient.launch_scan was called correctly
        expected_scan_name = f"Assessment {self.assessment.id} - {self.assessment.client.name} - {timezone.now().strftime('%Y-%m-%d %H:%M')}"
        # Note: The exact timestamp in scan_name might cause flakiness if not handled (e.g., by also mocking timezone.now within the task's scope or checking parts of the name)
        # For simplicity, we'll check the call was made.
        self.assertTrue(mock_tio_client.launch_scan.called)
        call_args = mock_tio_client.launch_scan.call_args
        self.assertEqual(call_args[0][0], MOCK_TENANCY_SCAN_DEFINITION_UUID) # scan_uuid argument
        self.assertEqual(call_args[0][1], self.targets) # targets argument
        self.assertTrue(call_args[0][2].startswith(f"Assessment {self.assessment.id} - {self.assessment.client.name}")) # scan_name argument (partial check)


        # 2. Verify TenableScanLog entry was created
        self.assertEqual(TenableScanLog.objects.count(), 1)
        log_entry = TenableScanLog.objects.first()

        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.assessment, self.assessment)
        self.assertTrue(log_entry.scan_name.startswith(f"Assessment {self.assessment.id} - {self.assessment.client.name}"))
        self.assertEqual(str(log_entry.scan_uuid), MOCK_TENANCY_SCAN_DEFINITION_UUID) # Scan *Definition* UUID
        self.assertEqual(log_entry.tenable_scan_id, MOCK_TENANCY_SCAN_DEFINITION_ID) # Scan *Definition* ID
        self.assertEqual(str(log_entry.scan_run_uuid), mock_scan_run_uuid) # Scan *Instance/Run* UUID
        self.assertEqual(log_entry.initiated_by, self.user)
        self.assertIsNotNone(log_entry.initiated_at)
        self.assertEqual(log_entry.status_from_tenable, "LAUNCHED") # Or "REQUESTED", "PENDING" depending on your logic

        # Check that result fields are initially empty/None
        self.assertIsNone(log_entry.completed_at)
        self.assertIsNone(log_entry.assets_scanned)
        self.assertIsNone(log_entry.critical_vuls)
        self.assertIsNone(log_entry.high_vuls)
        self.assertIsNone(log_entry.medium_vuls)
        self.assertIsNone(log_entry.low_vuls)
        self.assertIsNone(log_entry.raw_summary_data)
        self.assertIsNone(log_entry.last_fetched_from_tenable)

    @override_settings(
        TENABLE_ACCESS_KEY="dummy_access_key",
        TENABLE_SECRET_KEY="dummy_secret_key",
        TENABLE_IO_URL="https://dummy.tenable.io",
        TENANCY_SCAN_UUID=MOCK_TENANCY_SCAN_DEFINITION_UUID,
        TENANCY_SCAN_ID=MOCK_TENANCY_SCAN_DEFINITION_ID
    )
    @patch('tracker.tasks.get_tenable_client')
    @patch('tracker.tasks.logger') # Mock the logger
    def test_launch_tenable_scan_task_api_failure(self, mock_logger, mock_get_tenable_client):
        # Mock the TenableIOClient to raise an exception
        mock_tio_client = MagicMock()
        mock_tio_client.launch_scan.side_effect = Exception("Tenable API Error")
        mock_get_tenable_client.return_value = mock_tio_client

        # Call the task
        with self.assertRaises(Exception): # Expecting the task to re-raise or handle
            launch_tenable_scan_task(self.assessment.id, self.targets, self.user.id)

        # Verify no TenableScanLog entry was created on failure (unless you have specific error logging in the DB)
        self.assertEqual(TenableScanLog.objects.count(), 0)

        # Verify error was logged
        self.assertTrue(mock_logger.error.called)
        # You can make more specific assertions about the log message if needed
        # print(mock_logger.error.call_args_list) # to see what was logged

    @override_settings(
        TENABLE_ACCESS_KEY="dummy_access_key",
        TENABLE_SECRET_KEY="dummy_secret_key",
        TENABLE_IO_URL="https://dummy.tenable.io",
        TENANCY_SCAN_UUID=MOCK_TENANCY_SCAN_DEFINITION_UUID,
        TENANCY_SCAN_ID=MOCK_TENANCY_SCAN_DEFINITION_ID
    )
    @patch('tracker.tasks.get_tenable_client')
    def test_launch_tenable_scan_task_no_user(self, mock_get_tenable_client):
        # Test case where user_id is None
        mock_tio_client = MagicMock()
        mock_scan_run_uuid = str(uuid.uuid4())
        mock_tio_client.launch_scan.return_value = mock_scan_run_uuid
        mock_get_tenable_client.return_value = mock_tio_client

        launch_tenable_scan_task(self.assessment.id, self.targets, user_id=None)

        self.assertEqual(TenableScanLog.objects.count(), 1)
        log_entry = TenableScanLog.objects.first()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.assessment, self.assessment)
        self.assertIsNone(log_entry.initiated_by) # Check user is None
        self.assertEqual(str(log_entry.scan_run_uuid), mock_scan_run_uuid)
        self.assertEqual(log_entry.status_from_tenable, "LAUNCHED")
