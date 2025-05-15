import os

# This should match the data in your populate_workflow_steps.py
FULL_WORKFLOW_STEPS_DATA = [
    {'order': 1, 'name': 'Agree Date', 'description': 'Agree date of assessment', 'assignee': 'Both',
     'template_name': 'step_agree_date.html', 'skippable': False},
    {'order': 2, 'name': 'Define User Devices',
     'description': "List all users, roles, computer OS versions, mobile device versions in 'User Devices'.",
     'assignee': 'Applicant', 'template_name': 'step_define_user_devices.html', 'skippable': False},
    {'order': 3, 'name': 'Define External IPs',
     'description': "List external IPs/hostnames of internet-facing devices in 'External IPs'.",
     'assignee': 'Applicant', 'template_name': 'step_define_external_ips.html', 'skippable': False},
    {'order': 4, 'name': 'Define Servers', 'description': "List all managed servers (OS/version/role) in 'Servers'.",
     'assignee': 'Applicant', 'template_name': 'step_define_servers.html', 'skippable': False},
    {'order': 5, 'name': 'Provide MFA Proof',
     'description': "Provide admin and user MFA screenshots for each required cloud service in 'MFA'.",
     'assignee': 'Applicant', 'template_name': 'step_provide_mfa_proof.html', 'skippable': False},
    {'order': 6, 'name': 'Select Sample', 'description': 'Assessor selects list of users/devices to sample.',
     'assignee': 'Assessor', 'template_name': 'step_select_sample.html', 'skippable': False},
    {'order': 7, 'name': 'Confirm Availability',
     'description': 'Applicant confirms selected users are available for approx. 30 mins each on assessment date.',
     'assignee': 'Applicant', 'template_name': 'step_confirm_availability.html', 'skippable': False},
    {'order': 8, 'name': 'Finalise Sample List',
     'description': 'Both agree final list of users for assessment; Assessor provides list.', 'assignee': 'Both',
     'template_name': 'step_finalise_sample_list.html', 'skippable': False},
    {'order': 9, 'name': 'Install Nessus Agents',
     'description': 'Applicant installs Nessus agents on selected computers (details provided by Assessor).',
     'assignee': 'Applicant', 'template_name': 'step_install_nessus_agents.html', 'skippable': False},
    {'order': 10, 'name': 'Book User Slots',
     'description': 'Applicant books selected users for sequential 1-hour slots with assessor on agreed date.',
     'assignee': 'Applicant', 'template_name': 'step_book_user_slots.html', 'skippable': False},
    {'order': 11, 'name': 'Inform Users',
     'description': 'Applicant informs selected users about the assessment process (screen sharing, malware tests, etc.).',
     'assignee': 'Applicant', 'template_name': 'step_inform_users.html', 'skippable': False},
    {'order': 12, 'name': 'Install Mobile App',
     'description': 'Applicant ensures necessary app (e.g., Teams) is installed on selected mobile devices.',
     'assignee': 'Applicant', 'template_name': 'step_install_mobile_app.html', 'skippable': False},
    {'order': 13, 'name': 'Update Devices',
     'description': 'Applicant updates all computer & mobile device OS and installed apps.', 'assignee': 'Applicant',
     'template_name': 'step_update_devices.html', 'skippable': False},
    {'order': 14, 'name': 'Agent Test Scans',
     'description': 'Assessor runs test scans of selected computers via Nessus agents.', 'assignee': 'Assessor',
     'template_name': 'step_agent_test_scans.html', 'skippable': False},
    {'order': 15, 'name': 'Remediate Agent Scans',
     'description': 'Applicant updates apps/OS if scans show vulnerabilities.', 'assignee': 'Applicant',
     'template_name': 'step_remediate_agent_scans.html', 'skippable': False},
    {'order': 16, 'name': 'External Scan', 'description': 'Assessor scans external IP addresses/hostnames.',
     'assignee': 'Assessor', 'template_name': 'step_external_scan.html', 'skippable': False},
    {'order': 17, 'name': 'Remediate External Scan',
     'description': 'Applicant remediates identified issues, if any, from external scan.', 'assignee': 'Applicant',
     'template_name': 'step_remediate_external_scan.html', 'skippable': False},
    {'order': 18, 'name': 'Send Test Emails',
     'description': 'Assessor sends selected users test emails with fake malware.', 'assignee': 'Assessor',
     'template_name': 'step_send_test_emails.html', 'skippable': False},
    {'order': 19, 'name': 'Assessment Day Execution',
     'description': 'Assessment Day: Nessus scans run, checks on user computers and mobiles performed.',
     'assignee': 'Both', 'template_name': 'step_assessment_day_execution.html', 'skippable': False},
    {'order': 20, 'name': 'Generate Report', 'description': 'Assessor generates the final assessment report.',
     'assignee': 'Assessor', 'template_name': 'step_generate_report.html', 'skippable': False},
    {'order': 21, 'name': 'Issue Certificate',
     'description': 'Certification Body issues certificate upon successful assessment.', 'assignee': 'Assessor',
     'template_name': 'step_issue_certificate.html', 'skippable': False},
]

TEMPLATE_DIR = "tracker/templates/tracker/wizard/steps/"
os.makedirs(TEMPLATE_DIR, exist_ok=True)  # Create directory if it doesn't exist

# Basic content for each step-specific template
STEP_TEMPLATE_CONTENT = """{%% extends "tracker/wizard/wizard_base.html" %%}
{%% load i18n %%}

{%% block wizard_title %%}{%% translate "%(step_name)s" %%}{%% endblock %%}

{%% block wizard_content %%}
<h2>{%% translate "Step %(step_order)s: %(step_name)s" %%}</h2>
<p><em>{%% translate "Description" %%}: %(step_description)s</em></p>
<p><em>{%% translate "Template" %%}: <code>%(template_filename)s</code></em></p>

<form method="post" hx-post="{{ request.path }}" hx-target="this" hx-swap="outerHTML" class="mt-4">
    {%% csrf_token %%}
    {{ wizard.management_form }}

    {%% if form.errors %%}
        <div class="alert alert-danger">
            {%% translate "Please correct the errors below." %%}
            {{ form.non_field_errors }}
            {%% for field in form %%}
                {%% if field.errors %%}
                    <div><strong>{{ field.label }}:</strong> {{ field.errors|striptags }}</div>
                {%% endif %%}
            {%% endfor %%}
        </div>
    {%% endif %%}

    {%% if form %%}
        {{ form.as_p }}
    {%% else %%}
        <p>{%% translate "No specific form fields are defined for this step yet." %%}</p>
    {%% endif %%}

    <div class="mt-4">
        {%% if wizard.steps.prev %%}
            <button type="submit" name="wizard_goto_step" value="{{ wizard.steps.prev }}" class="btn btn-secondary">{%% translate "Previous Step" %%}</button>
        {%% endif %%}
        <button type="submit" class="btn btn-primary">{%% translate "Save and Continue" %%}</button>
    </div>
</form>
{%% endblock %%}
"""

for step_data in FULL_WORKFLOW_STEPS_DATA:
    template_filename = step_data['template_name']
    filepath = os.path.join(TEMPLATE_DIR, template_filename)

    content_format_data = {
        'step_name': step_data['name'],
        'step_order': step_data['order'],
        'template_filename': template_filename,
        'step_description': step_data.get('description', 'No description provided.')
    }

    if not os.path.exists(filepath):  # Optional: only create if it doesn't exist
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(STEP_TEMPLATE_CONTENT % content_format_data)
        print(f"Created template: {filepath}")
    else:
        print(f"Skipped (already exists): {filepath}")

# Create _step_placeholder.html (using the manually defined content from above)
placeholder_filepath = os.path.join(TEMPLATE_DIR, "_step_placeholder.html")
if not os.path.exists(placeholder_filepath):
    with open(placeholder_filepath, "w", encoding="utf-8") as f:
        f.write("""{% extends "tracker/wizard/wizard_base.html" %}
{% load i18n %}

{% block wizard_title %}{% translate "Step Placeholder" %}{% endblock %}

{% block wizard_content %}
<h2>{% translate "Wizard Step Placeholder" %}</h2>

{% if view.get_current_step_definition %}
    <p>{% blocktranslate with template_name=view.get_current_step_definition.template_name|default:"[unknown_template_name]" %}This is a placeholder. The specific template (<code>{{ template_name }}</code>) for this step has not been fully implemented yet.{% endblocktranslate %}</p>
    <p><strong>{% translate "Step Name" %}:</strong> {{ view.get_current_step_definition.name }}</p>
    <p><strong>{% translate "Step Order" %}:</strong> {{ view.get_current_step_definition.step_order }}</p>
{% else %}
    <p>{% translate "This is a placeholder for a wizard step, but the step definition could not be loaded." %}</p>
{% endif %}

<form method="post" hx-post="{{ request.path }}" hx-target="this" hx-swap="outerHTML" class="mt-4">
    {% csrf_token %}
    {{ wizard.management_form }}

    {% if form.errors %}
        <div class="alert alert-danger">
            {% translate "Please correct the errors below." %}
        </div>
    {% endif %}

    {% if form %}
        {{ form.as_p }}
    {% else %}
        <p>{% translate "No specific form fields are defined for this placeholder step yet." %}</p>
    {% endif %}

    <div class="mt-4">
        {% if wizard.steps.prev %}
            <button type="submit" name="wizard_goto_step" value="{{ wizard.steps.prev }}" class="btn btn-secondary">{% translate "Previous Step" %}</button>
        {% endif %}
        <button type="submit" class="btn btn-primary">{% translate "Next Step (Placeholder Action)" %}</button>
    </div>
</form>
{% endblock %}
""")
    print(f"Created template: {placeholder_filepath}")
else:
    print(f"Skipped (already exists): {placeholder_filepath}")

# Create _step_render_error.html (using the manually defined content from above)
render_error_filepath = os.path.join(TEMPLATE_DIR, "_step_render_error.html")
if not os.path.exists(render_error_filepath):
    with open(render_error_filepath, "w", encoding="utf-8") as f:
        f.write("""{% extends "tracker/wizard/wizard_base.html" %}
{% load i18n %}

{% block wizard_title %}{% translate "Template Loading Error" %}{% endblock %}

{% block wizard_content %}
<h2>{% translate "Error Rendering Step" %}</h2>
<p>{% translate "Sorry, there was an error trying to render this wizard step. The specific template for this step, or any fallback templates, could not be found." %}</p>

{% if view.get_current_step_definition %}
    <p>{% blocktranslate with template_name=view.get_current_step_definition.template_name step_name=view.get_current_step_definition.name %}The system attempted to load the template '<code>{{ template_name }}</code>' for the step '{{ step_name }}'.{% endblocktranslate %}</p>
{% endif %}

<p>{% blocktranslate with directory="tracker/templates/tracker/wizard/steps/" %}Please ensure the correct template files exist in the <code>{{ directory }}</code> directory or contact support.{% endblocktranslate %}</p>

{% if wizard.steps.prev %}
<form method="post" class="mt-4">
    {% csrf_token %}
    {{ wizard.management_form }}
    <button type="submit" name="wizard_goto_step" value="{{ wizard.steps.prev }}" class="btn btn-secondary">{% translate "Go to Previous Step" %}</button>
</form>
{% endif %}
{% endblock %}
""")
    print(f"Created template: {render_error_filepath}")
else:
    print(f"Skipped (already exists): {render_error_filepath}")

print("Basic template creation process finished.")
print(f"Ensure your 'wizard_base.html' is correctly set up at 'tracker/templates/tracker/wizard/wizard_base.html'")