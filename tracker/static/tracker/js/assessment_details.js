
document.addEventListener('DOMContentLoaded', function () {
    // Smooth scroll for internal links in left navigation
    document.querySelectorAll('#leftNavAccordion a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');
            if (href.length > 1 && document.querySelector(href)) {
                e.preventDefault();
                const targetElement = document.querySelector(href);
                // Adjust scroll position if you have a fixed navbar
                const navbarHeight = document.querySelector('.navbar.fixed-top')?.offsetHeight || 0; // Get navbar height
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - navbarHeight - 10; // 10px buffer

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
                // Optionally update URL hash without page jump for better UX
                // history.pushState(null, null, href);
            }
        });
    });

    // Ensure accordions in the left nav behave as expected (only one open)
    // This is default Bootstrap accordion behavior if data-bs-parent is set correctly.
});


let workflowContext = {}; // Populated on DOMContentLoaded

document.addEventListener('DOMContentLoaded', function() {
    const assessmentId = {{ assessment.id|default:"null" }};
    const leftNav = document.getElementById('leftScrollNav');
    const mainContentArea = document.querySelector('.main-content-area');
    if (leftNav) {
        document.body.style.paddingLeft = leftNav.offsetWidth + 'px';
        mainContentArea.style.paddingLeft = '1rem';
    }

    const leftNavLinks = document.querySelectorAll('.left-nav-container .nav-link-scroll');
    const allContentCards = document.querySelectorAll('.primary-content-column > .content-card'); // Select all cards in the main column
    const workflowOverviewCard = document.getElementById('workflowOverviewCard');
    const currentStepInfoDisplay = document.getElementById('currentStepInfoDisplay');
    const currentStepTextEl = document.getElementById('currentStepText');
    const currentStepDescriptionEl = document.getElementById('currentStepDescription');
    const currentStepInstructionsEl = document.getElementById('currentStepInstructionsContainer');
    const topStepperSteps = document.querySelectorAll('.top-workflow-stepper .top-step');

    // Populate workflowContext from Django template tags
    try {
        workflowContext = {
            allDefinitions: JSON.parse('{{ workflow_steps_context.all_definitions|jsonify_queryset|escapejs|default:"[]" }}'),
            stepsMap: JSON.parse('{{ workflow_steps_context.steps_map|jsonify_stepsmap|escapejs|default:"{}" }}'),
            currentDefinitionId: "{{ workflow_steps_context.current_definition.id|default:'' }}",
        };
        console.log("Workflow Context Initialized:", workflowContext);
    } catch (e) {
        console.error("Error parsing workflow context JSON:", e);
        workflowContext = { allDefinitions: [], stepsMap: {}, currentDefinitionId: null };
    }

    function updateCurrentStepInfoDisplay(stepDefId) {
        console.log("Updating current step info display for stepDefId:", stepDefId);
        const stepDef = workflowContext.allDefinitions.find(d => d.pk == stepDefId);
        const stepInstance = workflowContext.stepsMap ? workflowContext.stepsMap[stepDefId] : null;
        console.log("Found stepDef:", stepDef);
        console.log("Found stepInstance:", stepInstance);

        if (stepDef) {
            let assignee = stepDef.fields.default_assigned_to || 'N/A';
            let assignee_display = assignee;
            if (assignee === 'Applicant') assignee_display = '{% translate "You" %}';
            else if (assignee === 'Assessor') assignee_display = '{% translate "Assessor" %}';
            else if (assignee === 'Both') assignee_display = '{% translate "Both" %}';

            let statusText = '{% translate "Current Step" %}';
            let statusDisplay = stepInstance ? (stepInstance.fields.status_display || stepInstance.fields.status) : '{% translate "Not Started" %}';

            if (stepInstance && stepInstance.fields.status === 'HelpNeeded') { statusText = '<span class="text-warning"><i class="fas fa-exclamation-triangle"></i> {% translate "Step Needing Help" %}</span>'; }
            else if (stepInstance && stepInstance.fields.status === 'Complete') { statusText = '{% translate "Step Complete" %}'; }
            else if (stepInstance && stepInstance.fields.status === 'InProgress') { statusText = '{% translate "Step In Progress" %}'; }

            currentStepTextEl.innerHTML = `<strong>${statusText} (${% translate "Action" %}: ${assignee_display}):</strong> ${stepDef.fields.step_order}. ${stepDef.fields.name}`;
            currentStepDescriptionEl.textContent = stepDef.fields.description || '';

            if (stepInstance && stepInstance.fields.instructions_for_applicant) { currentStepInstructionsEl.innerHTML = `<hr class="my-2"><small><strong>{% translate "Instructions" %}:</strong> ${stepInstance.fields.instructions_for_applicant.replace(/\n/g, '<br>')}</small>`; }
            else { currentStepInstructionsEl.innerHTML = ''; }
            currentStepInfoDisplay.classList.remove('d-none');
        } else {
            currentStepInfoDisplay.classList.add('d-none');
            console.log("No stepDef found for ID:", stepDefId, "Hiding current step info.");
        }
    }


    function showTargetContent(targetId, isWorkflowStepCard = false, stepDefIdForInfo = null) {
        console.log(`Showing target: ${targetId}, isWorkflow: ${isWorkflowStepCard}, stepDefId: ${stepDefIdForInfo}`);
        allContentCards.forEach(card => card.classList.add('d-none')); // Hide all first
        leftNavLinks.forEach(nav => nav.classList.remove('active')); // Deactivate all nav links
        topStepperSteps.forEach(s => s.classList.remove('current')); // Deactivate all top steps

        const targetCard = document.getElementById(targetId);
        if (targetCard) {
            targetCard.classList.remove('d-none'); // Show the target card
            const correspondingNavLink = document.querySelector(`.left-nav-container a[href="#${targetId}"], .left-nav-container a[data-target-card-id="${targetId}"]`);
            const correspondingTopStep = document.querySelector(`.top-workflow-stepper .top-step[data-step-id="${stepDefIdForInfo}"]`);

            if (correspondingNavLink) { correspondingNavLink.classList.add('active'); }
            else { console.warn("Could not find corresponding left nav link for target:", targetId); }

            if (isWorkflowStepCard) {
                // No vertical stepper links to mark as current anymore
                if(correspondingTopStep) correspondingTopStep.classList.add('current'); // Mark top step as current
                updateCurrentStepInfoDisplay(stepDefIdForInfo); // Update info display
            } else {
                 currentStepInfoDisplay.classList.add('d-none'); // Hide info display for non-workflow cards
            }

             // Scroll to the element
            const headerOffset = 80;
            const elementPosition = targetCard.getBoundingClientRect().top;
            const offsetPosition = elementPosition + window.pageYOffset - headerOffset;
            window.scrollTo({ top: offsetPosition, behavior: "smooth" });

        } else {
             console.warn("Target card not found:", targetId, "Defaulting to overview.");
             if (workflowOverviewCard) { // Fallback to overview
                 workflowOverviewCard.classList.remove('d-none');
                 const overviewNavLink = document.querySelector('.overview-nav-item');
                 if(overviewNavLink) overviewNavLink.classList.add('active');
             }
             currentStepInfoDisplay.classList.add('d-none'); // Hide info display
        }
    }

    // Click handler for Left Nav
    leftNavLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetAnchorId = this.getAttribute('href').substring(1);
            const workflowCardId = this.dataset.targetCardId;
            const stepDefIdForInfo = this.dataset.stepId;
            if (workflowCardId) { showTargetContent(workflowCardId, true, stepDefIdForInfo); }
            else { showTargetContent(targetAnchorId, false); }
        });
    });

     // Click handler for Top Stepper
     window.handleTopStepperClick = function(stepDefId, clickedElement) {
        const targetCardId = 'workflow-content-' + stepDefId;
        showTargetContent(targetCardId, true, stepDefId);
        // Sync left nav active state
        const leftNavLink = document.querySelector(`.left-nav-container a[data-target-card-id="${targetCardId}"]`);
        if(leftNavLink) {
             leftNavLinks.forEach(nav => nav.classList.remove('active'));
             leftNavLink.classList.add('active');
        } else { // If no direct workflow link, activate overview
             const overviewNavLink = document.querySelector('.overview-nav-item');
             if(overviewNavLink) {
                 leftNavLinks.forEach(nav => nav.classList.remove('active'));
                 overviewNavLink.classList.add('active');
             }
        }
     }

    // Initial Display Logic: Show Overview by default
    console.log("Initial Display: Defaulting to overview card.");
    showTargetContent('workflowOverviewCard', false);

    // Make "View" buttons on overview table work
    document.querySelectorAll('.overview-view-step-btn').forEach(button => {
        button.addEventListener('click', function() {
            const stepDefId = this.dataset.stepId;
            // Simulate click on the corresponding top step
            const topStepElement = document.querySelector(`.top-workflow-stepper .top-step[data-step-id="${stepDefId}"]`);
            if(topStepElement) {
                handleTopStepperClick(stepDefId, topStepElement);
            } else {
                console.warn("Could not find top step element for overview button click:", stepDefId);
            }
        });
    });

    // Intersection Observer (Updates Left Nav only)
    const sections = document.querySelectorAll('.primary-content-column > .content-card[id], .assessment-header-card[id]');
    const observerOptions = { root: null, rootMargin: '-25% 0px -65% 0px', threshold: 0.01 };
    const observer = new IntersectionObserver((entries, obs) => {
        let intersectingNavLinkFound = false;
        entries.forEach(entry => {
            if(intersectingNavLinkFound) return;
            let navLink;
            if (entry.target.classList.contains('workflow-main-content')) {
                 navLink = document.querySelector(`.left-nav-container a[data-target-card-id="${entry.target.id}"]`);
            } else {
                 navLink = document.querySelector(`.left-nav-container a[href="#${entry.target.id}"]`);
            }

            if (navLink && entry.isIntersecting) {
                leftNavLinks.forEach(link => link.classList.remove('active'));
                navLink.classList.add('active');
                intersectingNavLinkFound = true;
                // Don't update top stepper or current info on scroll, only on click
            }
        });
    }, observerOptions);
    sections.forEach(section => { observer.observe(section); });

    // --- AJAX Handlers ---
    // Tenable Scan Polling
    if (assessmentId) {
        const scanStatusDisplay = document.getElementById('scan-status-display'); const scanMessageDisplay = document.getElementById('scan-message-display'); const tenableRawStatusDisplay = document.getElementById('tenable-raw-status-display'); const scanProgressBar = document.getElementById('scan-progress-bar'); const scanLastTenableUpdate = document.getElementById('scan-last-tenable-update');
        function updateScanDisplay(data) { if (scanStatusDisplay) scanStatusDisplay.textContent = data.status_display || 'Unknown'; if (scanMessageDisplay) scanMessageDisplay.innerHTML = `<em>${data.message || '-'}</em>`; if (tenableRawStatusDisplay) tenableRawStatusDisplay.textContent = data.raw_tenable_status || '-'; let progressPercent = parseInt(data.progress) || 0; if (scanProgressBar) { scanProgressBar.style.width = progressPercent + '%'; scanProgressBar.textContent = progressPercent + '%'; scanProgressBar.setAttribute('aria-valuenow', progressPercent); scanProgressBar.classList.toggle('progress-bar-animated', progressPercent > 0 && progressPercent < 100); } if (scanLastTenableUpdate) { scanLastTenableUpdate.textContent = data.last_modified_tenable ? new Date(data.last_modified_tenable * 1000).toLocaleString() : 'N/A'; } }
        function fetchScanStatus() { fetch(`/assessment/${assessmentId}/tenable_scan_status/`).then(response => response.ok ? response.json() : response.json().then(err => Promise.reject(err))).then(data => data.error ? console.error('API Error:', data.error) : updateScanDisplay(data)).catch(error => { console.error('Fetch Error:', error); if (scanMessageDisplay) scanMessageDisplay.innerHTML = `<em>{% translate "Failed to connect for status update" %}: ${error.message || 'Unknown error'}</em>`; }); }
        fetchScanStatus(); setInterval(fetchScanStatus, 30000);
    }

    // Workflow Status Update
    function rebuildActionButtons(actionCell, newStatus, stepPk, assessmentPk) {
        const actionGroup = actionCell.querySelector('.workflow-action-group'); if (!actionGroup) return; actionGroup.innerHTML = ''; actionGroup.style.display = 'flex';
        if (newStatus === 'NotStarted') { actionGroup.innerHTML = `<button type="button" class="btn btn-outline-primary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as In Progress"><i class="fas fa-play"></i> Start</button><button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed"><i class="fas fa-question-circle"></i> Help</button><button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete"><i class="fas fa-check"></i> Done</button>`; }
        else if (newStatus === 'InProgress') { actionGroup.innerHTML = `<button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started"><i class="fas fa-undo"></i> Reset</button><button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed"><i class="fas fa-question-circle"></i> Help</button><button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete"><i class="fas fa-check"></i> Done</button>`; }
        else if (newStatus === 'HelpNeeded') { actionGroup.innerHTML = `<button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started"><i class="fas fa-undo"></i> Reset</button><button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete"><i class="fas fa-check"></i> Done</button>`; }
        else if (newStatus === 'Complete') { actionGroup.innerHTML = `<button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reopen (Set In Progress)"><i class="fas fa-pencil-alt"></i> Reopen</button>`; }
        actionGroup.querySelectorAll('.workflow-status-change-btn').forEach(btn => btn.addEventListener('click', handleStatusChangeClick));
    }
    function handleStatusChangeClick(event) {
        event.preventDefault();
        const buttonEl = event.currentTarget; const targetStatus = buttonEl.dataset.status, stepPk = buttonEl.dataset.stepPk, assessmentPk = buttonEl.dataset.assessmentPk; const csrfTokenEl = document.querySelector('input[name="csrfmiddlewaretoken"]'); if (!csrfTokenEl) { console.error("CSRF token not found!"); alert("Action failed: security token missing."); return; } const csrfToken = csrfTokenEl.value;
        let actionCell, itemCard, stepNumberText;
        // Determine context (Overview table or Detail card)
        if (buttonEl.classList.contains('overview-status-change-btn')) {
            actionCell = buttonEl.closest('td'); itemCard = buttonEl.closest('tr'); stepNumberText = itemCard.querySelector('td:first-child').innerText;
        } else {
            actionCell = buttonEl.closest('.workflow-item-actions-notes'); itemCard = buttonEl.closest('.workflow-item-card'); stepNumberText = itemCard ? (itemCard.querySelector('.workflow-item-header .step-order')?.innerText || '{% translate "this task" %}') : '{% translate "this task" %}';
        }
        const spinnerContainer = actionCell.querySelector('.spinner-container'); const successMsgContainer = actionCell.querySelector('.update-success-msg'); const actionGroup = actionCell.querySelector('.workflow-action-group');

        let confirmMsg = `{% translate "Change status for step" %} ${stepNumberText} {% translate "to" %} "${targetStatus}"?`; if (targetStatus === 'HelpNeeded') confirmMsg = `{% translate "Mark step" %} ${stepNumberText} {% translate "as needing help? This will notify the assessor." %}`; if (!confirm(confirmMsg)) return;
        let url = `{% url 'tracker:update_workflow_step_status' assessment_pk=0 step_pk=0 %}`.replace('0/workflow/step/0', `${assessmentPk}/workflow/step/${stepPk}`); if (spinnerContainer) spinnerContainer.style.display = 'block'; if (actionGroup) actionGroup.style.display = 'none'; if (successMsgContainer) successMsgContainer.style.display = 'none';
        buttonEl.disabled = true; // Disable button
        fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrfToken, 'Accept': 'application/json' }, body: `status=${targetStatus}` })
        .then(response => response.ok ? response.json() : response.json().then(err => Promise.reject(new Error(err.error || `Request failed: ${response.status}`))))
        .then(data => {
            if (data.success) {
                console.log("Status update success, reloading page...");
                addMessage('Status updated successfully!', 'success'); // Use helper
                setTimeout(() => { window.location.reload(); }, 1000); // Reload handles UI update
            } else { throw new Error(data.error || '{% translate "Update failed." %}'); }
        }).catch(error => { console.error('Error updating workflow step:', error); if (spinnerContainer) spinnerContainer.style.display = 'none'; if (actionGroup) actionGroup.style.display = 'flex'; addMessage(`{% translate "An error occurred" %}: ${error.message}`, 'danger'); buttonEl.disabled = false; /* Re-enable button on error */ });
    }
    document.querySelectorAll('.workflow-status-change-btn, .overview-status-change-btn').forEach(button => button.addEventListener('click', handleStatusChangeClick));

    // --- Countdown Timers ---
    function startCountdown(elementId, targetDateISO, expiredText) {
        const timerElement = document.getElementById(elementId); if (!timerElement || !targetDateISO) return; const countDownDate = new Date(targetDateISO).getTime(); if (isNaN(countDownDate)) { timerElement.textContent = "{% translate 'Invalid date' %}"; return; }
        const interval = setInterval(() => { const now = new Date().getTime(); const distance = countDownDate - now; if (distance < 0) { clearInterval(interval); timerElement.textContent = expiredText; return; } const days = Math.floor(distance / (1000*60*60*24)); const hours = Math.floor((distance % (1000*60*60*24)) / (1000*60*60)); const minutes = Math.floor((distance % (1000*60*60)) / (1000*60)); const seconds = Math.floor((distance % (1000*60)) / 1000); let ts = ""; if(days > 0) ts += days + "d "; if(hours > 0 || days > 0) ts += hours + "h "; if(minutes > 0 || hours > 0 || days > 0) ts += minutes + "m "; ts += seconds + "s"; timerElement.textContent = ts; }, 1000);
        const now = new Date().getTime(); const distance = countDownDate - now; if (distance < 0) { timerElement.textContent = expiredText; } else { const days = Math.floor(distance / (1000*60*60*24)); const hours = Math.floor((distance % (1000*60*60*24)) / (1000*60*60)); const minutes = Math.floor((distance % (1000*60*60)) / (1000*60)); const seconds = Math.floor((distance % (1000*60)) / 1000); let ts = ""; if(days > 0) ts += days + "d "; if(hours > 0 || days > 0) ts += hours + "h "; if(minutes > 0 || hours > 0 || days > 0) ts += minutes + "m "; ts += seconds + "s"; timerElement.textContent = ts; }
    }
    startCountdown('certExpiryCountdown', "{{ assessment.date_cert_expiry|date:'c' }}", "{% translate 'Expired' %}"); // Use ISO 8601 format
    startCountdown('cePlusWindowCountdown', "{{ ce_plus_window_end_date|date:'c' }}", "{% translate 'Window Closed' %}"); // Use ISO 8601 format

    // --- Add Message Function ---
    function addMessage(message, type = 'info') {
        const container = document.getElementById('messagesContainer'); if (!container) return; const alertDiv = document.createElement('div'); alertDiv.className = `alert alert-${type} alert-dismissible fade show m-2`; alertDiv.setAttribute('role', 'alert'); let iconClass = 'fa-info-circle'; if (type === 'success') iconClass = 'fa-check-circle'; if (type === 'warning') iconClass = 'fa-exclamation-triangle'; if (type === 'danger') iconClass = 'fa-times-circle';
        alertDiv.innerHTML = `<i class="fas ${iconClass} me-1"></i><span>${message}</span><button type="button" class="btn-close btn-sm" data-bs-dismiss="alert" aria-label="Close"></button>`;
        container.appendChild(alertDiv);
        // setTimeout(() => { const bsAlert = bootstrap.Alert.getOrCreateInstance(alertDiv); if (bsAlert) bsAlert.close(); }, 7000);
    }

    // --- Flatpickr ---
    const dateInputId = "{{ propose_date_form.proposed_date.id_for_label|default:'' }}";
    if (dateInputId) { const dateInput = document.getElementById(dateInputId); if(dateInput) { const unavailableDatesRaw = '{{ assessor_unavailable_dates_json|escapejs|default:"[]" }}'; try { const unavailableDates = JSON.parse(unavailableDatesRaw); flatpickr(dateInput, { dateFormat: "Y-m-d", minDate: "today", disable: unavailableDates }); } catch (e) { console.error("Error parsing unavailable dates for Flatpickr:", e, unavailableDatesRaw); flatpickr(dateInput, { dateFormat: "Y-m-d", minDate: "today" }); } } }

});

document.addEventListener('DOMContentLoaded', function() {
    // --- Helper Function to Rebuild Buttons ---
    function rebuildActionButtons(actionCell, newStatus, stepPk, assessmentPk) {
        const actionGroup = actionCell.querySelector('.workflow-action-group');
        if (!actionGroup) return;

        actionGroup.innerHTML = ''; // Clear existing
        actionGroup.style.display = 'flex'; // Ensure visible

        // Add buttons based on the new status for Client
        if (newStatus === 'NotStarted') {
            actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-primary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as In Progress">
                    <i class="fas fa-play"></i> {% translate "Start" %}
                </button>
                <button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed">
                    <i class="fas fa-question-circle"></i> {% translate "Help" %}
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> {% translate "Done" %}
                </button>
            `;
        } else if (newStatus === 'InProgress') {
             actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started">
                    <i class="fas fa-undo"></i> {% translate "Reset" %}
                </button>
                <button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed">
                    <i class="fas fa-question-circle"></i> {% translate "Help" %}
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> {% translate "Done" %}
                </button>
             `;
        } else if (newStatus === 'HelpNeeded') {
             actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started">
                    <i class="fas fa-undo"></i> {% translate "Reset" %}
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> {% translate "Done" %}
                </button>
             `;
        } else if (newStatus === 'Complete') {
             actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reopen (Set In Progress)">
                    <i class="fas fa-pencil-alt"></i> {% translate "Reopen" %}
                </button>
             `;
        } // Add else if for 'Skipped' if needed

        // Re-attach event listeners
        actionGroup.querySelectorAll('.workflow-status-change-btn').forEach(newButton => {
             newButton.addEventListener('click', handleStatusChangeClick);
        });
    }

    // --- Named Handler Function for Clicks (Corrected & Namespaced URL) ---
    function handleStatusChangeClick(event) {
        event.preventDefault();
        const buttonEl = event.currentTarget;
        const targetStatus = buttonEl.dataset.status;
        const stepPk = buttonEl.dataset.stepPk;
        const assessmentPk = buttonEl.dataset.assessmentPk;
        const csrfToken = document.querySelector('input[name="csrfmiddlewaretoken"]').value;
        const actionCell = buttonEl.closest('td'); // Targets the td containing the button
        if (!actionCell) {
            console.error("Could not find action cell for button:", buttonEl);
            return;
        }
        const spinnerContainer = actionCell.querySelector('.spinner-container');
        const successMsgContainer = actionCell.querySelector('.update-success-msg');
        const actionGroup = actionCell.querySelector('.workflow-action-group');

        // Corrected Confirmation Message
        const stepRow = buttonEl.closest('tr');
        const stepNumberText = stepRow ? (stepRow.querySelector('td:first-child')?.innerText || '{% translate "this step" %}') : '{% translate "this step" %}';
        let confirmMsg = `{% translate "Change status for step" %} ${stepNumberText} {% translate "to" %} "${targetStatus}"?`;
        if (targetStatus === 'HelpNeeded') confirmMsg = `{% translate "Mark step" %} ${stepNumberText} {% translate "as needing help? This will notify the assessor." %}`;
        if (!confirm(confirmMsg)) {
            return;
        }

        // Use namespaced URL from old template's JS
        const url = "{% url 'tracker:update_workflow_step_status' assessment_pk=0 step_pk=0 %}".replace('0/workflow/step/0', `${assessmentPk}/workflow/step/${stepPk}`);

        // Show loading state
        if (spinnerContainer) spinnerContainer.style.display = 'block';
        if (actionGroup) actionGroup.style.display = 'none';
        if (successMsgContainer) successMsgContainer.style.display = 'none';
        buttonEl.disabled = true; // Disable button while processing

        // Fetch request
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrfToken, 'Accept': 'application/json' },
            body: `status=${targetStatus}`
        })
        .then(response => {
            if (!response.ok) { return response.json().then(errData => { throw new Error(errData.error || `Request failed: ${response.status}`); }); }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // UI Updates (Badge, Completion Info, Row Highlighting)
                const statusCell = document.getElementById(`workflow-status-${stepPk}`);
                const completionCell = document.getElementById(`workflow-completion-${stepPk}`);
                const row = document.getElementById(`workflow-step-row-${stepPk}`);
                if (statusCell) {
                     let badgeClass = 'bg-light text-dark border'; let iconPrefix = '';
                     if (data.new_status === 'Complete') badgeClass = 'bg-success';
                     else if (data.new_status === 'InProgress') badgeClass = 'bg-info text-dark';
                     else if (data.new_status === 'HelpNeeded') { badgeClass = 'bg-warning text-dark'; iconPrefix = '<i class="fa-solid fa-triangle-exclamation me-1"></i>'; }
                     else if (data.new_status === 'Skipped') badgeClass = 'bg-secondary';
                     statusCell.innerHTML = `<span class="badge ${badgeClass}">${iconPrefix}${data.new_status_display || ''}</span>`;
                 }
                if (completionCell) {
                    let completionText = '';
                    if (data.completed_by) completionText += `{% translate "by" %} ${data.completed_by} `;
                    if (data.completed_at) { const d = new Date(data.completed_at); completionText += `{% translate "on" %} ${d.toLocaleDateString()}`; } // Use locale date string
                    completionCell.innerHTML = completionText;
                 }
                 if(row) {
                     row.classList.remove('table-info', 'table-warning');
                     if (data.new_status === 'HelpNeeded') row.classList.add('table-warning');
                     // Add logic for current step highlighting if needed
                 }
                // Hide spinner, show success message
                if (spinnerContainer) spinnerContainer.style.display = 'none';
                if (successMsgContainer) { successMsgContainer.style.display = 'block'; setTimeout(() => { successMsgContainer.style.display = 'none'; }, 2500); }
                // Rebuild action buttons
                rebuildActionButtons(actionCell, data.new_status, stepPk, assessmentPk);
                // Optionally reload or update other parts of the page
                setTimeout(() => { window.location.reload(); }, 750); // Simple reload to reflect all changes

            } else {
                 throw new Error(data.error || '{% translate "Update failed." %}');
            }
        })
        .catch(error => {
            console.error('Error updating workflow step:', error);
            if (spinnerContainer) spinnerContainer.style.display = 'none';
            if (actionGroup) actionGroup.style.display = 'flex'; // Show buttons again on error
            alert(`{% translate "An error occurred:" %} ${error.message}`);
            buttonEl.disabled = false; // Re-enable button on error
        });
    }

    // --- Initial Setup: Attach event listeners to workflow buttons ---
    document.querySelectorAll('.workflow-status-change-btn').forEach(button => {
        button.addEventListener('click', handleStatusChangeClick);
    });

    // --- Smooth Scroll JS from New Version ---
    document.querySelectorAll('#leftNavAccordion a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const href = this.getAttribute('href');
            if (href.length > 1 && document.querySelector(href)) {
                const targetElement = document.querySelector(href);
                const navbarHeight = document.querySelector('.navbar.fixed-top')?.offsetHeight || 60; // Estimate navbar height
                const elementPosition = targetElement.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - navbarHeight - 10; // 10px buffer

                window.scrollTo({ top: offsetPosition, behavior: 'smooth' });
            }
        });
    });

    // Add other JS like Flatpickr init if needed
});
