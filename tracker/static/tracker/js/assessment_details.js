// assessment_details.js

// Ensure this runs only once to avoid re-attaching listeners on HMR or other reloads
if (!window.assessmentDetailsInitialized) {
    window.assessmentDetailsInitialized = true;

    let workflowContext = {}; // To be populated from global vars set in HTML
    let updateWorkflowStepStatusUrl = ''; // To be populated from global var set in HTML via script tag

    // --- Helper Function to Add Messages to the DOM ---
    function addMessage(message, type = 'info') {
        const container = document.getElementById('messagesContainer');
        if (!container) {
            console.warn("messagesContainer not found. Cannot display message:", message);
            alert(`${type.toUpperCase()}: ${message}`); // Fallback
            return;
        }
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show m-2`;
        alertDiv.setAttribute('role', 'alert');
        let iconClass = 'fa-info-circle';
        if (type === 'success') iconClass = 'fa-check-circle';
        if (type === 'warning') iconClass = 'fa-exclamation-triangle';
        if (type === 'danger') iconClass = 'fa-times-circle';

        alertDiv.innerHTML = `<i class="fas ${iconClass} me-1"></i><span>${message}</span><button type="button" class="btn-close btn-sm" data-bs-dismiss="alert" aria-label="Close"></button>`;
        container.appendChild(alertDiv);

        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alertDiv);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 7000);
    }

    // --- Helper Function to Rebuild Action Buttons ---
    function rebuildActionButtons(actionCell, newStatus, stepPk, assessmentPk) {
        const actionGroup = actionCell.querySelector('.workflow-action-group');
        if (!actionGroup) {
            console.error("Could not find .workflow-action-group in", actionCell);
            return;
        }
        actionGroup.innerHTML = '';
        actionGroup.style.display = 'flex';
        if (newStatus === 'NotStarted') {
            actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-primary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as In Progress">
                    <i class="fas fa-play"></i> Start
                </button>
                <button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed">
                    <i class="fas fa-question-circle"></i> Help
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> Done
                </button>
            `;
        } else if (newStatus === 'InProgress') {
            actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started">
                    <i class="fas fa-undo"></i> Reset
                </button>
                <button type="button" class="btn btn-outline-warning btn-sm workflow-status-change-btn" data-status="HelpNeeded" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Help Needed">
                    <i class="fas fa-question-circle"></i> Help
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> Done
                </button>
            `;
        } else if (newStatus === 'HelpNeeded') {
            actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="NotStarted" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reset to Not Started">
                    <i class="fas fa-undo"></i> Reset
                </button>
                <button type="button" class="btn btn-outline-success btn-sm workflow-status-change-btn" data-status="Complete" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Mark as Complete">
                    <i class="fas fa-check"></i> Done
                </button>
            `;
        } else if (newStatus === 'Complete') {
            actionGroup.innerHTML = `
                <button type="button" class="btn btn-outline-secondary btn-sm workflow-status-change-btn" data-status="InProgress" data-step-pk="${stepPk}" data-assessment-pk="${assessmentPk}" title="Reopen (Set In Progress)">
                    <i class="fas fa-pencil-alt"></i> Reopen
                </button>
            `;
        }
        actionGroup.querySelectorAll('.workflow-status-change-btn').forEach(newButton => {
            newButton.addEventListener('click', handleWorkflowStatusChangeClick);
        });
    }

    // --- Function to Refresh Workflow Visual (More Robust) ---
    function refreshWorkflowVisual() {
        const visualContainer = document.getElementById('workflow-visual-container');
        if (!visualContainer) {
            console.warn("Workflow visual container (#workflow-visual-container) not found.");
            return;
        }
        const visualUrl = visualContainer.dataset.visualUrl;
        if (!visualUrl) {
            console.warn("Workflow visual URL not found in data-visual-url attribute of #workflow-visual-container.");
            return;
        }

        fetch(visualUrl + (visualUrl.includes('?') ? '&' : '?') + '_=' + new Date().getTime()) // Cache buster
            .then(response => {
                if (!response.ok) {
                    throw new Error(`Failed to fetch workflow visual: ${response.status} ${response.statusText}`);
                }
                return response.text();
            })
            .then(html => {
                visualContainer.innerHTML = html;
                console.log("Workflow visual refreshed with new HTML.");

                // Attempt to execute scripts within the new HTML
                // This is a common requirement for dynamically loaded content.
                const scripts = visualContainer.querySelectorAll("script");
                scripts.forEach(oldScript => {
                    const newScript = document.createElement("script");
                    // Copy attributes
                    Array.from(oldScript.attributes).forEach(attr => {
                        newScript.setAttribute(attr.name, attr.value);
                    });
                    // Copy content
                    if (oldScript.src) {
                        newScript.src = oldScript.src; // Re-fetch external scripts if any
                    } else {
                        newScript.appendChild(document.createTextNode(oldScript.innerHTML));
                    }
                    // Replace the old script tag with the new one to execute it
                    // or append it to the head/body if it's more appropriate for your scripts
                    oldScript.parentNode.replaceChild(newScript, oldScript);
                });
                 // If your visual has specific JS initialization functions that need to be called,
                 // you might need to call them here, e.g., if (typeof window.initWorkflowStepper === 'function') window.initWorkflowStepper();
            })
            .catch(error => {
                console.error("Error refreshing workflow visual:", error);
                addMessage("Could not refresh workflow progress visual. It may be out of sync.", "warning");
            });
    }


    // --- Event Handler for Workflow Status Change Button Clicks ---
    function handleWorkflowStatusChangeClick(event) {
        event.preventDefault();
        const buttonEl = event.currentTarget;
        const targetStatus = buttonEl.dataset.status;
        const stepPk = buttonEl.dataset.stepPk;
        const assessmentPk = buttonEl.dataset.assessmentPk;
        const csrfTokenEl = document.querySelector('input[name="csrfmiddlewaretoken"]');

        if (!csrfTokenEl) {
            console.error("CSRF token not found!");
            addMessage("Action failed: security token missing.", "danger");
            return;
        }
        const csrfToken = csrfTokenEl.value;

        const actionCell = buttonEl.closest('td');
        if (!actionCell) {
            console.error("Could not find action cell for button:", buttonEl);
            addMessage("An internal UI error occurred (cannot find action cell).", "danger");
            return;
        }

        const spinnerContainer = actionCell.querySelector('.spinner-container');
        const successMsgContainer = actionCell.querySelector('.update-success-msg');
        const actionGroup = actionCell.querySelector('.workflow-action-group');

        const stepRow = buttonEl.closest('tr');
        const stepNumberText = stepRow ? (stepRow.querySelector('td:first-child')?.innerText || 'this step') : 'this step';

        let confirmMsg = `Change status for step ${stepNumberText} to "${targetStatus}"?`;
        if (targetStatus === 'HelpNeeded') {
            confirmMsg = `Mark step ${stepNumberText} as needing help? This will notify the assessor.`;
        }

        if (!confirm(confirmMsg)) {
            return;
        }

        if (!updateWorkflowStepStatusUrl) {
            console.error("Workflow update URL is not defined. Check for the script tag with id 'updateWorkflowStepStatusUrl'.");
            addMessage("Configuration error: Update URL not set.", "danger");
            return;
        }
        const url = updateWorkflowStepStatusUrl.replace('0/workflow/step/0', `${assessmentPk}/workflow/step/${stepPk}`);

        if (spinnerContainer) spinnerContainer.style.display = 'block';
        if (actionGroup) actionGroup.style.display = 'none';
        if (successMsgContainer) successMsgContainer.style.display = 'none';
        buttonEl.disabled = true;

        fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-CSRFToken': csrfToken,
                'Accept': 'application/json'
            },
            body: `status=${targetStatus}`
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errData => {
                    throw new Error(errData.error || `Request failed: ${response.status} ${response.statusText}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                const statusCell = document.getElementById(`workflow-status-${stepPk}`);
                const completionCell = document.getElementById(`workflow-completion-${stepPk}`);
                const currentStepRow = document.getElementById(`workflow-step-row-${stepPk}`);

                if (statusCell) {
                    let badgeClass = 'bg-light text-dark border';
                    let iconPrefix = '';
                    if (data.new_status === 'Complete') badgeClass = 'bg-success';
                    else if (data.new_status === 'InProgress') badgeClass = 'bg-info text-dark';
                    else if (data.new_status === 'HelpNeeded') {
                        badgeClass = 'bg-warning text-dark';
                        iconPrefix = '<i class="fa-solid fa-triangle-exclamation me-1"></i>';
                    } else if (data.new_status === 'Skipped') badgeClass = 'bg-secondary';
                    statusCell.innerHTML = `<span class="badge ${badgeClass}">${iconPrefix}${data.new_status_display || data.new_status}</span>`;
                }

                if (completionCell) {
                    let completionText = '';
                    if (data.completed_by) completionText += `by ${data.completed_by} `;
                    if (data.completed_at) {
                        const d = new Date(data.completed_at);
                        completionText += `on ${d.toLocaleDateString()}`;
                    }
                    completionCell.innerHTML = `<small class="d-block text-muted mt-1">${completionText.trim()}</small>`;
                }

                if (currentStepRow) {
                    currentStepRow.classList.remove('table-info', 'table-warning');
                    if (data.new_status === 'HelpNeeded') {
                        currentStepRow.classList.add('table-warning');
                    }
                    if (data.is_current_step && data.new_status !== 'HelpNeeded') {
                         currentStepRow.classList.add('table-info');
                    }
                }

                if (spinnerContainer) spinnerContainer.style.display = 'none';
                if (successMsgContainer) {
                    successMsgContainer.style.display = 'block';
                    setTimeout(() => { successMsgContainer.style.display = 'none'; }, 2500);
                }

                rebuildActionButtons(actionCell, data.new_status, stepPk, assessmentPk);
                addMessage('Status updated successfully!', 'success');

                refreshWorkflowVisual();

                // setTimeout(() => { window.location.reload(); }, 750); // Keep commented for now

            } else {
                throw new Error(data.error || 'Update failed. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error updating workflow step:', error);
            if (spinnerContainer) spinnerContainer.style.display = 'none';
            if (actionGroup) actionGroup.style.display = 'flex';
            addMessage(`An error occurred: ${error.message}`, 'danger');
            buttonEl.disabled = false;
        });
    }

    // --- DOMContentLoaded Event Listener ---
    document.addEventListener('DOMContentLoaded', function () {
        const urlScriptTag = document.getElementById('updateWorkflowStepStatusUrl');
        if (urlScriptTag && urlScriptTag.textContent) {
            updateWorkflowStepStatusUrl = urlScriptTag.textContent.trim();
        } else {
            console.error("Critical: Script tag with id 'updateWorkflowStepStatusUrl' not found or empty.");
            addMessage("Page configuration error: Cannot determine update URL.", "danger");
        }

        document.querySelectorAll('#workflow-checklist-section .workflow-status-change-btn').forEach(button => {
            button.addEventListener('click', handleWorkflowStatusChangeClick);
        });

        document.querySelectorAll('#onPageNav a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                const href = this.getAttribute('href');
                if (href && href.length > 1 && href.startsWith("#")) {
                    const targetElement = document.querySelector(href);
                    if (targetElement) {
                        e.preventDefault();
                        const navbarHeight = document.querySelector('.navbar.fixed-top')?.offsetHeight || 60;
                        const elementPosition = targetElement.getBoundingClientRect().top;
                        const offsetPosition = elementPosition + window.pageYOffset - navbarHeight - 10;

                        window.scrollTo({ top: offsetPosition, behavior: 'smooth' });
                    } else {
                        console.warn("Smooth scroll target not found:", href);
                    }
                }
            });
        });

        try {
            if (window.__WORKFLOW_DEFS__ && window.__WORKFLOW_MAP__ && typeof window.__WORKFLOW_CURRENT__ !== 'undefined') {
                workflowContext = {
                    allDefinitions: JSON.parse(window.__WORKFLOW_DEFS__),
                    stepsMap: JSON.parse(window.__WORKFLOW_MAP__),
                    currentDefinitionId: window.__WORKFLOW_CURRENT__,
                };
            }
        } catch (e) {
            console.error("Error parsing workflow context JSON from global variables:", e);
            workflowContext = { allDefinitions: [], stepsMap: {}, currentDefinitionId: null };
        }
        console.log("Assessment Details JS Initialized.");
    });

} // End of window.assessmentDetailsInitialized
