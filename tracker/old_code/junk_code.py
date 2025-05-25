@login_required
def view_scan_results_raw_old(request, assessment_pk, log_id):
    print(
        f"--- [RAW RESULTS VIEW DEBUG] --- Request for log_id: {log_id}, assessment_pk: {assessment_pk} by user: {request.user.username}")
    try:
        scan_log = get_object_or_404(
            TenableScanLog.objects.select_related('assessment__client'),
            id=log_id,
            assessment_id=assessment_pk
        )
        print(
            f"[RAW RESULTS VIEW DEBUG] Fetched scan_log: ID={scan_log.id}, DefID={scan_log.tenable_scan_definition_id}, RunUUID={scan_log.tenable_scan_run_uuid}")

        if not request.user.is_staff:
            if not (hasattr(scan_log.assessment, 'client') and hasattr(scan_log.assessment.client,
                                                                       'user_profile') and scan_log.assessment.client.user_profile.user == request.user):
                logger.warning(
                    f"User {request.user.username} permission denied for viewing raw results of scan_log {log_id} for assessment {assessment_pk}.")
                raise Http404("Permission denied or scan log not found.")

    except (TenableScanLog.DoesNotExist, ValueError, Http404) as e:
        print(
            f"[RAW RESULTS VIEW DEBUG] Scan log {log_id} (for assessment {assessment_pk}) not found or access denied. Error: {e}")
        logger.warning(
            f"Raw scan results: Scan log {log_id} (for assessment {assessment_pk}) not found or access denied for user {request.user.username}. Error: {e}")
        return HttpResponse("Scan log not found or access denied.", status=404)

    raw_vulnerabilities = []
    api_error_message = None
    scan_status_from_tenable_api = None
    tio = None

    if not scan_log.tenable_scan_definition_id or not scan_log.tenable_scan_run_uuid:
        api_error_message = "Scan log is missing necessary Tenable identifiers (Definition ID or Run UUID) to fetch results."
        print(f"[RAW RESULTS VIEW DEBUG] For log {scan_log.id}: {api_error_message}")
    else:
        print(
            f"[RAW RESULTS VIEW DEBUG] Has DefID and RunUUID. DefID: {scan_log.tenable_scan_definition_id}, RunUUID: {scan_log.tenable_scan_run_uuid}")
        try:
            print("[RAW RESULTS VIEW DEBUG] Attempting to initialize TenableIO client...")
            tio = get_tenable_io_client()
            if not tio:
                print(
                    "[RAW RESULTS VIEW DEBUG] TenableIO client initialization failed (get_tenable_io_client returned None).")
                raise ValueError("Tenable API client could not be initialized. Check configuration.")
            print("[RAW RESULTS VIEW DEBUG] TenableIO client initialized successfully.")

            try:
                print(
                    f"[RAW RESULTS VIEW DEBUG] Fetching history for DefID {scan_log.tenable_scan_definition_id}, to find RunUUID {scan_log.tenable_scan_run_uuid}")
                history_iterator = tio.scans.history(scan_id=scan_log.tenable_scan_definition_id)
                found_run_in_history = False

                for i, history_entry in enumerate(history_iterator):
                    print(
                        f"[RAW RESULTS VIEW DEBUG] Iterating history entry {i}: {json.dumps(history_entry, indent=2)}")

                    # CORRECTED KEY: Use 'scan_uuid' from the history_entry as per user's previous log output
                    entry_run_uuid = history_entry.get('scan_uuid')
                    if not entry_run_uuid:  # Fallback if 'scan_uuid' is not the key in some entries
                        entry_run_uuid = history_entry.get('uuid') or history_entry.get('history_uuid')

                    print(
                        f"[RAW RESULTS VIEW DEBUG] Comparing DB run UUID: '{str(scan_log.tenable_scan_run_uuid)}' with History Entry UUID: '{entry_run_uuid}' (Key used: 'scan_uuid' primarily)")

                    if entry_run_uuid and entry_run_uuid == str(scan_log.tenable_scan_run_uuid):
                        scan_status_from_tenable_api = history_entry.get('status')
                        print(
                            f"[RAW RESULTS VIEW DEBUG] Found matching scan run in history. Status: '{scan_status_from_tenable_api}'.")
                        found_run_in_history = True
                        break

                if not found_run_in_history:
                    print(
                        f"[RAW RESULTS VIEW DEBUG] Specific scan run {scan_log.tenable_scan_run_uuid} not found in history of def {scan_log.tenable_scan_definition_id}.")
                    scan_status_from_tenable_api = "RUN_NOT_FOUND_IN_HISTORY"

                if scan_status_from_tenable_api and scan_status_from_tenable_api.lower() == 'completed':
                    print(
                        f"[RAW RESULTS VIEW DEBUG] Scan run {scan_log.tenable_scan_run_uuid} is 'completed'. Fetching vulnerability details...")

                    # Use tio.scans.details() to get vulnerability information for a specific history_id
                    scan_run_details = tio.scans.details(
                        scan_id=scan_log.tenable_scan_definition_id,
                      #  history_id=str(scan_log.tenable_scan_run_uuid)  # history_id is the run UUID
                    )
                    print(
                        f"[RAW RESULTS VIEW DEBUG] Full scan_run_details response: {json.dumps(scan_run_details, indent=2)}")

                    # Vulnerabilities are often in a 'vulnerabilities' list or nested under 'hosts'
                    # The exact structure depends on the Tenable.io API response for scan details.
                    if 'vulnerabilities' in scan_run_details:
                        raw_vulnerabilities = scan_run_details['vulnerabilities']
                    elif 'hosts' in scan_run_details:
                        for host in scan_run_details.get('hosts', []):
                            raw_vulnerabilities.extend(host.get('vulnerabilities', []))
                    else:
                        print(
                            "[RAW RESULTS VIEW DEBUG] 'vulnerabilities' or 'hosts' key not found in scan_run_details response. Vulnerability data might be elsewhere or not present for this scan type/status.")
                        raw_vulnerabilities = []  # Ensure it's a list

                    print(
                        f"[RAW RESULTS VIEW DEBUG] Extracted {len(raw_vulnerabilities)} vulnerabilities for scan run {scan_log.tenable_scan_run_uuid}.")
                    if raw_vulnerabilities:
                        sample_size = min(3, len(raw_vulnerabilities))
                        print(f"[RAW RESULTS VIEW DEBUG] First {sample_size} vulnerability entries (sample):")
                        for i in range(sample_size):
                            print(f"--- Vuln {i + 1} ---")
                            print(json.dumps(raw_vulnerabilities[i], indent=2))

                elif scan_status_from_tenable_api and scan_status_from_tenable_api != "RUN_NOT_FOUND_IN_HISTORY":
                    api_error_message = f"Scan is not yet completed. Current Tenable status: '{scan_status_from_tenable_api}'. Raw vulnerability data can typically only be fetched for completed scans."
                    print(f"[RAW RESULTS VIEW DEBUG] {api_error_message}")
                elif scan_status_from_tenable_api == "RUN_NOT_FOUND_IN_HISTORY":
                    api_error_message = f"The specific scan run (UUID: {scan_log.tenable_scan_run_uuid}) was not found in the history of definition ID {scan_log.tenable_scan_definition_id}. It might be very old, purged, or the IDs are mismatched."
                    print(f"[RAW RESULTS VIEW DEBUG] {api_error_message}")
                else:
                    api_error_message = "Could not determine the status of the scan run from Tenable history. Unable to fetch vulnerabilities."
                    print(f"[RAW RESULTS VIEW DEBUG] {api_error_message}")

            except APIError as e:
                if e.code == 404:
                    api_error_message = f"Scan definition (ID: {scan_log.tenable_scan_definition_id}) or specific run (UUID: {scan_log.tenable_scan_run_uuid}) not found in Tenable. It may have been deleted."
                    print(f"[RAW RESULTS VIEW DEBUG] {api_error_message} - Tenable API Error: {e}")
                else:
                    api_error_message = f"Tenable API error while fetching scan status or vulnerabilities: {e.code} - {e.msg if hasattr(e, 'msg') else str(e)}"
                    logger.error(f"Raw results: {api_error_message}", exc_info=True)
            except Exception as e_fetch:
                api_error_message = f"An unexpected error occurred while fetching scan vulnerabilities: {str(e_fetch)}"
                logger.error(f"Raw results: {api_error_message}", exc_info=True)

        except ValueError as ve:
            api_error_message = str(ve)
            print(f"[RAW RESULTS VIEW DEBUG] Configuration or Value error for scan log {log_id}: {ve}")
            logger.error(f"Raw results: Configuration or Value error for scan log {log_id}: {ve}", exc_info=True)
        except Exception as e_client:
            api_error_message = f"An unexpected error occurred with the Tenable client: {str(e_client)}"
            print(f"[RAW RESULTS VIEW DEBUG] {api_error_message}")
            logger.error(f"Raw results: {api_error_message}", exc_info=True)

    print(
        f"[RAW RESULTS VIEW DEBUG] Final context: scan_log_id={scan_log.id}, vuln_count={len(raw_vulnerabilities)}, api_error='{api_error_message}', tenable_status='{scan_status_from_tenable_api}'")
    context = {
        'scan_log': scan_log,
        'raw_vulnerabilities_json': json.dumps(raw_vulnerabilities, indent=2) if raw_vulnerabilities else "[]",
        'vulnerability_count': len(raw_vulnerabilities),
        'api_error_message': api_error_message,
        'scan_status_from_tenable': scan_status_from_tenable_api,
        'assessment': scan_log.assessment
    }
    return render(request, 'tracker/client/client_scan_results_raw.html', context)


# CHANGES BEGIN - GEMINI-2025-05-17 - Simplified select_related in view_scan_results_raw
@login_required
def view_scan_results_raw_older(request, assessment_pk, log_id):
    """
    Proof-of-concept: pull raw vulnerabilities from TenableIO and print to console.
    """
    # 1. Init client
    tio = get_tenable_io_client()
    if not tio:
        print("ERROR: Could not initialize TenableIO client")
        return HttpResponse("Client init failed", status=500)

    try:
        # —— Option A: only vulns on assets tagged "TEST WE"
        tag_iterator = tio.exports.vulns(
            tags=[('Asset Group', 'TEST WE')]
        )
        print("[POC] Vulns for tag Asset Group=TEST WE:")
        for v in tag_iterator:
            print(json.dumps(v, indent=2))

        # —— Option B: only vulns from a single scan UUID (hardcoded for testing)
        scan_uuid = '0ebbdbe2-a728-48db-9923-aad399c84585'
        scan_iterator = tio.exports.vulns(scan_uuid=scan_uuid)
        all_scan_vulns = []
        print(f"[POC] Vulns from scan {scan_uuid}:")
        for v in scan_iterator:
            print(json.dumps(v, indent=2))
            all_scan_vulns.append(v)

        # ——— Save to MEDIA_ROOT/scan_reports/… ———
        reports_dir = os.path.join(settings.MEDIA_ROOT, 'scan_reports')
        os.makedirs(reports_dir, exist_ok=True)

        timestamp = timezone.now().strftime("%Y%m%d%H%M")
        filename = f"{timestamp}_{scan_uuid}.json"
        filepath = os.path.join(reports_dir, filename)

        with open(filepath, 'w') as fp:
            json.dump(all_scan_vulns, fp, indent=2)

        print(f"[POC] Saved {len(all_scan_vulns)} records to {filepath}")

        # Public URL (assuming MEDIA_URL is correctly served)
        file_url = f"{settings.MEDIA_URL}scan_reports/{filename}"

        return HttpResponse(
            f"Exported {len(all_scan_vulns)} vulnerabilities to:\n{filepath}\n\n"
            f"Accessible at: {file_url}",
            content_type="text/plain"
        )

    except Exception as e:
        print(f"ERROR fetching from TenableIO: {e}")
        return HttpResponse(f"Error: {e}", status=500)



class LoadAssessmentCardContentViewOlder(ClientRequiredMixin, View):
    """
    Handles HTMX requests to load different content cards.
    Context logic is delegated to functions in step_views.py.
    """

    CONTEXT_FUNCTION_MAP = {
        # All values are now STRING NAMES of functions in step_views.py
        'tracker/partials/client_scope_summary.html': 'get_scope_summary_context',
        'tracker/partials/client_networks_card.html': 'get_networks_context',
        'tracker/partials/client_cloud_services_card.html': 'get_cloud_services_context',
        'tracker/partials/client_external_ips_card.html': 'get_external_ips_context',
        'tracker/partials/client_date_scheduling.html': 'get_date_scheduling_context',  # Original date scheduling
        'tracker/partials/client_ce_plus_sample_card.html': 'get_ce_plus_sample_context',
        'tracker/partials/client_downloads_card.html': 'get_downloads_context',
        'tracker/partials/client_assessment_scan_history_card.html': 'get_scan_history_context',

        # New step partial
        'tracker/partials/step/step_agree_date.html': 'get_step_agree_date_context',
        # Add more for other steps:
        # 'tracker/partials/step/step_define_user_devices.html': 'get_define_user_devices_context',
    }

    def get_assessment_and_step(self, assessment_pk, step_pk):
        profile = self.request.user.userprofile  # type: ignore
        if not profile or not profile.client:
            logger.error(f"User {self.request.user.username} has no client profile or client link.")
            raise PermissionDenied("User has no associated client.")
        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if assessment.client != profile.client:
            logger.warning(
                f"Permission Denied: User {self.request.user.username} ClientID {profile.client.id if profile.client else 'N/A'} "
                f"vs AssessmentClientID {assessment.client.id if assessment.client else 'N/A'}"
            )
            raise Http404("Assessment not found or permission denied.")
        workflow_step = get_object_or_404(
            AssessmentWorkflowStep.objects.select_related('step_definition'),
            pk=step_pk, assessment=assessment
        )
        return assessment, workflow_step

    def get(self, request, assessment_pk, step_pk):
        if not request.htmx:
            return HttpResponseBadRequest("This endpoint is for HTMX requests only.")
        try:
            assessment, workflow_step = self.get_assessment_and_step(assessment_pk, step_pk)
        except (Http404, PermissionDenied) as e:
            logger.warning(
                f"HTMX card load: Error fetching assessment/step - {type(e).__name__} for assess_pk={assessment_pk}, step_pk={step_pk}, user={request.user.username}")
            status_code = 404 if isinstance(e, Http404) else 403
            return HttpResponse(f"Error: {str(e)}", status=status_code)

        card_template = workflow_step.step_definition.card_template_path
        if not card_template:
            logger.warning(f"No card template for step: {workflow_step.step_definition.name}")
            card_template = 'tracker/partials/_default_card_content.html'
            context = {
                'assessment': assessment, 'workflow_step': workflow_step,
                'error_message': _("Content card not configured for this step in the database.")
            }
            try:
                html_content = render_to_string(card_template, context, request=request)
            except Exception as e_render:
                logger.error(f"Error rendering default card template {card_template}: {e_render}", exc_info=True)
                html_content = "<div class='alert alert-danger'>Error rendering default content.</div>"
            response = HttpResponse(html_content)
            response['HX-Trigger-After-Swap'] = json.dumps(
                {'updateNavActiveState': {'stepPk': step_pk}})  # type: ignore
            return response

        base_context = {'assessment': assessment, 'workflow_step': workflow_step, 'user': request.user}

        function_name_str = self.CONTEXT_FUNCTION_MAP.get(card_template)
        specific_context = {}

        if function_name_str and hasattr(step_views, function_name_str):
            context_function = getattr(step_views, function_name_str)
            try:
                specific_context = context_function(assessment, workflow_step, request)
            except Exception as e_context:
                logger.error(
                    f"Error calling context function '{function_name_str}' from step_views for template '{card_template}': {e_context}",
                    exc_info=True)
                base_context['card_error'] = _("Error preparing dynamic content for this card.")
        elif function_name_str:
            logger.error(
                f"Context function '{function_name_str}' mapped for '{card_template}' but NOT found in step_views module.")
            base_context['card_error'] = _("Card configuration error (server: context function missing).")
        else:
            logger.info(
                f"No specific context function mapped in CONTEXT_FUNCTION_MAP for template '{card_template}'. Using base context only.")

        base_context.update(specific_context)

        try:
            html_content = render_to_string(card_template, base_context, request=request)
        except Exception as e_render_main:
            logger.error(
                f"Error rendering main card template '{card_template}' for step {workflow_step.step_definition.name} (Assessment: {assessment.pk}): {e_render_main}",
                exc_info=True)
            default_error_context = {
                'assessment': assessment, 'workflow_step': workflow_step,
                'error_message': _("Error rendering this content card. An administrator has been notified.")
            }
            html_content = render_to_string('tracker/partials/_default_card_content.html', default_error_context,
                                            request=request)

        response = HttpResponse(html_content)
        response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'stepPk': step_pk}})  # type: ignore
        return response
class LoadAssessmentCardContentViewOld(ClientRequiredMixin, View):
    """
    Handles HTMX requests to load different content cards for the
    client assessment detail page using database-driven template paths.
    """

    CONTEXT_FUNCTION_MAP = {
        'tracker/partials/client_scope_summary.html': '_get_scope_summary_context',
        'tracker/partials/client_networks_card.html': '_get_networks_context',
        'tracker/partials/client_cloud_services_card.html': '_get_cloud_services_context',
        'tracker/partials/client_external_ips_card.html': '_get_external_ips_context',
        'tracker/partials/client_date_scheduling.html': '_get_date_scheduling_context',
        'tracker/partials/client_ce_plus_sample_card.html': '_get_ce_plus_sample_context',
        'tracker/partials/client_downloads_card.html': '_get_downloads_context',
        'tracker/partials/client_assessment_scan_history_card.html': '_get_scan_history_context',
        # Add other template paths from your card_template_path field and their corresponding context functions.
        # If a card template needs no special context beyond 'assessment' and 'workflow_step',
        # it doesn't need an entry here if the view handles that gracefully.
    }

    def get_assessment_and_step(self, assessment_pk, step_pk):
        profile = self.request.user.userprofile
        # Ensure client profile exists, ClientRequiredMixin should ideally handle this.
        if not profile or not profile.client:
            logger.error(f"User {self.request.user.username} has no client profile or client link.")
            raise PermissionDenied("User has no associated client.")

        assessment = get_object_or_404(Assessment, pk=assessment_pk)
        if assessment.client != profile.client:
            logger.warning(
                f"Permission Denied: User {self.request.user.username} (Client ID: {profile.client.id}) "
                f"attempted to load card for assessment {assessment_pk} (Client ID: {assessment.client.id})."
            )
            raise Http404(
                "Assessment not found or permission denied.")  # Changed from PermissionDenied to Http404 for consistency

        workflow_step = get_object_or_404(
            AssessmentWorkflowStep.objects.select_related('step_definition'),
            pk=step_pk,
            assessment=assessment
        )
        return assessment, workflow_step

    def get(self, request, assessment_pk, step_pk):
        if not request.htmx:
            logger.warning(
                f"Non-HTMX request to LoadAssessmentCardContentView for assess_pk={assessment_pk}, step_pk={step_pk}")
            return HttpResponseBadRequest("This endpoint is for HTMX requests only.")

        try:
            assessment, workflow_step = self.get_assessment_and_step(assessment_pk, step_pk)
        except Http404:  # Catches Http404 from get_assessment_and_step
            logger.warning(
                f"HTMX card load: Http404 for assessment_pk={assessment_pk}, step_pk={step_pk}, user={request.user.username}")
            return HttpResponse("Error: Assessment or step not found or permission denied.", status=404)
        except PermissionDenied:  # Catch PermissionDenied from get_assessment_and_step
            logger.warning(
                f"HTMX card load: PermissionDenied for assessment_pk={assessment_pk}, step_pk={step_pk}, user={request.user.username}")
            return HttpResponse("Error: Permission denied.", status=403)

        card_template = workflow_step.step_definition.card_template_path

        if not card_template:
            logger.warning(
                f"No card template path defined in DB for step: {workflow_step.step_definition.name} (ID: {workflow_step.step_definition.pk}), Assessment: {assessment.pk}")
            card_template = 'tracker/partials/_default_card_content.html'
            context = {
                'assessment': assessment,
                'workflow_step': workflow_step,
                'error_message': _("Content card not configured for this step in the database.")
            }
            try:
                html_content = render_to_string(card_template, context, request=request)
            except Exception as e_render:
                logger.error(f"Error rendering default card template {card_template}: {e_render}", exc_info=True)
                html_content = "<div class='alert alert-danger'>Error rendering default content.</div>"

            response = HttpResponse(html_content)
            response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'stepPk': step_pk}})
            return response

        base_context = {'assessment': assessment, 'workflow_step': workflow_step, 'user': request.user}

        context_func_name = self.CONTEXT_FUNCTION_MAP.get(card_template)

        if context_func_name and hasattr(self, context_func_name):
            context_func = getattr(self, context_func_name)
            try:
                specific_context = context_func(assessment, workflow_step, request)
                base_context.update(specific_context)
            except Exception as e_context:
                logger.error(
                    f"Error calling context function {context_func_name} for template {card_template} (Assessment: {assessment.pk}, Step: {workflow_step.pk}): {e_context}",
                    exc_info=True)
                base_context['card_error'] = _("Error preparing dynamic content for this card.")
        elif context_func_name:
            logger.error(
                f"Context function '{context_func_name}' mapped for '{card_template}' but not found on LoadAssessmentCardContentView class.")
            base_context['card_error'] = _("Card configuration error (server: context function missing).")
        else:
            logger.info(
                f"No specific context function mapped in CONTEXT_FUNCTION_MAP for template '{card_template}' (Step: {workflow_step.step_definition.name}, Assessment: {assessment.pk}). Using base context only.")

        try:
            html_content = render_to_string(card_template, base_context, request=request)
        except Exception as e_render_main:
            logger.error(
                f"Error rendering main card template '{card_template}' for step {workflow_step.step_definition.name} (Assessment: {assessment.pk}): {e_render_main}",
                exc_info=True)
            # Fallback to rendering the default error card content if main card fails
            default_error_context = {
                'assessment': assessment,
                'workflow_step': workflow_step,
                'error_message': _("Error rendering this content card. An administrator has been notified.")
            }
            html_content = render_to_string('tracker/partials/_default_card_content.html', default_error_context,
                                            request=request)

        # [DEBUG] Print statement for successful card rendering
        # print(f"[DEBUG LoadAssessmentCardContentView GET {assessment.pk} Step {workflow_step.pk}] Rendered card '{card_template}' for step '{workflow_step.step_definition.name}' at {timezone.now()}")

        response = HttpResponse(html_content)
        response['HX-Trigger-After-Swap'] = json.dumps({'updateNavActiveState': {'stepPk': step_pk}})
        return response

    # --- Context gathering methods ---
    # These methods prepare context for specific cards. They should mirror the
    # logic from ClientAssessmentDetailView or use shared utility functions.

    def _get_scope_summary_context(self, assessment, workflow_step, request):
        all_scope_items = list(assessment.scoped_items.select_related('operating_system', 'network').all())
        scope_summary_data = defaultdict(
            lambda: {'count': 0, 'os_types': defaultdict(lambda: {'count': 0, 'is_supported': True, 'is_eol': False})})
        scope_summary_data['total_items'] = len(all_scope_items)
        scope_summary_data['has_unsupported_or_eol'] = False
        today = date.today()

        for item in all_scope_items:
            os_name_str, vendor_hint_str, is_supported, is_eol = "Unknown OS", "unknown", True, False
            if item.operating_system:
                os_name_str = str(item.operating_system)
                vendor_hint_str = item.operating_system.vendor.lower() if item.operating_system.vendor else "unknown"
                is_supported = item.operating_system.is_supported
                if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                    is_eol = True
                    is_supported = False  # EOL implies not supported for CE+
            if not is_supported or is_eol:
                scope_summary_data['has_unsupported_or_eol'] = True

            os_info_key = (os_name_str, vendor_hint_str)
            cat_map = {
                'Server': 'servers', 'Laptop': 'workstations', 'Desktop': 'workstations',
                'Mobile': 'mobiles', 'Firewall': 'network_devices', 'Router': 'network_devices',
                'Switch': 'network_devices', 'IP': 'network_devices', 'SaaS': 'cloud_services',
                'PaaS': 'cloud_services', 'IaaS': 'cloud_services'
            }
            category_key = cat_map.get(item.item_type, 'other')
            group_dict = scope_summary_data[category_key]
            group_dict['count'] += 1
            os_data = group_dict['os_types'][os_info_key]
            os_data['count'] += 1
            if not is_supported: os_data['is_supported'] = False
            if is_eol: os_data['is_eol'] = True

        final_scope_summary = {
            'total_items': scope_summary_data['total_items'],
            'has_unsupported_or_eol': scope_summary_data['has_unsupported_or_eol']
        }
        for category, data_dict in scope_summary_data.items():
            if category not in ['total_items', 'has_unsupported_or_eol']:
                final_scope_summary[category] = {
                    'count': data_dict['count'],
                    'os_types': {key_to_str(key): dict(val) for key, val in data_dict['os_types'].items()}
                }
        return {
            'scope_summary': final_scope_summary,
            'can_edit_scope': assessment.status == 'Scoping_Client',  # Example permission
        }

    def _get_networks_context(self, assessment, workflow_step, request):
        # client_networks_card.html likely iterates assessment.networks
        return {'networks': assessment.networks.all()}  # Pass the queryset

    def _get_cloud_services_context(self, assessment, workflow_step, request):
        # client_cloud_services_card.html likely iterates assessment.assessment_cloud_services
        return {
            'assessment_cloud_services': assessment.assessment_cloud_services.select_related('cloud_service_definition',
                                                                                             'verified_by').all()
        }

    def _get_external_ips_context(self, assessment, workflow_step, request):
        # client_external_ips_card.html likely iterates assessment.external_ips
        return {'external_ips': assessment.external_ips.all()}

    def _get_date_scheduling_context(self, assessment, workflow_step, request):
        date_options = list(assessment.date_options.select_related('proposed_by').order_by('proposed_date'))
        confirmed_date_option = next(
            (opt for opt in date_options if opt.status == AssessmentDateOption.Status.CONFIRMED), None)
        display_confirmed_assessment_date = confirmed_date_option.proposed_date if confirmed_date_option else assessment.date_start

        # Simplified logic from ClientAssessmentDetailView
        # Ensure Assessment model has these statuses if you use them
        editable_statuses = ['Draft', 'Date_Negotiation', 'Scoping_Client', 'Scoping_Review']
        assessment_allows_date_management = assessment.status in editable_statuses and not confirmed_date_option

        unavailable_dates_json = "[]"
        if assessment.assessor:
            unavailable_dates = AssessorAvailability.objects.filter(
                assessor=assessment.assessor
            ).values_list('unavailable_date', flat=True)
            unavailable_dates_str = [d.strftime('%Y-%m-%d') for d in unavailable_dates]
            unavailable_dates_json = json.dumps(unavailable_dates_str)

        return {
            'assessment_date_options': date_options,
            'display_confirmed_assessment_date': display_confirmed_assessment_date,
            'assessment_allows_date_management': assessment_allows_date_management,
            'propose_date_form': AssessmentDateOptionForm(assessment=assessment, user=request.user),
            'assessor_unavailable_dates_json': unavailable_dates_json,
            'ce_plus_window_start_date': assessment.date_ce_passed,
            'ce_plus_window_end_date': assessment.ce_plus_window_end_date,  # Property on Assessment model
            'confirmed_assessment_date': display_confirmed_assessment_date,  # For consistency in template
        }

    def _get_ce_plus_sample_context(self, assessment, workflow_step, request):
        today = date.today()
        # Use prefetch_related from assessment object if already fetched in main view, or select_related here.
        all_scope_items = list(assessment.scoped_items.select_related('operating_system', 'network').all())
        ce_plus_sample_items_list = [item for item in all_scope_items if item.is_in_ce_plus_sample]

        sample_items_with_status = []
        if assessment.assessment_type == 'CE+':
            for item in ce_plus_sample_items_list:
                item.eol_status = 'ok'  # Default
                if item.operating_system:
                    if not item.operating_system.is_supported:
                        item.eol_status = 'unsupported'
                    if item.operating_system.end_of_life_date and item.operating_system.end_of_life_date < today:
                        item.eol_status = 'eol'
                elif item.item_type not in ['SaaS', 'PaaS', 'IaaS', 'Other', 'IP']:  # Types usually without OS EOL
                    item.eol_status = 'unknown'  # Or 'n/a'
                sample_items_with_status.append(item)
        return {
            'has_ce_plus_sample': assessment.assessment_type == 'CE+' and bool(ce_plus_sample_items_list),
            'ce_plus_sample_items': sorted(sample_items_with_status,
                                           key=lambda x: (x.item_type, str(x.operating_system or ''))),
            'scan_launch_status': assessment.can_launch_ce_plus_scan(),  # Method on Assessment model
        }

    def _get_downloads_context(self, assessment, workflow_step, request):
        # client_downloads_card.html likely iterates assessment.evidence_files
        return {
            'downloadable_evidence': assessment.evidence_files.select_related('uploaded_by').all()
        }

    def _get_scan_history_context(self, assessment, workflow_step, request):
        # client_assessment_scan_history_card.html likely iterates assessment.tenable_scan_logs
        return {
            'tenable_scan_logs': assessment.tenable_scan_logs.select_related('assessment'
                                                                             # , 'initiated_by' - if you add this field
                                                                             ).order_by('-created_at')
        }
