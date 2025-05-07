from django.urls import path
from . import views


app_name = 'tracker'

urlpatterns = [
    # Dashboard/Home (Redirector)
    path('', views.dashboard, name='dashboard'),

    # Admin URLs
    path('manage/dashboard/', views.admin_dashboard, name='admin_dashboard'),  # Name stays the same
    path('manage/clients/', views.ClientListView.as_view(), name='client_list'),
    path('manage/clients/new/', views.ClientCreateView.as_view(), name='client_create'),
    path('manage/clients/<int:pk>/edit/', views.ClientUpdateView.as_view(), name='client_update'),
    path('manage/clients/<int:pk>/delete/', views.ClientDeleteView.as_view(), name='client_delete'),
    path('manage/clients/<int:client_pk>/validate_ch/', views.validate_client_companies_house,
         name='client_validate_ch'),
    path('manage/clients/<int:client_pk>/confirm_ch_update/', views.confirm_update_from_companies_house, name='client_confirm_ch_update'),
    path('manage/users/', views.UserListView.as_view(), name='user_list'),
    path('manage/users/new/', views.UserCreateView.as_view(), name='user_create'),
    path('manage/users/<int:pk>/edit/', views.UserUpdateView.as_view(), name='user_update'),
    path('manage/assessments/', views.AdminAssessmentListView.as_view(), name='admin_assessment_list'),
    path('manage/assessments/new/', views.AssessmentCreateView.as_view(), name='assessment_create'),
    # Admin can likely use assessor detail/update views if permissions allow or create specific ones
    path('manage/assessments/<int:pk>/delete/', views.AssessmentDeleteView.as_view(), name='assessment_delete'),

    path('manage/cloud-services/', views.CloudServiceDefinitionListView.as_view(),
         name='cloud_service_definition_list'),
    path('manage/cloud-services/new/', views.CloudServiceDefinitionCreateView.as_view(),
         name='cloud_service_definition_create'),
    path('manage/cloud-services/<int:pk>/edit/', views.CloudServiceDefinitionUpdateView.as_view(),
         name='cloud_service_definition_update'),
    path('manage/cloud-services/<int:pk>/delete/', views.CloudServiceDefinitionDeleteView.as_view(),
         name='cloud_service_definition_delete'),

    path('manage/operating-systems/', views.OperatingSystemListView.as_view(), name='os_list'),
    path('manage/operating-systems/new/', views.OperatingSystemCreateView.as_view(), name='os_create'),
    path('manage/operating-systems/<int:pk>/edit/', views.OperatingSystemUpdateView.as_view(), name='os_update'),
    path('manage/operating-systems/<int:pk>/delete/', views.OperatingSystemDeleteView.as_view(), name='os_delete'),
    # --- END NEW URLs ---

    # Assessor URLs
    path('assessor/dashboard/', views.assessor_dashboard, name='assessor_dashboard'),
    path('assessor/assessments/', views.AssessorAssessmentListView.as_view(), name='assessor_assessment_list'),
    path('assessor/assessments/<int:pk>/', views.AssessorAssessmentDetailView.as_view(), name='assessor_assessment_detail'),
    path('assessor/assessments/<int:pk>/update/', views.AssessmentUpdateStatusView.as_view(), name='assessment_update_status'),
    path('assessor/assessments/<int:assessment_pk>/upload_evidence/', views.EvidenceUploadView.as_view(), name='evidence_upload'),
    path('assessor/assessments/<int:assessment_pk>/calculate_sample/', views.calculate_and_save_sample, name='calculate_save_sample'),

    path('assessor/assessments/<int:assessment_pk>/networks/', views.NetworkListView.as_view(), name='network_list'),
    path('assessor/assessments/<int:assessment_pk>/networks/new/', views.NetworkCreateView.as_view(),
         name='network_create'),
    path('assessor/assessments/<int:assessment_pk>/networks/<int:pk>/edit/', views.NetworkUpdateView.as_view(),
         name='network_update'),
    path('assessor/assessments/<int:assessment_pk>/networks/<int:pk>/delete/', views.NetworkDeleteView.as_view(),
         name='network_delete'),
    path('assessor/assessments/<int:assessment_pk>/cloud-services/', views.AssessmentCloudServiceListView.as_view(),
         name='assessment_cloud_service_list'),
    path('assessor/assessments/<int:assessment_pk>/cloud-services/add/', views.AssessmentCloudServiceAddView.as_view(),
         name='assessment_cloud_service_add'),
    path('assessor/assessments/<int:assessment_pk>/cloud-services/<int:pk>/update/',
         views.AssessmentCloudServiceUpdateView.as_view(), name='assessment_cloud_service_update'),
    # View handles verification
    path('assessor/assessments/<int:assessment_pk>/cloud-services/<int:pk>/delete/',
         views.AssessmentCloudServiceDeleteView.as_view(), name='assessment_cloud_service_delete'),
    path('assessor/assessments/<int:assessment_pk>/external-ips/', views.ExternalIPListView.as_view(), name='externalip_list'),
    path('assessor/assessments/<int:assessment_pk>/external-ips/add/', views.ExternalIPCreateView.as_view(), name='externalip_create'),
    path('assessor/assessments/<int:assessment_pk>/external-ips/<int:pk>/edit/', views.ExternalIPUpdateView.as_view(), name='externalip_update'),
    path('assessor/assessments/<int:assessment_pk>/external-ips/<int:pk>/delete/', views.ExternalIPDeleteView.as_view(), name='externalip_delete'),
    path('assessor/assessments/<int:assessment_pk>/external-ips/<int:pk>/update-scan/', views.ExternalIPScanUpdateView.as_view(), name='externalip_update_scan'),

    path('assessor/assessments/<int:pk>/generate-agent-script/',
         views.GenerateAgentScriptView.as_view(),
         name='generate_agent_script'),

    path('assessor/assessments/upload_report/', views.UploadExtractReportView.as_view(), name='upload_extract_report'),
    # Client URLs

    path('assessor/availability/', views.AssessorAvailabilityListView.as_view(), name='assessor_availability_list'),
    # Assessor Manage View (GET/POST for add)
    path('assessor/availability/<int:pk>/delete/', views.DeleteAssessorAvailabilityView.as_view(),
         name='assessor_availability_delete'),  # Assessor Delete (POST)


    path('assessment/<int:pk>/trigger-tenable-client-tag-sync/',
         views.TriggerTenableClientTagSyncView.as_view(),
         name='trigger_tenable_client_tag_sync'), # Renamed task, but URL keeps same name for now

    # Add NEW Client-based trigger for asset tagging task
    path('manage/clients/<int:client_pk>/trigger-tenable-asset-tag/', # Uses client_pk
         views.TriggerTenableAssetTaggingView.as_view(), # View now uses client_pk
         name='trigger_tenable_asset_tagging'), # Name updated to reflect client base

    # Add NEW view for showing agents in a group
    path('manage/clients/<int:pk>/tenable-group/', # pk here is client_pk
         views.TenableGroupDetailView.as_view(),
         name='tenable_group_detail'),

    path('client/dashboard/', views.client_dashboard, name='client_dashboard'),
    path('client/assessments/', views.ClientAssessmentListView.as_view(), name='client_assessment_list'),
    path('client/assessments/<int:pk>/', views.ClientAssessmentDetailView.as_view(), name='client_assessment_detail'),
    path('client/assessments/<int:assessment_pk>/scope/', views.ScopeItemManageView.as_view(), name='client_scope_manage'),
    path('client/assessments/<int:assessment_pk>/scope/delete/<int:item_pk>/', views.scope_item_delete, name='client_scope_item_delete'),
    path('client/assessments/<int:assessment_pk>/scope/submit/', views.scope_submit, name='client_scope_submit'),

path('client/assessments/<int:pk>/generate-agent-script/', views.GenerateAgentScriptView.as_view(), name='client_generate_agent_script'),

    path('client/assessments/<int:assessment_pk>/scope/<int:pk>/edit/', views.ScopedItemUpdateView.as_view(), name='client_scope_item_edit'),

    path('client/assessments/<int:assessment_pk>/networks/', views.NetworkListView.as_view(), name='client_network_list'),
    path('client/assessments/<int:assessment_pk>/networks/new/', views.NetworkCreateView.as_view(), name='client_network_create'),
    path('client/assessments/<int:assessment_pk>/networks/<int:pk>/edit/', views.NetworkUpdateView.as_view(), name='client_network_update'),
    path('client/assessments/<int:assessment_pk>/networks/<int:pk>/delete/', views.NetworkDeleteView.as_view(), name='client_network_delete'),
    # --- END NEW Client Network URLs ---

    path('client/assessments/<int:assessment_pk>/cloud-services/', views.AssessmentCloudServiceListView.as_view(),
         name='client_assessment_cloud_service_list'),
    path('client/assessments/<int:assessment_pk>/cloud-services/add/', views.AssessmentCloudServiceAddView.as_view(),
         name='client_assessment_cloud_service_add'),
    path('client/assessments/<int:assessment_pk>/cloud-services/<int:pk>/update/',
         views.AssessmentCloudServiceUpdateView.as_view(), name='client_assessment_cloud_service_update'),
    # View handles proof upload
    path('client/assessments/<int:assessment_pk>/cloud-services/<int:pk>/delete/',
         views.AssessmentCloudServiceDeleteView.as_view(), name='client_assessment_cloud_service_delete'),

    path('client/assessments/<int:assessment_pk>/external-ips/', views.ExternalIPListView.as_view(),
         name='client_externalip_list'),
    path('client/assessments/<int:assessment_pk>/external-ips/add/', views.ExternalIPCreateView.as_view(),
         name='client_externalip_create'),
    path('client/assessments/<int:assessment_pk>/external-ips/<int:pk>/edit/', views.ExternalIPUpdateView.as_view(),
         name='client_externalip_update'),
    path('client/assessments/<int:assessment_pk>/external-ips/<int:pk>/delete/', views.ExternalIPDeleteView.as_view(),
         name='client_externalip_delete'),

    path('assessments/<int:assessment_pk>/workflow/step/<int:step_pk>/update_status/',
         views.update_workflow_step_status,
         name='update_workflow_step_status'),

    path('assessment/<int:pk>/trigger-tenable-asset-tag/',
         views.TriggerTenableAssetTaggingView.as_view(),
         name='trigger_tenable_asset_tagging'),

    path('assessment/<int:pk>/trigger-tenable-client-tag-sync/',
         views.TriggerTenableClientTagSyncView.as_view(),
         name='trigger_tenable_client_tag_sync'),

    path('assessment/<int:assessment_pk>/dates/propose/', views.ProposeAssessmentDateView.as_view(), name='propose_assessment_date'), # POST
    path('assessment/<int:assessment_pk>/dates/<int:option_pk>/update_status/', views.UpdateAssessmentDateStatusView.as_view(), name='update_assessment_date_status'), # POST
    path('assessment/<int:assessment_pk>/dates/<int:option_pk>/delete/', views.DeleteAssessmentDateOptionView.as_view(), name='delete_assessment_date_option'), # POST



    path('assessments/<int:assessment_pk>/map-agents/', views.MapAgentsView.as_view(), name='map_agents'),

    # Shared URLs
    path('evidence/<int:evidence_pk>/download/', views.download_evidence, name='download_evidence'),

    # Logout (if not using project-level auth URLs exclusively)
    path('logout/', views.LogoutView.as_view(), name='logout'), # Use project level preferably


    path('assessments/<int:assessment_pk>/launch-scan/', views.LaunchScanView.as_view(), name='launch_tenable_scan'),
]