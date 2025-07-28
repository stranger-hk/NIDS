from django.urls import path
from . import views

app_name = 'nids_app'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('start-capture/', views.start_capture, name='start_capture'),
    path('start-wlan-capture/', views.start_wlan_capture, name='start_wlan_capture'),  # Add this line
    path('stop-capture/', views.stop_capture, name='stop_capture'),
    path('get-stats/', views.get_stats, name='get_stats'),
    path('get-debug-info/', views.get_debug_info, name='get_debug_info'),
    path('test-capture/', views.test_capture, name='test_capture'),
    path('get-alerts/', views.get_alerts, name='get_alerts'),
    path('clear-alerts/', views.clear_alerts, name='clear_alerts'),
    path('upload-model/', views.upload_model, name='upload_model'),
    path('packets/', views.packet_list, name='packet_list'),
    path('packet/<int:packet_id>/', views.packet_detail, name='packet_detail'),
    path('flow/<int:flow_id>/', views.flow_detail, name='flow_detail'),
    path('get-packet-data/', views.get_packet_data, name='get_packet_data'),
    path('upload-csv/', views.upload_csv, name='upload_csv'),
    path('csv-analysis/<int:analysis_id>/', views.csv_analysis_detail, name='csv_analysis_detail'),
    path('get-csv-analysis/', views.get_csv_analysis, name='get_csv_analysis'),
]
