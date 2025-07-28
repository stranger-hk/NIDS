import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.conf import settings
from django.utils import timezone
from django.db import models
import threading
import os

# Use absolute imports
try:
    from nids_app.models import NetworkFlow, Alert, SystemStats, PacketDetail, CSVAnalysis, CSVFlowResult
    from nids_app.packet_capture import packet_capture
    from nids_app.csv_analyzer import csv_analyzer
except ImportError:
    # Fallback to relative imports
    from .models import NetworkFlow, Alert, SystemStats, PacketDetail, CSVAnalysis, CSVFlowResult
    from .packet_capture import packet_capture
    from .csv_analyzer import csv_analyzer

def dashboard(request):
    """Main dashboard view"""
    # Get packet and flow counts
    total_packets = PacketDetail.objects.count()
    total_flows = NetworkFlow.objects.count()
    total_alerts = Alert.objects.count()
    
    # Get recent alerts
    recent_alerts = Alert.objects.filter(acknowledged=False)[:10]
    
    # Get recent CSV analyses
    recent_analyses = CSVAnalysis.objects.all()[:5]
    
    context = {
        'total_packets': total_packets,
        'total_flows': total_flows,
        'total_alerts': total_alerts,
        'recent_alerts': recent_alerts,
        'recent_analyses': recent_analyses,
        'is_capturing': packet_capture.is_capturing,
    }
    return render(request, 'nids_app/dashboard.html', context)

@csrf_exempt
@require_http_methods(["POST"])
def start_capture(request):
    """Start packet capture"""
    try:
        data = json.loads(request.body) if request.body else {}
        interface = data.get('interface', None)
        
        # If no interface specified, try to use wlan0 if available
        if not interface:
            available_interfaces = packet_capture.debug_info.get('available_interfaces', [])
            if 'wlan0' in available_interfaces:
                interface = 'wlan0'
                print(f"🔧 Forcing interface to wlan0 for wireless capture")
        
        success = packet_capture.start_capture(interface)
        
        return JsonResponse({
            'success': success,
            'message': f'Packet capture started on {interface}' if success else 'Failed to start capture',
            'interface_used': interface,
            'debug_info': packet_capture.get_debug_info()
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}',
            'debug_info': packet_capture.get_debug_info()
        })

@csrf_exempt
@require_http_methods(["POST"])
def start_wlan_capture(request):
    """Start packet capture specifically on wlan0"""
    try:
        available_interfaces = packet_capture.debug_info.get('available_interfaces', [])
        
        if 'wlan0' not in available_interfaces:
            return JsonResponse({
                'success': False,
                'message': 'wlan0 interface not found',
                'available_interfaces': available_interfaces
            })
        
        success = packet_capture.start_capture('wlan0')
        
        return JsonResponse({
            'success': success,
            'message': 'Packet capture started on wlan0' if success else 'Failed to start capture on wlan0',
            'interface_used': 'wlan0',
            'debug_info': packet_capture.get_debug_info()
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        })

@csrf_exempt
@require_http_methods(["POST"])
def stop_capture(request):
    """Stop packet capture"""
    try:
        packet_capture.stop_capture()
        return JsonResponse({
            'success': True,
            'message': 'Packet capture stopped',
            'debug_info': packet_capture.get_debug_info()
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        })

def get_stats(request):
    """Get current system statistics"""
    try:
        stats = packet_capture.get_stats()
        
        # Get recent database stats
        recent_packets = PacketDetail.objects.count()
        recent_flows = NetworkFlow.objects.count()
        recent_alerts = Alert.objects.filter(acknowledged=False).count()
        
        stats.update({
            'db_packets': recent_packets,
            'db_flows': recent_flows,
            'db_alerts': recent_alerts,
        })
        
        return JsonResponse(stats)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        })

def get_debug_info(request):
    """Get debug information for troubleshooting"""
    try:
        debug_info = packet_capture.get_debug_info()
        
        # Add database stats
        debug_info.update({
            'db_packets': PacketDetail.objects.count(),
            'db_flows': NetworkFlow.objects.count(),
            'db_alerts': Alert.objects.count(),
            'model_path': str(settings.NIDS_CONFIG['MODEL_PATH']),
            'model_exists': os.path.exists(settings.NIDS_CONFIG['MODEL_PATH'])
        })
        
        return JsonResponse(debug_info)
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        })

def test_capture(request):
    """Test packet capture functionality"""
    try:
        from scapy.all import get_if_list, sniff
        import time
        
        debug_results = {
            'timestamp': timezone.now().isoformat(),
            'available_interfaces': [],
            'interface_tests': {},
            'permission_test': None,
            'scapy_version': None
        }
        
        # Test 1: Get available interfaces
        try:
            interfaces = get_if_list()
            debug_results['available_interfaces'] = interfaces
            print(f"Available interfaces: {interfaces}")
        except Exception as e:
            debug_results['interface_error'] = str(e)
        
        # Test 2: Test each interface
        for interface in debug_results['available_interfaces']:
            if interface in ['lo', 'Loopback']:
                continue
                
            test_result = {
                'interface': interface,
                'test_passed': False,
                'error': None,
                'packets_captured': 0
            }
            
            try:
                print(f"Testing interface: {interface}")
                
                # Try to capture 1 packet with 3 second timeout
                packets = sniff(
                    iface=interface,
                    timeout=3,
                    count=1,
                    store=1
                )
                
                test_result['test_passed'] = True
                test_result['packets_captured'] = len(packets)
                print(f"Interface {interface}: captured {len(packets)} packets")
                
            except Exception as e:
                test_result['error'] = str(e)
                print(f"Interface {interface} failed: {e}")
            
            debug_results['interface_tests'][interface] = test_result
        
        # Test 3: Permission test
        try:
            # Try to create a raw socket (requires root)
            import socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.close()
            debug_results['permission_test'] = 'PASSED - Raw socket creation successful'
        except PermissionError:
            debug_results['permission_test'] = 'FAILED - Need root privileges for raw sockets'
        except Exception as e:
            debug_results['permission_test'] = f'ERROR - {str(e)}'
        
        return JsonResponse(debug_results)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'suggestion': 'Try running the server with sudo privileges'
        })

def get_alerts(request):
    """Get recent alerts"""
    try:
        alerts = Alert.objects.filter(acknowledged=False)[:20]
        alert_data = []
        
        for alert in alerts:
            alert_data.append({
                'id': alert.id,
                'timestamp': alert.timestamp.isoformat(),
                'attack_type': alert.get_attack_type_display(),
                'confidence': alert.confidence,
                'src_ip': alert.flow.src_ip,
                'dst_ip': alert.flow.dst_ip,
                'src_port': alert.flow.src_port,
                'dst_port': alert.flow.dst_port,
                'protocol': alert.flow.protocol,
            })
        
        return JsonResponse({
            'alerts': alert_data
        })
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        })

@csrf_exempt
@require_http_methods(["POST"])
def clear_alerts(request):
    """Clear all alerts"""
    try:
        Alert.objects.filter(acknowledged=False).update(acknowledged=True)
        return JsonResponse({
            'success': True,
            'message': 'All alerts cleared'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        })

@csrf_exempt
@require_http_methods(["POST"])
def upload_model(request):
    """Upload a new model file"""
    try:
        if 'model_file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'message': 'No model file provided'
            })
        
        model_file = request.FILES['model_file']
        
        # Save the file
        file_path = default_storage.save(f'models/{model_file.name}', model_file)
        
        # Update settings
        settings.NIDS_CONFIG['MODEL_PATH'] = default_storage.path(file_path)
        
        # Reload model
        success = packet_capture.load_model()
        
        return JsonResponse({
            'success': success,
            'message': 'Model uploaded and loaded successfully' if success else 'Model upload failed'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        })

def packet_list(request):
    """Display all captured packets with filtering options"""
    # Get filter parameters
    attack_type = request.GET.get('attack_type', 'all')
    protocol = request.GET.get('protocol', 'all')
    time_range = request.GET.get('time_range', '1h')
    
    # Calculate time filter
    from datetime import timedelta
    time_filters = {
        '1h': timedelta(hours=1),
        '6h': timedelta(hours=6),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        'all': None
    }
    
    # Base query for statistics (separate from display query)
    stats_query = PacketDetail.objects.select_related('flow').all()
    
    # Apply filters to stats query
    if time_filters[time_range]:
        cutoff_time = timezone.now() - time_filters[time_range]
        stats_query = stats_query.filter(timestamp__gte=cutoff_time)
    
    if attack_type != 'all':
        attack_type_map = {
            'normal': 0, 'ddos': 1, 'bruteforce': 2, 
            'portscan': 3, 'sql_injection': 4
        }
        if attack_type in attack_type_map:
            stats_query = stats_query.filter(flow__prediction=attack_type_map[attack_type])
    
    if protocol != 'all':
        stats_query = stats_query.filter(protocol=protocol.upper())
    
    # Get statistics from the stats query
    total_packets = stats_query.count()
    attack_packets = stats_query.filter(flow__prediction__gt=0).count()
    normal_packets = total_packets - attack_packets
    
    # Create separate query for display (with same filters)
    display_query = PacketDetail.objects.select_related('flow').all()
    
    # Apply same filters to display query
    if time_filters[time_range]:
        cutoff_time = timezone.now() - time_filters[time_range]
        display_query = display_query.filter(timestamp__gte=cutoff_time)
    
    if attack_type != 'all':
        attack_type_map = {
            'normal': 0, 'ddos': 1, 'bruteforce': 2, 
            'portscan': 3, 'sql_injection': 4
        }
        if attack_type in attack_type_map:
            display_query = display_query.filter(flow__prediction=attack_type_map[attack_type])
    
    if protocol != 'all':
        display_query = display_query.filter(protocol=protocol.upper())
    
    # Order and limit the display query
    packets = display_query.order_by('-timestamp')[:1000]
    
    context = {
        'packets': packets,
        'total_packets': total_packets,
        'attack_packets': attack_packets,
        'normal_packets': normal_packets,
        'current_filters': {
            'attack_type': attack_type,
            'protocol': protocol,
            'time_range': time_range
        }
    }
    
    return render(request, 'nids_app/packet_list.html', context)

def packet_detail(request, packet_id):
    """Display detailed information about a specific packet"""
    try:
        packet = PacketDetail.objects.select_related('flow', 'flow__classification').get(id=packet_id)
        
        # Get related packets in the same flow
        related_packets = PacketDetail.objects.filter(
            flow=packet.flow
        ).order_by('timestamp')[:50]
        
        context = {
            'packet': packet,
            'related_packets': related_packets,
            'attack_types': {
                0: 'Normal', 1: 'DDoS', 2: 'Brute Force', 
                3: 'Port Scan', 4: 'SQL Injection'
            }
        }
        
        return render(request, 'nids_app/packet_detail.html', context)
        
    except PacketDetail.DoesNotExist:
        return render(request, 'nids_app/packet_not_found.html', {'packet_id': packet_id})

def flow_detail(request, flow_id):
    """Display detailed information about a network flow"""
    try:
        flow = NetworkFlow.objects.select_related('classification').get(id=flow_id)
        packets = PacketDetail.objects.filter(flow=flow).order_by('timestamp')
        alerts = Alert.objects.filter(flow=flow).order_by('-timestamp')
        
        # Calculate flow statistics
        flow_stats = {
            'total_packets': packets.count(),
            'forward_packets': packets.filter(is_forward=True).count(),
            'backward_packets': packets.filter(is_forward=False).count(),
            'total_bytes': sum(p.packet_size for p in packets),
            'duration': (packets.last().timestamp - packets.first().timestamp).total_seconds() if packets.count() > 1 else 0,
            'avg_packet_size': packets.aggregate(avg_size=models.Avg('packet_size'))['avg_size'] or 0
        }
        
        context = {
            'flow': flow,
            'packets': packets,
            'alerts': alerts,
            'flow_stats': flow_stats,
            'attack_types': {
                0: 'Normal', 1: 'DDoS', 2: 'Brute Force', 
                3: 'Port Scan', 4: 'SQL Injection'
            }
        }
        
        return render(request, 'nids_app/flow_detail.html', context)
        
    except NetworkFlow.DoesNotExist:
        return render(request, 'nids_app/flow_not_found.html', {'flow_id': flow_id})

def get_packet_data(request):
    """Get packet data for real-time updates"""
    try:
        # Get recent packets (last 100)
        packets = PacketDetail.objects.select_related('flow').order_by('-timestamp')[:100]
        
        packet_data = []
        for packet in packets:
            packet_data.append({
                'id': packet.id,
                'timestamp': packet.timestamp.isoformat(),
                'src_ip': packet.src_ip,
                'src_port': packet.src_port,
                'dst_ip': packet.dst_ip,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'size': packet.packet_size,
                'attack_type': packet_capture.get_attack_name(packet.flow.prediction),
                'confidence': packet.flow.confidence,
                'is_attack': packet.flow.is_attack,
                'tcp_flags': packet.tcp_flags,
                'anomaly_score': packet.anomaly_score
            })
        
        # Get classification distribution
        from django.db.models import Count
        classification_stats = NetworkFlow.objects.values('prediction').annotate(
            count=Count('prediction')
        ).order_by('prediction')
        
        classification_data = {
            'normal': 0, 'ddos': 0, 'bruteforce': 0, 'portscan': 0, 'sql_injection': 0
        }
        
        attack_names = ['normal', 'ddos', 'bruteforce', 'portscan', 'sql_injection']
        for stat in classification_stats:
            if 0 <= stat['prediction'] < len(attack_names):
                classification_data[attack_names[stat['prediction']]] = stat['count']
        
        return JsonResponse({
            'packets': packet_data,
            'classification_stats': classification_data,
            'total_packets': len(packet_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        })

@csrf_exempt
@require_http_methods(["POST"])
def upload_csv(request):
    """Upload and analyze CSV file"""
    try:
        if 'csv_file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'message': 'No CSV file provided'
            })
        
        csv_file = request.FILES['csv_file']
        
        # Validate file extension
        if not csv_file.name.lower().endswith('.csv'):
            return JsonResponse({
                'success': False,
                'message': 'Please upload a CSV file'
            })
        
        # Save the file
        file_path = default_storage.save(f'csv_uploads/{csv_file.name}', csv_file)
        full_file_path = default_storage.path(file_path)
        
        # Create analysis record
        analysis = CSVAnalysis.objects.create(
            filename=csv_file.name,
            status='processing'
        )
        
        # Start analysis in background thread
        analysis_thread = threading.Thread(
            target=csv_analyzer.analyze_csv_file,
            args=(full_file_path, csv_file.name, analysis.id),
            daemon=True
        )
        analysis_thread.start()
        
        return JsonResponse({
            'success': True,
            'message': 'CSV file uploaded successfully. Analysis started.',
            'analysis_id': analysis.id
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error uploading CSV: {str(e)}'
        })

def csv_analysis_detail(request, analysis_id):
    """Display detailed CSV analysis results"""
    try:
        analysis = CSVAnalysis.objects.get(id=analysis_id)
        
        # Get flow results with pagination
        page_size = 100
        page = int(request.GET.get('page', 1))
        offset = (page - 1) * page_size
        
        flow_results = CSVFlowResult.objects.filter(
            analysis=analysis
        ).order_by('row_number')[offset:offset + page_size]
        
        # Get filter parameters
        attack_filter = request.GET.get('attack_type', 'all')
        if attack_filter != 'all':
            attack_type_map = {
                'normal': 0, 'ddos': 1, 'bruteforce': 2, 
                'portscan': 3, 'sql_injection': 4
            }
            if attack_filter in attack_type_map:
                flow_results = flow_results.filter(
                    predicted_class=attack_type_map[attack_filter]
                )
        
        # Calculate statistics
        total_results = CSVFlowResult.objects.filter(analysis=analysis).count()
        total_pages = (total_results + page_size - 1) // page_size
        
        # Get accuracy if original labels are present
        accuracy = None
        if flow_results.filter(original_label__isnull=False).exists():
            # Calculate accuracy for flows with original labels
            correct_predictions = 0
            total_with_labels = 0
            
            for result in CSVFlowResult.objects.filter(analysis=analysis, original_label__isnull=False):
                total_with_labels += 1
                # Map original label to prediction class (this might need adjustment based on your label format)
                if result.original_label.lower() in ['normal', '0']:
                    expected_class = 0
                elif result.original_label.lower() in ['ddos', '1']:
                    expected_class = 1
                elif result.original_label.lower() in ['bruteforce', 'brute force', '2']:
                    expected_class = 2
                elif result.original_label.lower() in ['portscan', 'port scan', '3']:
                    expected_class = 3
                elif result.original_label.lower() in ['sql injection', 'sql_injection', '4']:
                    expected_class = 4
                else:
                    continue  # Skip unknown labels
                
                if result.predicted_class == expected_class:
                    correct_predictions += 1
            
            if total_with_labels > 0:
                accuracy = (correct_predictions / total_with_labels) * 100
        
        context = {
            'analysis': analysis,
            'flow_results': flow_results,
            'total_results': total_results,
            'current_page': page,
            'total_pages': total_pages,
            'accuracy': accuracy,
            'attack_filter': attack_filter,
            'attack_types': {
                0: 'Normal', 1: 'DDoS', 2: 'Brute Force', 
                3: 'Port Scan', 4: 'SQL Injection'
            }
        }
        
        return render(request, 'nids_app/csv_analysis_detail.html', context)
        
    except CSVAnalysis.DoesNotExist:
        return render(request, 'nids_app/csv_analysis_not_found.html', {'analysis_id': analysis_id})

def get_csv_analysis(request):
    """Get CSV analysis status and results"""
    try:
        # Get recent analyses
        analyses = CSVAnalysis.objects.all()[:10]
        
        analysis_data = []
        for analysis in analyses:
            analysis_data.append({
                'id': analysis.id,
                'filename': analysis.filename,
                'upload_timestamp': analysis.upload_timestamp.isoformat(),
                'status': analysis.status,
                'total_rows': analysis.total_rows,
                'processed_rows': analysis.processed_rows,
                'failed_rows': analysis.failed_rows,
                'normal_count': analysis.normal_count,
                'ddos_count': analysis.ddos_count,
                'bruteforce_count': analysis.bruteforce_count,
                'portscan_count': analysis.portscan_count,
                'sql_injection_count': analysis.sql_injection_count,
                'processing_time': analysis.processing_time,
                'error_message': analysis.error_message
            })
        
        return JsonResponse({
            'analyses': analysis_data
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        })
