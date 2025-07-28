#!/usr/bin/env python
"""
Setup script to initialize the Django database and create necessary tables
"""
import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nids_project.settings')
django.setup()

from django.core.management import execute_from_command_line
from django.core.management import call_command

def setup_database():
    """Initialize database and run migrations"""
    print("🔧 Setting up NIDS database...")
    
    # Make migrations
    print("📝 Creating migrations...")
    try:
        call_command('makemigrations', verbosity=1)
    except Exception as e:
        print(f"Warning: {e}")
    
    # Run migrations
    print("🗃️  Running migrations...")
    try:
        call_command('migrate', verbosity=1)
    except Exception as e:
        print(f"Error running migrations: {e}")
        return False
    
    # Create media directories
    from django.conf import settings
    
    media_dirs = ['csv_uploads', 'models']
    for dir_name in media_dirs:
        dir_path = os.path.join(settings.BASE_DIR, 'media', dir_name)
        os.makedirs(dir_path, exist_ok=True)
        print(f"📁 Created directory: {dir_path}")
    
    # Create static directory
    static_path = os.path.join(settings.BASE_DIR, 'static')
    os.makedirs(static_path, exist_ok=True)
    print(f"📁 Created static directory: {static_path}")
    
    print("✅ Database setup completed!")
    print("🚀 You can now run the NIDS system with: python manage.py runserver")
    return True

def create_sample_data():
    """Create some sample data for testing"""
    from nids_app.models import NetworkFlow, Alert, PacketDetail, FlowClassification
    from django.utils import timezone
    import random
    
    print("📝 Creating sample data...")
    
    # Create sample flows
    sample_flows = [
        {
            'flow_id': 'sample_normal_flow',
            'src_ip': '192.168.1.100',
            'src_port': 12345,
            'dst_ip': '8.8.8.8',
            'dst_port': 80,
            'protocol': 'TCP',
            'prediction': 0,
            'confidence': 0.95,
            'is_attack': False
        },
        {
            'flow_id': 'sample_ddos_flow',
            'src_ip': '10.0.0.50',
            'src_port': 54321,
            'dst_ip': '192.168.1.10',
            'dst_port': 80,
            'protocol': 'TCP',
            'prediction': 1,
            'confidence': 0.87,
            'is_attack': True
        },
        {
            'flow_id': 'sample_bruteforce_flow',
            'src_ip': '172.16.0.25',
            'src_port': 22,
            'dst_ip': '192.168.1.5',
            'dst_port': 22,
            'protocol': 'TCP',
            'prediction': 2,
            'confidence': 0.92,
            'is_attack': True
        }
    ]
    
    for flow_data in sample_flows:
        flow, created = NetworkFlow.objects.get_or_create(
            flow_id=flow_data['flow_id'],
            defaults=flow_data
        )
        
        if created:
            print(f"Created flow: {flow_data['flow_id']}")
            
            # Create classification data
            FlowClassification.objects.create(
                flow=flow,
                prob_normal=0.95 if flow_data['prediction'] == 0 else 0.05,
                prob_ddos=0.87 if flow_data['prediction'] == 1 else 0.02,
                prob_bruteforce=0.92 if flow_data['prediction'] == 2 else 0.01,
                prob_portscan=0.03,
                prob_sql_injection=0.01
            )
            
            # Create sample packets for each flow
            for i in range(5):
                PacketDetail.objects.create(
                    flow=flow,
                    packet_id=f"{flow_data['flow_id']}_packet_{i}",
                    timestamp=timezone.now(),
                    src_ip=flow_data['src_ip'],
                    src_port=flow_data['src_port'],
                    dst_ip=flow_data['dst_ip'],
                    dst_port=flow_data['dst_port'],
                    protocol=flow_data['protocol'],
                    packet_size=random.randint(64, 1500),
                    tcp_flags='SYN,ACK' if i == 0 else 'ACK',
                    is_forward=i % 2 == 0,
                    is_suspicious=flow_data['is_attack'],
                    anomaly_score=1.0 - flow_data['confidence'] if flow_data['is_attack'] else 0.1
                )
            
            # Create alert if it's an attack
            if flow_data['is_attack']:
                Alert.objects.create(
                    flow=flow,
                    attack_type=flow_data['prediction'],
                    confidence=flow_data['confidence']
                )
        else:
            print(f"Flow already exists: {flow_data['flow_id']}")
    
    print("✅ Sample data created successfully!")

if __name__ == '__main__':
    if setup_database():
        create_sample_data()
