from django.db import models
from django.utils import timezone

class NetworkFlow(models.Model):
    flow_id = models.CharField(max_length=100, unique=True)
    src_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    timestamp = models.DateTimeField(default=timezone.now)
    
    # Flow statistics
    flow_duration = models.FloatField(default=0)
    tot_fwd_pkts = models.IntegerField(default=0)
    tot_bwd_pkts = models.IntegerField(default=0)
    
    # Prediction results
    prediction = models.IntegerField(default=0)  # 0=normal, 1=ddos, 2=bruteforce, 3=portscan, 4=sql_injection
    confidence = models.FloatField(default=0.0)
    is_attack = models.BooleanField(default=False)
    
    # Source tracking
    source_type = models.CharField(max_length=20, default='live')  # 'live' or 'csv'
    
    class Meta:
        ordering = ['-timestamp']

class Alert(models.Model):
    ATTACK_TYPES = [
        (0, 'Normal'),
        (1, 'DDoS'),
        (2, 'Brute Force'),
        (3, 'Port Scan'),
        (4, 'SQL Injection'),
    ]
    
    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE)
    attack_type = models.IntegerField(choices=ATTACK_TYPES)
    confidence = models.FloatField()
    timestamp = models.DateTimeField(default=timezone.now)
    acknowledged = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']

class SystemStats(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    total_packets = models.IntegerField(default=0)
    total_flows = models.IntegerField(default=0)
    total_attacks = models.IntegerField(default=0)
    cpu_usage = models.FloatField(default=0.0)
    memory_usage = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ['-timestamp']

class PacketDetail(models.Model):
    """Store detailed packet information for analysis"""
    flow = models.ForeignKey(NetworkFlow, on_delete=models.CASCADE, related_name='packets')
    packet_id = models.CharField(max_length=100)
    timestamp = models.DateTimeField()
    
    # Raw packet data
    src_ip = models.GenericIPAddressField()
    src_port = models.IntegerField()
    dst_ip = models.GenericIPAddressField()
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    packet_size = models.IntegerField()
    
    # TCP/UDP specific
    tcp_flags = models.CharField(max_length=20, blank=True)
    tcp_window_size = models.IntegerField(null=True, blank=True)
    tcp_seq_num = models.BigIntegerField(null=True, blank=True)
    tcp_ack_num = models.BigIntegerField(null=True, blank=True)
    
    # Packet direction
    is_forward = models.BooleanField(default=True)
    
    # Raw packet data (hex)
    raw_data = models.TextField(blank=True)
    
    # Analysis results
    is_suspicious = models.BooleanField(default=False)
    anomaly_score = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['is_suspicious']),
        ]

class FlowClassification(models.Model):
    """Store detailed classification results for each flow"""
    flow = models.OneToOneField(NetworkFlow, on_delete=models.CASCADE, related_name='classification')
    
    # All 5 class probabilities
    prob_normal = models.FloatField(default=0.0)
    prob_ddos = models.FloatField(default=0.0)
    prob_bruteforce = models.FloatField(default=0.0)
    prob_portscan = models.FloatField(default=0.0)
    prob_sql_injection = models.FloatField(default=0.0)
    
    # Feature importance scores
    top_features = models.JSONField(default=dict)  # Store top contributing features
    
    # Cleaning statistics
    features_cleaned = models.IntegerField(default=0)
    features_failed_validation = models.IntegerField(default=0)
    cleaning_success_rate = models.FloatField(default=100.0)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']

class CSVAnalysis(models.Model):
    """Store CSV file analysis results"""
    filename = models.CharField(max_length=255)
    upload_timestamp = models.DateTimeField(auto_now_add=True)
    
    # Analysis statistics
    total_rows = models.IntegerField(default=0)
    processed_rows = models.IntegerField(default=0)
    failed_rows = models.IntegerField(default=0)
    
    # Attack distribution
    normal_count = models.IntegerField(default=0)
    ddos_count = models.IntegerField(default=0)
    bruteforce_count = models.IntegerField(default=0)
    portscan_count = models.IntegerField(default=0)
    sql_injection_count = models.IntegerField(default=0)
    
    # Processing status
    STATUS_CHOICES = [
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='processing')
    error_message = models.TextField(blank=True)
    
    # Processing time
    processing_time = models.FloatField(default=0.0)  # in seconds
    
    class Meta:
        ordering = ['-upload_timestamp']

class CSVFlowResult(models.Model):
    """Store individual flow results from CSV analysis"""
    analysis = models.ForeignKey(CSVAnalysis, on_delete=models.CASCADE, related_name='flow_results')
    
    # Original CSV row data (key fields)
    flow_id = models.CharField(max_length=200)
    src_ip = models.CharField(max_length=45)  # Support IPv6
    src_port = models.IntegerField()
    dst_ip = models.CharField(max_length=45)
    dst_port = models.IntegerField()
    protocol = models.CharField(max_length=20)
    
    # Original label (if present in CSV)
    original_label = models.CharField(max_length=50, blank=True)
    
    # Prediction results
    predicted_class = models.IntegerField()  # 0-4
    confidence = models.FloatField()
    
    # All class probabilities
    prob_normal = models.FloatField(default=0.0)
    prob_ddos = models.FloatField(default=0.0)
    prob_bruteforce = models.FloatField(default=0.0)
    prob_portscan = models.FloatField(default=0.0)
    prob_sql_injection = models.FloatField(default=0.0)
    
    # Validation status
    is_valid = models.BooleanField(default=True)
    validation_errors = models.TextField(blank=True)
    
    # Row number in original CSV
    row_number = models.IntegerField()
    
    class Meta:
        ordering = ['row_number']
        indexes = [
            models.Index(fields=['analysis', 'predicted_class']),
            models.Index(fields=['analysis', 'is_valid']),
        ]
