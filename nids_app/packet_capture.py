import threading
import time
import pickle
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, get_if_list, conf
import psutil
from django.conf import settings
import logging
import os

# Use absolute imports to avoid import issues
try:
    from nids_app.models import NetworkFlow, Alert, SystemStats
    from nids_app.data_cleaner import NetworkDataCleaner
except ImportError:
    # Fallback to relative imports if absolute imports fail
    from .models import NetworkFlow, Alert, SystemStats
    from .data_cleaner import NetworkDataCleaner

logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self):
        # Initialize debug info first
        self.debug_info = {
            'available_interfaces': [],
            'selected_interface': None,
            'last_error': None,
            'packets_processed': 0,
            'packets_saved': 0
        }
        
        self.is_capturing = False
        self.capture_thread = None
        self.flows = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'start_time': None,
            'last_seen': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'features': {}
        })
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'total_attacks': 0,
            'start_time': None,
            'capture_errors': 0,
            'processing_errors': 0
        }
        
        # Initialize components
        self._get_available_interfaces()
        self.data_cleaner = NetworkDataCleaner()
        self.load_model()  # This can fail gracefully now
    
    def _get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = get_if_list()
            self.debug_info['available_interfaces'] = interfaces
            print(f"📡 Available network interfaces: {interfaces}")
        
            # Prioritize wireless interfaces first, then other non-loopback interfaces
            preferred_interfaces = ['wlan0', 'wlan1', 'wifi0', 'en0', 'eth0', 'eth1']
        
            # Try to find a preferred interface in order
            for preferred in preferred_interfaces:
                if preferred in interfaces:
                    self.debug_info['selected_interface'] = preferred
                    print(f"🎯 Selected preferred interface: {preferred}")
                    break
        
            # If no preferred interface found, use first non-loopback interface
            if not self.debug_info['selected_interface']:
                for iface in interfaces:
                    if iface not in ['lo', 'Loopback']:  # Skip loopback
                        self.debug_info['selected_interface'] = iface
                        break
        
            # Last resort: use first available interface
            if not self.debug_info['selected_interface'] and interfaces:
                self.debug_info['selected_interface'] = interfaces[0]
            
            print(f"🎯 Final selected interface: {self.debug_info['selected_interface']}")
        
        except Exception as e:
            print(f"❌ Error getting interfaces: {e}")
            self.debug_info['last_error'] = str(e)
    
    def load_model(self):
        """Load the trained SVM model"""
        try:
            model_path = settings.NIDS_CONFIG['MODEL_PATH']
            print(f"🔍 Looking for model at: {model_path}")
            
            # Check if model file exists
            if not os.path.exists(model_path):
                error_msg = f"Model file not found at {model_path}"
                print(f"❌ {error_msg}")
                self.debug_info['last_error'] = error_msg
                return False
            
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.label_encoder = model_data['label_encoder']
                self.feature_names = model_data['feature_names']
            print(f"✅ Model loaded successfully with {len(self.feature_names)} features")
            return True
        except Exception as e:
            error_msg = f"Model loading error: {str(e)}"
            print(f"❌ {error_msg}")
            self.debug_info['last_error'] = error_msg
            return False
    
    def start_capture(self, interface=None):
        """Start packet capture with better error handling"""
        if self.is_capturing:
            print("⚠️  Capture already running")
            return False
        
        if not self.model:
            print("❌ No model loaded - cannot start capture")
            print("💡 Please upload a model file first or ensure the model exists at the configured path")
            return False
        
        # Use provided interface or default
        capture_interface = interface or self.debug_info['selected_interface']
        
        if not capture_interface:
            print("❌ No network interface available for capture")
            return False
        
        print(f"🚀 Starting packet capture on interface: {capture_interface}")
        print(f"📊 Model ready with {len(self.feature_names)} features")
        
        self.is_capturing = True
        self.stats['start_time'] = datetime.now()
        self.stats['capture_errors'] = 0
        self.stats['processing_errors'] = 0
        
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(capture_interface,),
            daemon=True
        )
        self.capture_thread.start()
        
        print("🎯 Packet capture thread started")
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        print("🛑 Stopping packet capture...")
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        print(f"📈 Capture session stats:")
        print(f"   Total packets processed: {self.debug_info['packets_processed']}")
        print(f"   Total packets saved: {self.debug_info['packets_saved']}")
        print(f"   Capture errors: {self.stats['capture_errors']}")
        print(f"   Processing errors: {self.stats['processing_errors']}")
    
    def _capture_packets(self, interface):
        """Main packet capture loop with enhanced debugging"""
        try:
            print(f"🔍 Starting packet sniffing on {interface}...")
            
            # Test if we can capture on this interface
            def packet_handler(packet):
                try:
                    self._process_packet(packet)
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    if self.stats['processing_errors'] <= 5:  # Only log first 5 errors
                        print(f"❌ Packet processing error: {e}")
        
            # Add a test to see if interface is valid
            try:
                print(f"🔧 Testing packet capture on {interface}...")
                
                # Try a short test capture first
                test_packets = sniff(
                    iface=interface,
                    timeout=2,
                    count=1,
                    store=1
                )
                
                if test_packets:
                    print(f"✅ Test capture successful - captured {len(test_packets)} packet(s)")
                else:
                    print("⚠️  No packets captured in test - interface may be inactive or no traffic")
                
            except Exception as test_e:
                print(f"❌ Test capture failed: {test_e}")
                self.debug_info['last_error'] = f"Test capture error: {str(test_e)}"
                self.stats['capture_errors'] += 1
                return
        
            print(f"🎯 Starting continuous packet capture...")
        
            # Start main sniffing loop
            packet_count = 0
            start_time = time.time()
        
            def enhanced_packet_handler(packet):
                nonlocal packet_count
                packet_count += 1
            
                # Log every 10th packet for the first 100 packets
                if packet_count <= 100 and packet_count % 10 == 0:
                    print(f"📦 Captured {packet_count} packets so far...")
            
                try:
                    self._process_packet(packet)
                except Exception as e:
                    self.stats['processing_errors'] += 1
                    if self.stats['processing_errors'] <= 5:
                        print(f"❌ Packet processing error: {e}")
        
            # Main capture loop with better error handling
            while self.is_capturing:
                try:
                    # Capture packets in small batches
                    packets = sniff(
                        iface=interface,
                        prn=enhanced_packet_handler,
                        timeout=5,  # 5 second timeout
                        count=100,  # Process up to 100 packets at a time
                        store=0
                    )
                
                    # Check if we're still supposed to be capturing
                    if not self.is_capturing:
                        break
                    
                    # Log status every 30 seconds
                    current_time = time.time()
                    if current_time - start_time > 30:
                        print(f"📊 Capture status: {packet_count} packets processed, still running...")
                        start_time = current_time
                    
                except KeyboardInterrupt:
                    print("🛑 Capture interrupted by user")
                    break
                except Exception as loop_e:
                    print(f"❌ Capture loop error: {loop_e}")
                    self.debug_info['last_error'] = f"Capture loop error: {str(loop_e)}"
                    self.stats['capture_errors'] += 1
                
                    # Wait a bit before retrying
                    if self.is_capturing:
                        print("⏳ Waiting 5 seconds before retry...")
                        time.sleep(5)
        
            print(f"📈 Capture session ended. Total packets processed: {packet_count}")
        
        except PermissionError as e:
            error_msg = f"Permission denied - try running with sudo: {e}"
            print(f"❌ {error_msg}")
            self.debug_info['last_error'] = error_msg
            self.stats['capture_errors'] += 1
        except OSError as e:
            error_msg = f"Network interface error: {e}"
            print(f"❌ {error_msg}")
            self.debug_info['last_error'] = error_msg
            self.stats['capture_errors'] += 1
        except Exception as e:
            error_msg = f"Capture error: {e}"
            print(f"❌ {error_msg}")
            self.debug_info['last_error'] = error_msg
            self.stats['capture_errors'] += 1
        finally:
            self.is_capturing = False
            print("🏁 Packet capture loop ended")
    
    def _process_packet(self, packet):
        """Process individual packets with enhanced debugging"""
        try:
            if not packet.haslayer(IP):
                return
            
            self.stats['total_packets'] += 1
            self.debug_info['packets_processed'] += 1
            
            # Log first few packets for debugging
            if self.debug_info['packets_processed'] <= 5:
                print(f"📦 Processing packet #{self.debug_info['packets_processed']}")
            
            # Extract packet information
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            src_port = dst_port = 0
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = 'TCP'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = 'UDP'
            else:
                protocol_name = 'OTHER'
            
            # Create flow ID
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            reverse_flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            
            # Determine flow direction
            if flow_id in self.flows:
                current_flow_id = flow_id
                is_forward = True
            elif reverse_flow_id in self.flows:
                current_flow_id = reverse_flow_id
                is_forward = False
            else:
                current_flow_id = flow_id
                is_forward = True
                self.stats['total_flows'] += 1
                
                # Log new flows
                if self.stats['total_flows'] <= 5:
                    print(f"🆕 New flow #{self.stats['total_flows']}: {current_flow_id}")
            
            # Update flow
            flow = self.flows[current_flow_id]
            current_time = datetime.now()
            
            if flow['start_time'] is None:
                flow['start_time'] = current_time
            
            flow['last_seen'] = current_time
            flow['packets'].append({
                'timestamp': current_time,
                'size': len(packet),
                'is_forward': is_forward,
                'packet': packet
            })
            
            # Add to forward or backward packets
            if is_forward:
                flow['fwd_packets'].append(packet)
            else:
                flow['bwd_packets'].append(packet)
            
            # Extract features and predict if we have enough packets
            if len(flow['packets']) >= 5:  # Reduced from 10 to 5 for better responsiveness
                try:
                    features = self._extract_features(flow, src_ip, src_port, dst_ip, dst_port, protocol_name)
                    if features is not None:
                        prediction, probabilities = self._predict_attack(features)
                        
                        # Save to database
                        self._save_flow_to_db(
                            current_flow_id, src_ip, src_port, dst_ip, dst_port,
                            protocol_name, flow, prediction, probabilities
                        )
                        
                        self.debug_info['packets_saved'] += 1
                        
                        # Log first few predictions
                        if self.debug_info['packets_saved'] <= 3:
                            attack_name = self.get_attack_name(prediction)
                            print(f"🎯 Flow prediction #{self.debug_info['packets_saved']}: {attack_name} (confidence: {max(probabilities.values()):.3f})")
                    else:
                        print(f"⚠️  Feature extraction failed for flow {current_flow_id}")
                
                except Exception as e:
                    print(f"❌ Feature extraction/prediction error: {e}")
                    import traceback
                    traceback.print_exc()
                    self.stats['processing_errors'] += 1
            
            # Clean old flows periodically
            if self.stats['total_packets'] % 100 == 0:
                self._cleanup_old_flows()
                
        except Exception as e:
            print(f"❌ Packet processing error: {e}")
            self.stats['processing_errors'] += 1
    
    def _extract_features(self, flow, src_ip, src_port, dst_ip, dst_port, protocol):
        """Extract features matching the training data format with cleaning"""
        try:
            packets = list(flow['packets'])
            if len(packets) < 2:
                print(f"🔍 Flow {src_ip}:{src_port}-{dst_ip}:{dst_port} has only {len(packets)} packets, skipping")
                return None
        
            print(f"🔍 Extracting features for flow {src_ip}:{src_port}-{dst_ip}:{dst_port} with {len(packets)} packets")
        
            # Initialize feature dictionary
            features = {}
            
            # Basic flow information
            features['Flow ID'] = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            features['Src IP'] = src_ip
            features['Src Port'] = src_port
            features['Dst IP'] = dst_ip
            features['Dst Port'] = dst_port
            features['Protocol'] = protocol
            features['Timestamp'] = flow['start_time'].timestamp()
            
            # Flow duration
            duration = (flow['last_seen'] - flow['start_time']).total_seconds()
            features['Flow Duration'] = max(duration, 0.000001)  # Avoid division by zero
            
            # Packet counts
            fwd_packets = [p for p in packets if p['is_forward']]
            bwd_packets = [p for p in packets if p['is_forward']]
            
            features['Tot Fwd Pkts'] = len(fwd_packets)
            features['Tot Bwd Pkts'] = len(bwd_packets)
            
            # Packet lengths
            fwd_lengths = [p['size'] for p in fwd_packets] if fwd_packets else [0]
            bwd_lengths = [p['size'] for p in bwd_packets] if bwd_packets else [0]
            
            features['TotLen Fwd Pkts'] = sum(fwd_lengths)
            features['TotLen Bwd Pkts'] = sum(bwd_lengths)
            
            # Forward packet statistics
            features['Fwd Pkt Len Max'] = max(fwd_lengths) if fwd_lengths else 0
            features['Fwd Pkt Len Min'] = min(fwd_lengths) if fwd_lengths else 0
            features['Fwd Pkt Len Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
            features['Fwd Pkt Len Std'] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
            
            # Backward packet statistics
            features['Bwd Pkt Len Max'] = max(bwd_lengths) if bwd_lengths else 0
            features['Bwd Pkt Len Min'] = min(bwd_lengths) if bwd_lengths else 0
            features['Bwd Pkt Len Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
            features['Bwd Pkt Len Std'] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
            
            # Flow rates
            total_bytes = sum(fwd_lengths) + sum(bwd_lengths)
            total_packets = len(fwd_packets) + len(bwd_packets)
            
            features['Flow Byts/s'] = total_bytes / features['Flow Duration']
            features['Flow Pkts/s'] = total_packets / features['Flow Duration']
            
            print(f"🔍 Basic features extracted: {len(features)} features")
            
            # Apply data cleaning to ensure consistency with training data
            cleaned_features = self.data_cleaner.clean_flow_features(features)
            
            if cleaned_features is None:
                print(f"⚠️  Flow {src_ip}:{src_port}-{dst_ip}:{dst_port} failed data cleaning validation")
                return None
            
            print(f"✅ Features cleaned successfully: {len(cleaned_features)} features")
            return cleaned_features
        
        except Exception as e:
            print(f"❌ Feature extraction error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _predict_attack(self, features):
        """Predict attack type and return all class probabilities"""
        try:
            # Create DataFrame with features
            feature_df = pd.DataFrame([features])
            
            # Ensure all required features are present
            for feature_name in self.feature_names:
                if feature_name not in feature_df.columns:
                    feature_df[feature_name] = 0.0
            
            # Select only the features used in training
            feature_df = feature_df[self.feature_names]
            
            # Scale features
            features_scaled = self.scaler.transform(feature_df)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Return prediction and all class probabilities
            return int(prediction), {
                'normal': float(probabilities[0]) if len(probabilities) > 0 else 0.0,
                'ddos': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                'bruteforce': float(probabilities[2]) if len(probabilities) > 2 else 0.0,
                'portscan': float(probabilities[3]) if len(probabilities) > 3 else 0.0,
                'sql_injection': float(probabilities[4]) if len(probabilities) > 4 else 0.0
            }
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return 0, {'normal': 1.0, 'ddos': 0.0, 'bruteforce': 0.0, 'portscan': 0.0, 'sql_injection': 0.0}

    
    def _save_flow_to_db(self, flow_id, src_ip, src_port, dst_ip, dst_port, protocol, flow, prediction, probabilities):
        """Save flow and prediction to database with detailed packet information"""
        try:
            print(f"💾 Saving flow to database: {flow_id}")
        
            # Import here to avoid circular imports
            from nids_app.models import PacketDetail, FlowClassification
        
            # Get max confidence from probabilities
            confidence = max(probabilities.values())
        
            # Create or update NetworkFlow
            network_flow, created = NetworkFlow.objects.get_or_create(
                flow_id=flow_id,
                defaults={
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'flow_duration': (flow['last_seen'] - flow['start_time']).total_seconds(),
                    'tot_fwd_pkts': len([p for p in flow['packets'] if p['is_forward']]),
                    'tot_bwd_pkts': len([p for p in flow['packets'] if not p['is_forward']]),
                    'prediction': prediction,
                    'confidence': confidence,
                    'is_attack': prediction != 0
                }
            )
        
            print(f"💾 NetworkFlow {'created' if created else 'updated'}: {network_flow.id}")
        
            # Store detailed classification results
            classification, class_created = FlowClassification.objects.update_or_create(
                flow=network_flow,
                defaults={
                    'prob_normal': probabilities.get('normal', 0.0),
                    'prob_ddos': probabilities.get('ddos', 0.0),
                    'prob_bruteforce': probabilities.get('bruteforce', 0.0),
                    'prob_portscan': probabilities.get('portscan', 0.0),
                    'prob_sql_injection': probabilities.get('sql_injection', 0.0),
                    'cleaning_success_rate': 100.0  # Will be updated with actual stats
                }
            )
        
            print(f"💾 FlowClassification {'created' if class_created else 'updated'}")
        
            # Store individual packet details (limit to last 50 packets to avoid DB bloat)
            recent_packets = list(flow['packets'])[-50:]
            packet_count = 0
        
            for i, packet_info in enumerate(recent_packets):
                if 'packet' in packet_info:
                    packet = packet_info['packet']
                
                    # Extract TCP flags if available
                    tcp_flags = ""
                    tcp_window = None
                    tcp_seq = None
                    tcp_ack = None
                
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        flags = []
                        if tcp_layer.flags & 0x01: flags.append("FIN")
                        if tcp_layer.flags & 0x02: flags.append("SYN")
                        if tcp_layer.flags & 0x04: flags.append("RST")
                        if tcp_layer.flags & 0x08: flags.append("PSH")
                        if tcp_layer.flags & 0x10: flags.append("ACK")
                        if tcp_layer.flags & 0x20: flags.append("URG")
                        tcp_flags = ",".join(flags)
                        tcp_window = tcp_layer.window
                        tcp_seq = tcp_layer.seq
                        tcp_ack = tcp_layer.ack
                
                    packet_detail, pkt_created = PacketDetail.objects.update_or_create(
                        flow=network_flow,
                        packet_id=f"{flow_id}_{i}",
                        defaults={
                            'timestamp': packet_info['timestamp'],
                            'src_ip': src_ip if packet_info['is_forward'] else dst_ip,
                            'src_port': src_port if packet_info['is_forward'] else dst_port,
                            'dst_ip': dst_ip if packet_info['is_forward'] else src_ip,
                            'dst_port': dst_port if packet_info['is_forward'] else src_port,
                            'protocol': protocol,
                            'packet_size': packet_info['size'],
                            'tcp_flags': tcp_flags,
                            'tcp_window_size': tcp_window,
                            'tcp_seq_num': tcp_seq,
                            'tcp_ack_num': tcp_ack,
                            'is_forward': packet_info['is_forward'],
                            'raw_data': str(packet)[:1000],  # Limit raw data size
                            'is_suspicious': prediction != 0,
                            'anomaly_score': 1.0 - probabilities.get('normal', 0.0)
                        }
                    )
                
                    if pkt_created:
                        packet_count += 1
        
            print(f"💾 Saved {packet_count} packet details")
    
            # Create alert if attack detected
            if prediction != 0:  # Not normal
                alert = Alert.objects.create(
                    flow=network_flow,
                    attack_type=prediction,
                    confidence=confidence
                )
                self.stats['total_attacks'] += 1
                print(f"🚨 ATTACK DETECTED: {self.get_attack_name(prediction)} (Confidence: {confidence:.3f})")
                print(f"   📊 All probabilities: {probabilities}")
                print(f"   🚨 Alert created: {alert.id}")
        
            print(f"✅ Flow saved successfully to database")
        
        except Exception as e:
            print(f"❌ Database save error: {e}")
            import traceback
            traceback.print_exc()
    
    def _cleanup_old_flows(self):
        """Remove old flows to prevent memory issues"""
        current_time = datetime.now()
        timeout = timedelta(seconds=settings.NIDS_CONFIG['FLOW_TIMEOUT'])
        
        flows_to_remove = []
        for flow_id, flow in self.flows.items():
            if flow['last_seen'] and (current_time - flow['last_seen']) > timeout:
                flows_to_remove.append(flow_id)
        
        for flow_id in flows_to_remove:
            del self.flows[flow_id]
    
    def get_attack_name(self, prediction):
        """Get attack name from prediction"""
        attack_names = {
            0: 'Normal',
            1: 'DDoS',
            2: 'Brute Force',
            3: 'Port Scan',
            4: 'SQL Injection'
        }
        return attack_names.get(prediction, 'Unknown')
    
    def get_stats(self):
        """Get current statistics"""
        # Update system stats
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        
        SystemStats.objects.create(
            total_packets=self.stats['total_packets'],
            total_flows=self.stats['total_flows'],
            total_attacks=self.stats['total_attacks'],
            cpu_usage=cpu_usage,
            memory_usage=memory_usage
        )
        
        return {
            'is_capturing': self.is_capturing,
            'total_packets': self.stats['total_packets'],
            'total_flows': self.stats['total_flows'],
            'total_attacks': self.stats['total_attacks'],
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'uptime': (datetime.now() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0,
            'debug_info': self.debug_info,
            'capture_errors': self.stats['capture_errors'],
            'processing_errors': self.stats['processing_errors']
        }
    
    def get_debug_info(self):
        """Get debug information for troubleshooting"""
        return {
            'available_interfaces': self.debug_info['available_interfaces'],
            'selected_interface': self.debug_info['selected_interface'],
            'last_error': self.debug_info['last_error'],
            'packets_processed': self.debug_info['packets_processed'],
            'packets_saved': self.debug_info['packets_saved'],
            'model_loaded': self.model is not None,
            'feature_count': len(self.feature_names) if self.feature_names else 0,
            'is_capturing': self.is_capturing,
            'capture_errors': self.stats['capture_errors'],
            'processing_errors': self.stats['processing_errors']
        }

# Global packet capture instance
packet_capture = PacketCapture()
