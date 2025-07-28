#!/usr/bin/env python
"""
Create a dummy model file for testing purposes
"""
import os
import sys
import pickle
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nids_project.settings')
import django
django.setup()

from django.conf import settings

def create_dummy_model():
    """Create a dummy SVM model for testing"""
    print("🔧 Creating dummy model for testing...")
    
    # Create dummy feature names (matching the expected features)
    feature_names = [
        'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
        'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
        'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
        'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
        'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
        'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
        'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
        'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
        'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
        'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
        'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
        'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min',
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
    
    # Create dummy training data
    n_samples = 1000
    n_features = len(feature_names)
    
    # Generate random features
    X = np.random.rand(n_samples, n_features)
    
    # Generate random labels (0-4 for 5 classes)
    y = np.random.randint(0, 5, n_samples)
    
    # Create and train dummy model
    model = SVC(probability=True, random_state=42)
    model.fit(X, y)
    
    # Create scaler
    scaler = StandardScaler()
    scaler.fit(X)
    
    # Create label encoder
    label_encoder = LabelEncoder()
    label_encoder.fit(y)
    
    # Create model data dictionary
    model_data = {
        'model': model,
        'scaler': scaler,
        'label_encoder': label_encoder,
        'feature_names': feature_names
    }
    
    # Ensure models directory exists
    model_dir = os.path.dirname(settings.NIDS_CONFIG['MODEL_PATH'])
    os.makedirs(model_dir, exist_ok=True)
    
    # Save the model
    model_path = settings.NIDS_CONFIG['MODEL_PATH']
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"✅ Dummy model created successfully at: {model_path}")
    print(f"📊 Model features: {len(feature_names)}")
    print(f"🎯 Model classes: 5 (Normal, DDoS, Brute Force, Port Scan, SQL Injection)")
    print("⚠️  Note: This is a dummy model for testing only!")

if __name__ == '__main__':
    create_dummy_model()
