import pandas as pd
import numpy as np
import pickle
import time
from datetime import datetime
from django.conf import settings
import logging

# Use absolute imports
try:
    from nids_app.data_cleaner import NetworkDataCleaner
    from nids_app.models import CSVAnalysis, CSVFlowResult
except ImportError:
    # Fallback to relative imports
    from .data_cleaner import NetworkDataCleaner
    from .models import CSVAnalysis, CSVFlowResult

logger = logging.getLogger(__name__)

class CSVAnalyzer:
    """
    Analyze CSV files containing network flow data using the trained model
    """
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.data_cleaner = NetworkDataCleaner()
        self.load_model()
    
    def load_model(self):
        """Load the trained SVM model"""
        try:
            model_path = settings.NIDS_CONFIG['MODEL_PATH']
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.label_encoder = model_data['label_encoder']
                self.feature_names = model_data['feature_names']
            logger.info("Model loaded successfully for CSV analysis")
            return True
        except Exception as e:
            logger.error(f"Error loading model for CSV analysis: {e}")
            return False
    
    def analyze_csv_file(self, file_path, filename, analysis_id):
        """
        Analyze a CSV file and store results in the database
        
        Args:
            file_path: Path to the CSV file
            filename: Original filename
            analysis_id: ID of the CSVAnalysis record
        """
        start_time = time.time()
        
        try:
            # Get the analysis record
            analysis = CSVAnalysis.objects.get(id=analysis_id)
            analysis.status = 'processing'
            analysis.save()
            
            # Read CSV file
            logger.info(f"Reading CSV file: {filename}")
            df = pd.read_csv(file_path)
            
            analysis.total_rows = len(df)
            analysis.save()
            
            # Clean the data using the same process as training
            logger.info("Cleaning CSV data...")
            df_clean = self.data_cleaner.clean_network_data(df.copy())
            
            if len(df_clean) == 0:
                raise ValueError("No valid rows remaining after data cleaning")
            
            analysis.processed_rows = len(df_clean)
            analysis.failed_rows = analysis.total_rows - analysis.processed_rows
            analysis.save()
            
            # Prepare features for prediction
            logger.info("Preparing features for prediction...")
            feature_columns = [col for col in df_clean.columns 
                             if col not in ['Flow ID', 'Src IP', 'Dst IP', 'Protocol', 'Timestamp', 'Label']]
            
            # Ensure all required features are present
            missing_features = set(self.feature_names) - set(feature_columns)
            for feature in missing_features:
                df_clean[feature] = 0.0
            
            # Select only the features used in training
            X = df_clean[self.feature_names].fillna(0)
            
            # Scale features
            logger.info("Scaling features...")
            X_scaled = self.scaler.transform(X)
            
            # Make predictions
            logger.info("Making predictions...")
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            # Process results and save to database
            logger.info("Saving results to database...")
            attack_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
            
            for idx, (_, row) in enumerate(df_clean.iterrows()):
                prediction = predictions[idx]
                probs = probabilities[idx]
                
                # Get original label if present
                original_label = ''
                if 'Label' in row:
                    original_label = str(row['Label'])
                
                # Create flow result record
                CSVFlowResult.objects.create(
                    analysis=analysis,
                    flow_id=str(row.get('Flow ID', f'flow_{idx}')),
                    src_ip=str(row.get('Src IP', '0.0.0.0')),
                    src_port=int(row.get('Src Port', 0)),
                    dst_ip=str(row.get('Dst IP', '0.0.0.0')),
                    dst_port=int(row.get('Dst Port', 0)),
                    protocol=str(row.get('Protocol', 'TCP')),
                    original_label=original_label,
                    predicted_class=int(prediction),
                    confidence=float(max(probs)),
                    prob_normal=float(probs[0]) if len(probs) > 0 else 0.0,
                    prob_ddos=float(probs[1]) if len(probs) > 1 else 0.0,
                    prob_bruteforce=float(probs[2]) if len(probs) > 2 else 0.0,
                    prob_portscan=float(probs[3]) if len(probs) > 3 else 0.0,
                    prob_sql_injection=float(probs[4]) if len(probs) > 4 else 0.0,
                    is_valid=True,
                    row_number=idx + 1
                )
                
                attack_counts[prediction] += 1
            
            # Update analysis with final results
            processing_time = time.time() - start_time
            analysis.normal_count = attack_counts[0]
            analysis.ddos_count = attack_counts[1]
            analysis.bruteforce_count = attack_counts[2]
            analysis.portscan_count = attack_counts[3]
            analysis.sql_injection_count = attack_counts[4]
            analysis.processing_time = processing_time
            analysis.status = 'completed'
            analysis.save()
            
            logger.info(f"CSV analysis completed successfully in {processing_time:.2f} seconds")
            logger.info(f"Results: Normal={attack_counts[0]}, DDoS={attack_counts[1]}, "
                       f"Brute Force={attack_counts[2]}, Port Scan={attack_counts[3]}, "
                       f"SQL Injection={attack_counts[4]}")
            
        except Exception as e:
            # Update analysis with error
            processing_time = time.time() - start_time
            analysis.status = 'failed'
            analysis.error_message = str(e)
            analysis.processing_time = processing_time
            analysis.save()
            
            logger.error(f"CSV analysis failed: {e}")
            raise e
    
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

# Global CSV analyzer instance
csv_analyzer = CSVAnalyzer()
