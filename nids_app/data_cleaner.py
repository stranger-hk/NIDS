import pandas as pd
import numpy as np
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkDataCleaner:
    """
    Enhanced network data cleaner that creates missing features through calculation
    or intelligent defaults to ensure compatibility with trained models
    """
    
    def __init__(self):
        self.validation_stats = {
            'total_processed': 0,
            'total_cleaned': 0,
            'features_added': 0,
            'validation_failures': {}
        }
        
        # Define all expected features for network flow analysis
        self.expected_features = [
            # Basic flow information
            'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
            
            # Forward packet statistics
            'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
            
            # Backward packet statistics  
            'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
            
            # Flow rates
            'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s',
            
            # Inter-arrival times
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            
            # TCP flags
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
            'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
            
            # Header lengths
            'Fwd Header Len', 'Bwd Header Len',
            
            # Packet statistics
            'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
            
            # Size features
            'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
            
            # Bulk features
            'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
            'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
            
            # Subflow features
            'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
            
            # Window features
            'Init Fwd Win Byts', 'Init Bwd Win Byts',
            
            # Active features
            'Fwd Act Data Pkts', 'Fwd Seg Size Min',
            
            # Activity times
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
    
    def clean_flow_features(self, features_dict):
        """
        Clean and validate network flow features, adding missing ones through calculation
        
        Args:
            features_dict: Dictionary of extracted features
            
        Returns:
            dict: Cleaned and validated features with all expected features present
        """
        try:
            self.validation_stats['total_processed'] += 1
            
            # Convert to DataFrame for easier processing
            df = pd.DataFrame([features_dict])
            
            # Add missing features through calculation or defaults
            df = self._add_missing_features(df)
            
            # Apply cleaning rules
            df_clean = self._apply_cleaning_rules(df)
            
            if len(df_clean) == 0:
                logger.warning("Flow failed validation and was filtered out")
                return None
            
            self.validation_stats['total_cleaned'] += 1
            
            # Convert back to dictionary
            cleaned_features = df_clean.iloc[0].to_dict()
            
            # Ensure all values are numeric and finite
            for key, value in cleaned_features.items():
                if key not in ['Flow ID', 'Src IP', 'Dst IP', 'Protocol', 'Timestamp']:
                    try:
                        cleaned_value = float(value)
                        if np.isnan(cleaned_value) or np.isinf(cleaned_value):
                            cleaned_features[key] = 0.0
                        else:
                            cleaned_features[key] = cleaned_value
                    except (ValueError, TypeError):
                        cleaned_features[key] = 0.0
            
            return cleaned_features
            
        except Exception as e:
            logger.error(f"Error cleaning flow features: {e}")
            return None
    
    def _add_missing_features(self, df):
        """Add missing features through calculation or intelligent defaults"""
        df = df.copy()
        
        # Basic packet counts (if missing, set to 0)
        if 'Tot Fwd Pkts' not in df.columns:
            df['Tot Fwd Pkts'] = 0
        if 'Tot Bwd Pkts' not in df.columns:
            df['Tot Bwd Pkts'] = 0
            
        # Total packet lengths
        if 'TotLen Fwd Pkts' not in df.columns:
            df['TotLen Fwd Pkts'] = df.get('Tot Fwd Pkts', 0) * 64  # Assume 64 bytes per packet
        if 'TotLen Bwd Pkts' not in df.columns:
            df['TotLen Bwd Pkts'] = df.get('Tot Bwd Pkts', 0) * 64
            
        # Flow duration (if missing, calculate from IAT or set default)
        if 'Flow Duration' not in df.columns:
            if 'Flow IAT Mean' in df.columns and df['Flow IAT Mean'].iloc[0] > 0:
                total_packets = df.get('Tot Fwd Pkts', 0).iloc[0] + df.get('Tot Bwd Pkts', 0).iloc[0]
                df['Flow Duration'] = df['Flow IAT Mean'] * max(total_packets - 1, 1)
            else:
                df['Flow Duration'] = 1.0  # Default 1 second
        
        # Forward packet length statistics
        self._add_packet_length_stats(df, 'Fwd', df.get('Tot Fwd Pkts', 0).iloc[0], df.get('TotLen Fwd Pkts', 0).iloc[0])
        
        # Backward packet length statistics  
        self._add_packet_length_stats(df, 'Bwd', df.get('Tot Bwd Pkts', 0).iloc[0], df.get('TotLen Bwd Pkts', 0).iloc[0])
        
        # Flow rates
        self._add_flow_rates(df)
        
        # Inter-arrival time features
        self._add_iat_features(df)
        
        # TCP flag features
        self._add_tcp_flag_features(df)
        
        # Header length features
        self._add_header_features(df)
        
        # Packet statistics
        self._add_packet_statistics(df)
        
        # Size and ratio features
        self._add_size_features(df)
        
        # Bulk transfer features
        self._add_bulk_features(df)
        
        # Subflow features
        self._add_subflow_features(df)
        
        # Window features
        self._add_window_features(df)
        
        # Active data features
        self._add_active_features(df)
        
        # Activity time features
        self._add_activity_time_features(df)
        
        return df
    
    def _add_packet_length_stats(self, df, direction, packet_count, total_length):
        """Add packet length statistics for forward or backward direction"""
        prefix = f'{direction} Pkt Len'
        
        if packet_count > 0:
            avg_length = total_length / packet_count
            
            # If stats don't exist, calculate reasonable estimates
            if f'{prefix} Mean' not in df.columns:
                df[f'{prefix} Mean'] = avg_length
            if f'{prefix} Max' not in df.columns:
                df[f'{prefix} Max'] = min(avg_length * 1.5, 1500)  # MTU limit
            if f'{prefix} Min' not in df.columns:
                df[f'{prefix} Min'] = max(avg_length * 0.5, 20)  # Minimum reasonable packet size
            if f'{prefix} Std' not in df.columns:
                df[f'{prefix} Std'] = avg_length * 0.3  # Reasonable standard deviation
        else:
            # No packets in this direction
            for stat in ['Mean', 'Max', 'Min', 'Std']:
                if f'{prefix} {stat}' not in df.columns:
                    df[f'{prefix} {stat}'] = 0.0
    
    def _add_flow_rates(self, df):
        """Add flow rate features"""
        duration = df.get('Flow Duration', 1.0).iloc[0]
        if duration <= 0:
            duration = 1.0
            
        # Bytes per second
        if 'Flow Byts/s' not in df.columns:
            total_bytes = df.get('TotLen Fwd Pkts', 0).iloc[0] + df.get('TotLen Bwd Pkts', 0).iloc[0]
            df['Flow Byts/s'] = total_bytes / duration
            
        # Packets per second
        if 'Flow Pkts/s' not in df.columns:
            total_packets = df.get('Tot Fwd Pkts', 0).iloc[0] + df.get('Tot Bwd Pkts', 0).iloc[0]
            df['Flow Pkts/s'] = total_packets / duration
            
        # Forward packets per second
        if 'Fwd Pkts/s' not in df.columns:
            df['Fwd Pkts/s'] = df.get('Tot Fwd Pkts', 0).iloc[0] / duration
            
        # Backward packets per second
        if 'Bwd Pkts/s' not in df.columns:
            df['Bwd Pkts/s'] = df.get('Tot Bwd Pkts', 0).iloc[0] / duration
    
    def _add_iat_features(self, df):
        """Add Inter-Arrival Time features"""
        duration = df.get('Flow Duration', 1.0).iloc[0]
        total_packets = df.get('Tot Fwd Pkts', 0).iloc[0] + df.get('Tot Bwd Pkts', 0).iloc[0]
        fwd_packets = df.get('Tot Fwd Pkts', 0).iloc[0]
        bwd_packets = df.get('Tot Bwd Pkts', 0).iloc[0]
        
        # Flow IAT features
        if total_packets > 1:
            avg_iat = duration / (total_packets - 1)
            for feature in ['Flow IAT Mean', 'Flow IAT Max', 'Flow IAT Min']:
                if feature not in df.columns:
                    df[feature] = avg_iat
            if 'Flow IAT Std' not in df.columns:
                df['Flow IAT Std'] = avg_iat * 0.3
        else:
            for feature in ['Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min']:
                if feature not in df.columns:
                    df[feature] = 0.0
        
        # Forward IAT features
        if fwd_packets > 1:
            fwd_duration = duration * (fwd_packets / max(total_packets, 1))
            fwd_avg_iat = fwd_duration / (fwd_packets - 1)
            
            if 'Fwd IAT Tot' not in df.columns:
                df['Fwd IAT Tot'] = fwd_duration
            for feature in ['Fwd IAT Mean', 'Fwd IAT Max', 'Fwd IAT Min']:
                if feature not in df.columns:
                    df[feature] = fwd_avg_iat
            if 'Fwd IAT Std' not in df.columns:
                df['Fwd IAT Std'] = fwd_avg_iat * 0.3
        else:
            for feature in ['Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min']:
                if feature not in df.columns:
                    df[feature] = 0.0
        
        # Backward IAT features
        if bwd_packets > 1:
            bwd_duration = duration * (bwd_packets / max(total_packets, 1))
            bwd_avg_iat = bwd_duration / (bwd_packets - 1)
            
            if 'Bwd IAT Tot' not in df.columns:
                df['Bwd IAT Tot'] = bwd_duration
            for feature in ['Bwd IAT Mean', 'Bwd IAT Max', 'Bwd IAT Min']:
                if feature not in df.columns:
                    df[feature] = bwd_avg_iat
            if 'Bwd IAT Std' not in df.columns:
                df['Bwd IAT Std'] = bwd_avg_iat * 0.3
        else:
            for feature in ['Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min']:
                if feature not in df.columns:
                    df[feature] = 0.0
    
    def _add_tcp_flag_features(self, df):
        """Add TCP flag features"""
        # PSH and URG flags per direction
        for direction in ['Fwd', 'Bwd']:
            for flag in ['PSH', 'URG']:
                feature = f'{direction} {flag} Flags'
                if feature not in df.columns:
                    df[feature] = 0
        
        # Overall flag counts
        flag_features = ['FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
                        'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt']
        
        for feature in flag_features:
            if feature not in df.columns:
                df[feature] = 0
    
    def _add_header_features(self, df):
        """Add header length features"""
        # Estimate header lengths based on packet counts
        fwd_packets = df.get('Tot Fwd Pkts', 0).iloc[0]
        bwd_packets = df.get('Tot Bwd Pkts', 0).iloc[0]
        
        if 'Fwd Header Len' not in df.columns:
            df['Fwd Header Len'] = fwd_packets * 20  # Assume 20 bytes per TCP header
        if 'Bwd Header Len' not in df.columns:
            df['Bwd Header Len'] = bwd_packets * 20
    
    def _add_packet_statistics(self, df):
        """Add overall packet statistics"""
        fwd_len = df.get('TotLen Fwd Pkts', 0).iloc[0]
        bwd_len = df.get('TotLen Bwd Pkts', 0).iloc[0]
        total_len = fwd_len + bwd_len
        
        fwd_packets = df.get('Tot Fwd Pkts', 0).iloc[0]
        bwd_packets = df.get('Tot Bwd Pkts', 0).iloc[0]
        total_packets = fwd_packets + bwd_packets
        
        if total_packets > 0:
            avg_len = total_len / total_packets
            
            if 'Pkt Len Mean' not in df.columns:
                df['Pkt Len Mean'] = avg_len
            if 'Pkt Len Max' not in df.columns:
                df['Pkt Len Max'] = min(avg_len * 1.5, 1500)
            if 'Pkt Len Min' not in df.columns:
                df['Pkt Len Min'] = max(avg_len * 0.5, 20)
            if 'Pkt Len Std' not in df.columns:
                df['Pkt Len Std'] = avg_len * 0.3
            if 'Pkt Len Var' not in df.columns:
                df['Pkt Len Var'] = (avg_len * 0.3) ** 2
        else:
            for feature in ['Pkt Len Mean', 'Pkt Len Max', 'Pkt Len Min', 'Pkt Len Std', 'Pkt Len Var']:
                if feature not in df.columns:
                    df[feature] = 0.0
    
    def _add_size_features(self, df):
        """Add size and ratio features"""
        fwd_packets = df.get('Tot Fwd Pkts', 0).iloc[0]
        bwd_packets = df.get('Tot Bwd Pkts', 0).iloc[0]
        fwd_len = df.get('TotLen Fwd Pkts', 0).iloc[0]
        bwd_len = df.get('TotLen Bwd Pkts', 0).iloc[0]
        total_len = fwd_len + bwd_len
        total_packets = fwd_packets + bwd_packets
        
        # Down/Up ratio
        if 'Down/Up Ratio' not in df.columns:
            df['Down/Up Ratio'] = bwd_packets / max(fwd_packets, 1)
        
        # Average packet size
        if 'Pkt Size Avg' not in df.columns:
            df['Pkt Size Avg'] = total_len / max(total_packets, 1)
        
        # Segment size averages
        if 'Fwd Seg Size Avg' not in df.columns:
            df['Fwd Seg Size Avg'] = fwd_len / max(fwd_packets, 1)
        if 'Bwd Seg Size Avg' not in df.columns:
            df['Bwd Seg Size Avg'] = bwd_len / max(bwd_packets, 1)
    
    def _add_bulk_features(self, df):
        """Add bulk transfer features"""
        # These are typically 0 for most flows
        bulk_features = ['Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
                        'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg']
        
        for feature in bulk_features:
            if feature not in df.columns:
                df[feature] = 0.0
    
    def _add_subflow_features(self, df):
        """Add subflow features"""
        # Subflow features are typically the same as main flow for single flows
        if 'Subflow Fwd Pkts' not in df.columns:
            df['Subflow Fwd Pkts'] = df.get('Tot Fwd Pkts', 0)
        if 'Subflow Fwd Byts' not in df.columns:
            df['Subflow Fwd Byts'] = df.get('TotLen Fwd Pkts', 0)
        if 'Subflow Bwd Pkts' not in df.columns:
            df['Subflow Bwd Pkts'] = df.get('Tot Bwd Pkts', 0)
        if 'Subflow Bwd Byts' not in df.columns:
            df['Subflow Bwd Byts'] = df.get('TotLen Bwd Pkts', 0)
    
    def _add_window_features(self, df):
        """Add window size features"""
        # Default TCP window sizes
        if 'Init Fwd Win Byts' not in df.columns:
            df['Init Fwd Win Byts'] = 8192  # Default TCP window
        if 'Init Bwd Win Byts' not in df.columns:
            df['Init Bwd Win Byts'] = 8192
    
    def _add_active_features(self, df):
        """Add active data features"""
        if 'Fwd Act Data Pkts' not in df.columns:
            df['Fwd Act Data Pkts'] = df.get('Tot Fwd Pkts', 0)
        if 'Fwd Seg Size Min' not in df.columns:
            df['Fwd Seg Size Min'] = df.get('Fwd Pkt Len Min', 0)
    
    def _add_activity_time_features(self, df):
        """Add activity and idle time features"""
        # These are typically 0 for most flows
        activity_features = ['Active Mean', 'Active Std', 'Active Max', 'Active Min',
                           'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
        
        for feature in activity_features:
            if feature not in df.columns:
                df[feature] = 0.0
    
    def clean_network_data(self, df):
        """
        Clean network data from CSV files, adding missing features
        
        Args:
            df: pandas DataFrame with network flow data
            
        Returns:
            pandas DataFrame: Cleaned data with all expected features
        """
        df_clean = df.copy()
        print(f"Initial number of rows: {len(df_clean)}")
        
        try:
            # Step 1: Validate critical identifiers
            if 'Flow ID' in df_clean.columns:
                df_clean = df_clean.dropna(subset=['Flow ID'])
                print(f"Rows after validating Flow ID (non-null): {len(df_clean)}")
                if len(df_clean) == 0:
                    raise ValueError("Dataset is empty after validating Flow ID.")
            
            if 'Timestamp' in df_clean.columns:
                df_clean['Timestamp'] = pd.to_datetime(df_clean['Timestamp'], errors='coerce', format='%d/%m/%Y %I:%M:%S %p')
                df_clean = df_clean.dropna(subset=['Timestamp'])
                print(f"Rows after validating Timestamp: {len(df_clean)}")
                if len(df_clean) == 0:
                    raise ValueError("Dataset is empty after validating Timestamp.")
            
            if 'Label' in df_clean.columns:
                df_clean = df_clean.dropna(subset=['Label'])
                print(f"Rows after validating Label (non-null): {len(df_clean)}")
                if len(df_clean) == 0:
                    raise ValueError("Dataset is empty after validating Label.")
            
            # Step 2: Drop duplicates
            df_clean = df_clean.drop_duplicates()
            print(f"Rows after dropping duplicates: {len(df_clean)}")
            if len(df_clean) == 0:
                raise ValueError("Dataset is empty after dropping duplicates.")
            
            # Step 3: Add missing features for each row
            print("Adding missing features...")
            df_clean = self._add_missing_features(df_clean)
            
            # Step 4: Apply cleaning rules
            df_clean = self._apply_cleaning_rules(df_clean)
            
            print(f"Final cleaned rows: {len(df_clean)}")
            print(f"Total features after cleaning: {len(df_clean.columns)}")
            
            return df_clean
            
        except Exception as e:
            print(f"Error in clean_network_data: {e}")
            raise e
    
    def _apply_cleaning_rules(self, df):
        """Apply the same cleaning rules as used during training"""
        df_clean = df.copy()
        
        try:
            # Handle missing values and 'Infinity' for feature columns
            feature_columns = [col for col in df_clean.columns if col not in ['Flow ID', 'Src IP', 'Dst IP', 'Protocol', 'Timestamp', 'Label']]
            df_clean[feature_columns] = df_clean[feature_columns].replace(['Infinity', 'NaN', np.inf, -np.inf], np.nan)
            
            # Fill missing values with 0 for numeric columns (since we've already calculated most features)
            numeric_cols = df_clean[feature_columns].select_dtypes(include=[np.number]).columns
            for col in numeric_cols:
                if df_clean[col].isna().any():
                    df_clean[col] = df_clean[col].fillna(0.0)
            
            # Validate specific constraints
            df_clean = self._validate_constraints(df_clean)
            
            # Remove any remaining NaN values
            df_clean = df_clean.dropna(subset=feature_columns)
            
            return df_clean
            
        except Exception as e:
            logger.error(f"Error applying cleaning rules: {e}")
            return pd.DataFrame()  # Return empty DataFrame on error
    
    def _validate_constraints(self, df):
        """Validate logical constraints between features"""
        # Ensure non-negative values for counts and durations
        count_features = ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Flow Duration']
        for feature in count_features:
            if feature in df.columns:
                df[feature] = df[feature].clip(lower=0)
        
        # Ensure packet length max >= min
        for direction in ['Fwd', 'Bwd', '']:
            prefix = f'{direction} Pkt Len' if direction else 'Pkt Len'
            max_col = f'{prefix} Max'
            min_col = f'{prefix} Min'
            
            if max_col in df.columns and min_col in df.columns:
                # Ensure max >= min
                df[max_col] = np.maximum(df[max_col], df[min_col])
        
        # Ensure rates are non-negative
        rate_features = [col for col in df.columns if '/s' in col or 'Rate' in col]
        for feature in rate_features:
            df[feature] = df[feature].clip(lower=0)
        
        return df
    
    def get_cleaning_stats(self):
        """Get cleaning statistics"""
        success_rate = (self.validation_stats['total_cleaned'] / 
                       max(self.validation_stats['total_processed'], 1)) * 100
        
        return {
            'total_processed': self.validation_stats['total_processed'],
            'total_cleaned': self.validation_stats['total_cleaned'],
            'features_added': self.validation_stats['features_added'],
            'success_rate': success_rate,
            'validation_failures': self.validation_stats['validation_failures']
        }
