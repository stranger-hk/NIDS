import pandas as pd
import numpy as np
import os
import sys

def clean_network_data(df):
    df_clean = df.copy()
    print(f"Initial number of rows: {len(df_clean)}")
    
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
    
    # Handle missing values and 'Infinity' for feature columns (preserve original where valid)
    feature_columns = [col for col in df_clean.columns if col not in ['Flow ID', 'Label', 'is attack']]
    df_clean[feature_columns] = df_clean[feature_columns].replace(['Infinity', 'NaN'], np.nan)
    numeric_cols = df_clean[feature_columns].select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        df_clean[col] = df_clean[col].fillna(df_clean[col].median())
        print(f"Column {col} - NaN count after filling: {df_clean[col].isna().sum()}")
    categorical_cols = df_clean[feature_columns].select_dtypes(include=['object']).columns
    for col in categorical_cols:
        df_clean[col] = df_clean[col].fillna(df_clean[col].mode()[0] if not df_clean[col].mode().empty else 'Unknown')
        print(f"Column {col} - NaN count after filling: {df_clean[col].isna().sum()}")
    print(f"Rows after handling missing values: {len(df_clean)}")
    if len(df_clean) == 0:
        raise ValueError("Dataset is empty after handling missing values.")
    
    # Validate IP addresses (0.0.0.0 to 255.255.255.255)
    ip_columns = ['Src IP', 'Dst IP']
    for col in ip_columns:
        if col in df_clean.columns:
            df_clean = df_clean[df_clean[col].str.match(
                r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                na=False
            )]
            print(f"Rows after validating {col}: {len(df_clean)}")
            if len(df_clean) == 0:
                raise ValueError(f"Dataset is empty after validating {col}.")
    
    # Clean port numbers (0 to 65,535)
    port_columns = ['Src Port', 'Dst Port']
    for col in port_columns:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')
            df_clean = df_clean[df_clean[col].between(0, 65535, inclusive='both')]
            print(f"Rows after validating {col}: {len(df_clean)} (Min: {df_clean[col].min()}, Max: {df_clean[col].max()})")
            if len(df_clean) == 0:
                raise ValueError(f"Dataset is empty after validating {col}.")
    
    # Validate protocol (retain all valid numeric or string values)
    if 'Protocol' in df_clean.columns:
        def clean_protocol(x):
            if pd.isna(x):
                return None
            try:
                x_str = str(x).replace('.', '')
                if x_str.isdigit():
                    return int(x_str)
                return x
            except (ValueError, TypeError):
                print(f"Invalid Protocol value encountered: {x}")
                return None
        df_clean['Protocol'] = df_clean['Protocol'].apply(clean_protocol)
        df_clean = df_clean.dropna(subset=['Protocol'])
        print(f"Rows after validating Protocol: {len(df_clean)}")
        if len(df_clean) == 0:
            raise ValueError("Dataset is empty after validating Protocol.")
    
    # Remove unreasonable values for feature columns (preserve original values where valid)
    if 'Flow Duration' in df_clean.columns:
        df_clean['Flow Duration'] = pd.to_numeric(df_clean['Flow Duration'], errors='coerce')
        df_clean = df_clean[df_clean['Flow Duration'] >= 0]
        print(f"Rows after validating Flow Duration: {len(df_clean)} (Min: {df_clean['Flow Duration'].min()}, Max: {df_clean['Flow Duration'].max()})")
    if 'Tot Fwd Pkts' in df_clean.columns:
        df_clean['Tot Fwd Pkts'] = pd.to_numeric(df_clean['Tot Fwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['Tot Fwd Pkts'] >= 0]
        print(f"Rows after validating Tot Fwd Pkts: {len(df_clean)}")
    if 'Tot Bwd Pkts' in df_clean.columns:
        df_clean['Tot Bwd Pkts'] = pd.to_numeric(df_clean['Tot Bwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['Tot Bwd Pkts'] >= 0]
        print(f"Rows after validating Tot Bwd Pkts: {len(df_clean)}")
    if 'TotLen Fwd Pkts' in df_clean.columns:
        df_clean['TotLen Fwd Pkts'] = pd.to_numeric(df_clean['TotLen Fwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['TotLen Fwd Pkts'] >= 0]
        print(f"Rows after validating TotLen Fwd Pkts: {len(df_clean)}")
    if 'TotLen Bwd Pkts' in df_clean.columns:
        df_clean['TotLen Bwd Pkts'] = pd.to_numeric(df_clean['TotLen Bwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['TotLen Bwd Pkts'] >= 0]
        print(f"Rows after validating TotLen Bwd Pkts: {len(df_clean)}")
    if 'Fwd Pkt Len Max' in df_clean.columns and 'Fwd Pkt Len Min' in df_clean.columns:
        df_clean['Fwd Pkt Len Max'] = pd.to_numeric(df_clean['Fwd Pkt Len Max'], errors='coerce')
        df_clean['Fwd Pkt Len Min'] = pd.to_numeric(df_clean['Fwd Pkt Len Min'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Pkt Len Max'] >= df_clean['Fwd Pkt Len Min']]
        df_clean = df_clean[df_clean['Fwd Pkt Len Max'] <= 1500]
        print(f"Rows after validating Fwd Pkt Len consistency: {len(df_clean)}")
    if 'Fwd Pkt Len Mean' in df_clean.columns and 'Fwd Pkt Len Max' in df_clean.columns:
        df_clean['Fwd Pkt Len Mean'] = pd.to_numeric(df_clean['Fwd Pkt Len Mean'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Pkt Len Mean'] >= 0]
        df_clean = df_clean[df_clean['Fwd Pkt Len Mean'] <= df_clean['Fwd Pkt Len Max']]
        print(f"Rows after validating Fwd Pkt Len Mean: {len(df_clean)}")
    if 'Fwd Pkt Len Std' in df_clean.columns:
        df_clean['Fwd Pkt Len Std'] = pd.to_numeric(df_clean['Fwd Pkt Len Std'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Pkt Len Std'] >= 0]
        print(f"Rows after validating Fwd Pkt Len Std: {len(df_clean)}")
    if 'Bwd Pkt Len Max' in df_clean.columns and 'Bwd Pkt Len Min' in df_clean.columns:
        df_clean['Bwd Pkt Len Max'] = pd.to_numeric(df_clean['Bwd Pkt Len Max'], errors='coerce')
        df_clean['Bwd Pkt Len Min'] = pd.to_numeric(df_clean['Bwd Pkt Len Min'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Pkt Len Max'] >= df_clean['Bwd Pkt Len Min']]
        df_clean = df_clean[df_clean['Bwd Pkt Len Max'] <= 1500]
        print(f"Rows after validating Bwd Pkt Len consistency: {len(df_clean)}")
    if 'Bwd Pkt Len Mean' in df_clean.columns and 'Bwd Pkt Len Max' in df_clean.columns:
        df_clean['Bwd Pkt Len Mean'] = pd.to_numeric(df_clean['Bwd Pkt Len Mean'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Pkt Len Mean'] >= 0]
        df_clean = df_clean[df_clean['Bwd Pkt Len Mean'] <= df_clean['Bwd Pkt Len Max']]
        print(f"Rows after validating Bwd Pkt Len Mean: {len(df_clean)}")
    if 'Bwd Pkt Len Std' in df_clean.columns:
        df_clean['Bwd Pkt Len Std'] = pd.to_numeric(df_clean['Bwd Pkt Len Std'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Pkt Len Std'] >= 0]
        print(f"Rows after validating Bwd Pkt Len Std: {len(df_clean)}")
    if 'Flow Byts/s' in df_clean.columns:
        df_clean['Flow Byts/s'] = pd.to_numeric(df_clean['Flow Byts/s'], errors='coerce')
        df_clean = df_clean[(df_clean['Flow Byts/s'] >= 0) & (df_clean['Flow Byts/s'].notna())]
        print(f"Rows after validating Flow Byts/s: {len(df_clean)}")
    if 'Flow Pkts/s' in df_clean.columns:
        df_clean['Flow Pkts/s'] = pd.to_numeric(df_clean['Flow Pkts/s'], errors='coerce')
        df_clean = df_clean[(df_clean['Flow Pkts/s'] >= 0) & (df_clean['Flow Pkts/s'].notna())]
        print(f"Rows after validating Flow Pkts/s: {len(df_clean)}")
    if 'Flow IAT Mean' in df_clean.columns:
        df_clean['Flow IAT Mean'] = pd.to_numeric(df_clean['Flow IAT Mean'], errors='coerce')
        df_clean = df_clean[(df_clean['Flow IAT Mean'] >= 0) & (df_clean['Flow IAT Mean'] <= 86400000)]  # 1 day in µs
        print(f"Rows after validating Flow IAT Mean: {len(df_clean)}")
    if 'Flow IAT Std' in df_clean.columns:
        df_clean['Flow IAT Std'] = pd.to_numeric(df_clean['Flow IAT Std'], errors='coerce')
        df_clean = df_clean[df_clean['Flow IAT Std'] >= 0]
        print(f"Rows after validating Flow IAT Std: {len(df_clean)}")
    if 'Flow IAT Max' in df_clean.columns:
        df_clean['Flow IAT Max'] = pd.to_numeric(df_clean['Flow IAT Max'], errors='coerce')
        df_clean = df_clean[df_clean['Flow IAT Max'] >= 0]
        print(f"Rows after validating Flow IAT Max: {len(df_clean)}")
    if 'Flow IAT Min' in df_clean.columns:
        df_clean['Flow IAT Min'] = pd.to_numeric(df_clean['Flow IAT Min'], errors='coerce')
        df_clean = df_clean[df_clean['Flow IAT Min'] >= 0]
        print(f"Rows after validating Flow IAT Min: {len(df_clean)}")
    if 'Fwd IAT Tot' in df_clean.columns:
        df_clean['Fwd IAT Tot'] = pd.to_numeric(df_clean['Fwd IAT Tot'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd IAT Tot'] >= 0]
        print(f"Rows after validating Fwd IAT Tot: {len(df_clean)}")
    if 'Fwd IAT Mean' in df_clean.columns:
        df_clean['Fwd IAT Mean'] = pd.to_numeric(df_clean['Fwd IAT Mean'], errors='coerce')
        df_clean = df_clean[(df_clean['Fwd IAT Mean'] >= 0) & (df_clean['Fwd IAT Mean'] <= 86400000)]
        print(f"Rows after validating Fwd IAT Mean: {len(df_clean)}")
    if 'Fwd IAT Std' in df_clean.columns:
        df_clean['Fwd IAT Std'] = pd.to_numeric(df_clean['Fwd IAT Std'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd IAT Std'] >= 0]
        print(f"Rows after validating Fwd IAT Std: {len(df_clean)}")
    if 'Fwd IAT Max' in df_clean.columns:
        df_clean['Fwd IAT Max'] = pd.to_numeric(df_clean['Fwd IAT Max'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd IAT Max'] >= 0]
        print(f"Rows after validating Fwd IAT Max: {len(df_clean)}")
    if 'Fwd IAT Min' in df_clean.columns:
        df_clean['Fwd IAT Min'] = pd.to_numeric(df_clean['Fwd IAT Min'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd IAT Min'] >= 0]
        print(f"Rows after validating Fwd IAT Min: {len(df_clean)}")
    if 'Bwd IAT Tot' in df_clean.columns:
        df_clean['Bwd IAT Tot'] = pd.to_numeric(df_clean['Bwd IAT Tot'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd IAT Tot'] >= 0]
        print(f"Rows after validating Bwd IAT Tot: {len(df_clean)}")
    if 'Bwd IAT Mean' in df_clean.columns:
        df_clean['Bwd IAT Mean'] = pd.to_numeric(df_clean['Bwd IAT Mean'], errors='coerce')
        df_clean = df_clean[(df_clean['Bwd IAT Mean'] >= 0) & (df_clean['Bwd IAT Mean'] <= 86400000)]
        print(f"Rows after validating Bwd IAT Mean: {len(df_clean)}")
    if 'Bwd IAT Std' in df_clean.columns:
        df_clean['Bwd IAT Std'] = pd.to_numeric(df_clean['Bwd IAT Std'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd IAT Std'] >= 0]
        print(f"Rows after validating Bwd IAT Std: {len(df_clean)}")
    if 'Bwd IAT Max' in df_clean.columns:
        df_clean['Bwd IAT Max'] = pd.to_numeric(df_clean['Bwd IAT Max'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd IAT Max'] >= 0]
        print(f"Rows after validating Bwd IAT Max: {len(df_clean)}")
    if 'Bwd IAT Min' in df_clean.columns:
        df_clean['Bwd IAT Min'] = pd.to_numeric(df_clean['Bwd IAT Min'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd IAT Min'] >= 0]
        print(f"Rows after validating Bwd IAT Min: {len(df_clean)}")
    if 'Fwd PSH Flags' in df_clean.columns:
        df_clean['Fwd PSH Flags'] = pd.to_numeric(df_clean['Fwd PSH Flags'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd PSH Flags'].isin([0, 1])]
        print(f"Rows after validating Fwd PSH Flags: {len(df_clean)}")
    if 'Bwd PSH Flags' in df_clean.columns:
        df_clean['Bwd PSH Flags'] = pd.to_numeric(df_clean['Bwd PSH Flags'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd PSH Flags'].isin([0, 1])]
        print(f"Rows after validating Bwd PSH Flags: {len(df_clean)}")
    if 'Fwd URG Flags' in df_clean.columns:
        df_clean['Fwd URG Flags'] = pd.to_numeric(df_clean['Fwd URG Flags'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd URG Flags'].isin([0, 1])]
        print(f"Rows after validating Fwd URG Flags: {len(df_clean)}")
    if 'Bwd URG Flags' in df_clean.columns:
        df_clean['Bwd URG Flags'] = pd.to_numeric(df_clean['Bwd URG Flags'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd URG Flags'].isin([0, 1])]
        print(f"Rows after validating Bwd URG Flags: {len(df_clean)}")
    if 'Fwd Header Len' in df_clean.columns:
        df_clean['Fwd Header Len'] = pd.to_numeric(df_clean['Fwd Header Len'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Header Len'] >= 0]
        print(f"Rows after validating Fwd Header Len: {len(df_clean)}")
    if 'Bwd Header Len' in df_clean.columns:
        df_clean['Bwd Header Len'] = pd.to_numeric(df_clean['Bwd Header Len'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Header Len'] >= 0]
        print(f"Rows after validating Bwd Header Len: {len(df_clean)}")
    if 'Fwd Pkts/s' in df_clean.columns:
        df_clean['Fwd Pkts/s'] = pd.to_numeric(df_clean['Fwd Pkts/s'], errors='coerce')
        df_clean = df_clean[(df_clean['Fwd Pkts/s'] >= 0) & (df_clean['Fwd Pkts/s'].notna())]
        print(f"Rows after validating Fwd Pkts/s: {len(df_clean)}")
    if 'Bwd Pkts/s' in df_clean.columns:
        df_clean['Bwd Pkts/s'] = pd.to_numeric(df_clean['Bwd Pkts/s'], errors='coerce')
        df_clean = df_clean[(df_clean['Bwd Pkts/s'] >= 0) & (df_clean['Bwd Pkts/s'].notna())]
        print(f"Rows after validating Bwd Pkts/s: {len(df_clean)}")
    if 'Pkt Len Min' in df_clean.columns and 'Pkt Len Max' in df_clean.columns:
        df_clean['Pkt Len Min'] = pd.to_numeric(df_clean['Pkt Len Min'], errors='coerce')
        df_clean['Pkt Len Max'] = pd.to_numeric(df_clean['Pkt Len Max'], errors='coerce')
        df_clean = df_clean[df_clean['Pkt Len Min'] >= 0]
        df_clean = df_clean[df_clean['Pkt Len Max'] >= df_clean['Pkt Len Min']]
        df_clean = df_clean[df_clean['Pkt Len Max'] <= 1500]
        print(f"Rows after validating Pkt Len consistency: {len(df_clean)}")
    if 'Pkt Len Mean' in df_clean.columns and 'Pkt Len Max' in df_clean.columns:
        df_clean['Pkt Len Mean'] = pd.to_numeric(df_clean['Pkt Len Mean'], errors='coerce')
        df_clean = df_clean[df_clean['Pkt Len Mean'] >= 0]
        df_clean = df_clean[df_clean['Pkt Len Mean'] <= df_clean['Pkt Len Max']]
        print(f"Rows after validating Pkt Len Mean: {len(df_clean)}")
    if 'Pkt Len Std' in df_clean.columns:
        df_clean['Pkt Len Std'] = pd.to_numeric(df_clean['Pkt Len Std'], errors='coerce')
        df_clean = df_clean[df_clean['Pkt Len Std'] >= 0]
        print(f"Rows after validating Pkt Len Std: {len(df_clean)}")
    if 'Pkt Len Var' in df_clean.columns:
        df_clean['Pkt Len Var'] = pd.to_numeric(df_clean['Pkt Len Var'], errors='coerce')
        df_clean = df_clean[df_clean['Pkt Len Var'] >= 0]
        print(f"Rows after validating Pkt Len Var: {len(df_clean)}")
    if 'FIN Flag Cnt' in df_clean.columns:
        df_clean['FIN Flag Cnt'] = pd.to_numeric(df_clean['FIN Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['FIN Flag Cnt'] >= 0]
        print(f"Rows after validating FIN Flag Cnt: {len(df_clean)}")
    if 'SYN Flag Cnt' in df_clean.columns:
        df_clean['SYN Flag Cnt'] = pd.to_numeric(df_clean['SYN Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['SYN Flag Cnt'] >= 0]
        print(f"Rows after validating SYN Flag Cnt: {len(df_clean)}")
    if 'RST Flag Cnt' in df_clean.columns:
        df_clean['RST Flag Cnt'] = pd.to_numeric(df_clean['RST Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['RST Flag Cnt'] >= 0]
        print(f"Rows after validating RST Flag Cnt: {len(df_clean)}")
    if 'PSH Flag Cnt' in df_clean.columns:
        df_clean['PSH Flag Cnt'] = pd.to_numeric(df_clean['PSH Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['PSH Flag Cnt'] >= 0]
        print(f"Rows after validating PSH Flag Cnt: {len(df_clean)}")
    if 'ACK Flag Cnt' in df_clean.columns:
        df_clean['ACK Flag Cnt'] = pd.to_numeric(df_clean['ACK Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['ACK Flag Cnt'] >= 0]
        print(f"Rows after validating ACK Flag Cnt: {len(df_clean)}")
    if 'URG Flag Cnt' in df_clean.columns:
        df_clean['URG Flag Cnt'] = pd.to_numeric(df_clean['URG Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['URG Flag Cnt'] >= 0]
        print(f"Rows after validating URG Flag Cnt: {len(df_clean)}")
    if 'CWE Flag Count' in df_clean.columns:
        df_clean['CWE Flag Count'] = pd.to_numeric(df_clean['CWE Flag Count'], errors='coerce')
        df_clean = df_clean[df_clean['CWE Flag Count'] >= 0]
        print(f"Rows after validating CWE Flag Count: {len(df_clean)}")
    if 'ECE Flag Cnt' in df_clean.columns:
        df_clean['ECE Flag Cnt'] = pd.to_numeric(df_clean['ECE Flag Cnt'], errors='coerce')
        df_clean = df_clean[df_clean['ECE Flag Cnt'] >= 0]
        print(f"Rows after validating ECE Flag Cnt: {len(df_clean)}")
    if 'Down/Up Ratio' in df_clean.columns:
        df_clean['Down/Up Ratio'] = pd.to_numeric(df_clean['Down/Up Ratio'], errors='coerce')
        df_clean = df_clean[df_clean['Down/Up Ratio'] >= 0]
        print(f"Rows after validating Down/Up Ratio: {len(df_clean)}")
    if 'Pkt Size Avg' in df_clean.columns:
        df_clean['Pkt Size Avg'] = pd.to_numeric(df_clean['Pkt Size Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Pkt Size Avg'] >= 0]
        print(f"Rows after validating Pkt Size Avg: {len(df_clean)}")
    if 'Fwd Seg Size Avg' in df_clean.columns:
        df_clean['Fwd Seg Size Avg'] = pd.to_numeric(df_clean['Fwd Seg Size Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Seg Size Avg'] >= 0]
        print(f"Rows after validating Fwd Seg Size Avg: {len(df_clean)}")
    if 'Bwd Seg Size Avg' in df_clean.columns:
        df_clean['Bwd Seg Size Avg'] = pd.to_numeric(df_clean['Bwd Seg Size Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Seg Size Avg'] >= 0]
        print(f"Rows after validating Bwd Seg Size Avg: {len(df_clean)}")
    if 'Fwd Byts/b Avg' in df_clean.columns:
        df_clean['Fwd Byts/b Avg'] = pd.to_numeric(df_clean['Fwd Byts/b Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Byts/b Avg'] >= 0]
        print(f"Rows after validating Fwd Byts/b Avg: {len(df_clean)}")
    if 'Fwd Pkts/b Avg' in df_clean.columns:
        df_clean['Fwd Pkts/b Avg'] = pd.to_numeric(df_clean['Fwd Pkts/b Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Pkts/b Avg'] >= 0]
        print(f"Rows after validating Fwd Pkts/b Avg: {len(df_clean)}")
    if 'Fwd Blk Rate Avg' in df_clean.columns:
        df_clean['Fwd Blk Rate Avg'] = pd.to_numeric(df_clean['Fwd Blk Rate Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Blk Rate Avg'] >= 0]
        print(f"Rows after validating Fwd Blk Rate Avg: {len(df_clean)}")
    if 'Bwd Byts/b Avg' in df_clean.columns:
        df_clean['Bwd Byts/b Avg'] = pd.to_numeric(df_clean['Bwd Byts/b Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Byts/b Avg'] >= 0]
        print(f"Rows after validating Bwd Byts/b Avg: {len(df_clean)}")
    if 'Bwd Pkts/b Avg' in df_clean.columns:
        df_clean['Bwd Pkts/b Avg'] = pd.to_numeric(df_clean['Bwd Pkts/b Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Pkts/b Avg'] >= 0]
        print(f"Rows after validating Bwd Pkts/b Avg: {len(df_clean)}")
    if 'Bwd Blk Rate Avg' in df_clean.columns:
        df_clean['Bwd Blk Rate Avg'] = pd.to_numeric(df_clean['Bwd Blk Rate Avg'], errors='coerce')
        df_clean = df_clean[df_clean['Bwd Blk Rate Avg'] >= 0]
        print(f"Rows after validating Bwd Blk Rate Avg: {len(df_clean)}")
    if 'Subflow Fwd Pkts' in df_clean.columns:
        df_clean['Subflow Fwd Pkts'] = pd.to_numeric(df_clean['Subflow Fwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['Subflow Fwd Pkts'] >= 0]
        print(f"Rows after validating Subflow Fwd Pkts: {len(df_clean)}")
    if 'Subflow Fwd Byts' in df_clean.columns:
        df_clean['Subflow Fwd Byts'] = pd.to_numeric(df_clean['Subflow Fwd Byts'], errors='coerce')
        df_clean = df_clean[df_clean['Subflow Fwd Byts'] >= 0]
        print(f"Rows after validating Subflow Fwd Byts: {len(df_clean)}")
    if 'Subflow Bwd Pkts' in df_clean.columns:
        df_clean['Subflow Bwd Pkts'] = pd.to_numeric(df_clean['Subflow Bwd Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['Subflow Bwd Pkts'] >= 0]
        print(f"Rows after validating Subflow Bwd Pkts: {len(df_clean)}")
    if 'Subflow Bwd Byts' in df_clean.columns:
        df_clean['Subflow Bwd Byts'] = pd.to_numeric(df_clean['Subflow Bwd Byts'], errors='coerce')
        df_clean = df_clean[df_clean['Subflow Bwd Byts'] >= 0]
        print(f"Rows after validating Subflow Bwd Byts: {len(df_clean)}")
    if 'Init Fwd Win Byts' in df_clean.columns:
        df_clean['Init Fwd Win Byts'] = pd.to_numeric(df_clean['Init Fwd Win Byts'], errors='coerce')
        df_clean = df_clean[df_clean['Init Fwd Win Byts'].apply(lambda x: x >= 0 or x == -1)]
        print(f"Rows after validating Init Fwd Win Byts: {len(df_clean)}")
    if 'Init Bwd Win Byts' in df_clean.columns:
        df_clean['Init Bwd Win Byts'] = pd.to_numeric(df_clean['Init Bwd Win Byts'], errors='coerce')
        df_clean = df_clean[df_clean['Init Bwd Win Byts'].apply(lambda x: x >= 0 or x == -1)]
        print(f"Rows after validating Init Bwd Win Byts: {len(df_clean)}")
    if 'Fwd Act Data Pkts' in df_clean.columns:
        df_clean['Fwd Act Data Pkts'] = pd.to_numeric(df_clean['Fwd Act Data Pkts'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Act Data Pkts'] >= 0]
        print(f"Rows after validating Fwd Act Data Pkts: {len(df_clean)}")
    if 'Fwd Seg Size Min' in df_clean.columns:
        df_clean['Fwd Seg Size Min'] = pd.to_numeric(df_clean['Fwd Seg Size Min'], errors='coerce')
        df_clean = df_clean[df_clean['Fwd Seg Size Min'] >= 0]
        print(f"Rows after validating Fwd Seg Size Min: {len(df_clean)}")
    if 'Active Mean' in df_clean.columns:
        df_clean['Active Mean'] = pd.to_numeric(df_clean['Active Mean'], errors='coerce')
        df_clean = df_clean[(df_clean['Active Mean'] >= 0) & (df_clean['Active Mean'] <= 86400000)]
        print(f"Rows after validating Active Mean: {len(df_clean)}")
    if 'Active Std' in df_clean.columns:
        df_clean['Active Std'] = pd.to_numeric(df_clean['Active Std'], errors='coerce')
        df_clean = df_clean[df_clean['Active Std'] >= 0]
        print(f"Rows after validating Active Std: {len(df_clean)}")
    if 'Active Max' in df_clean.columns:
        df_clean['Active Max'] = pd.to_numeric(df_clean['Active Max'], errors='coerce')
        df_clean = df_clean[df_clean['Active Max'] >= 0]
        print(f"Rows after validating Active Max: {len(df_clean)}")
    if 'Active Min' in df_clean.columns:
        df_clean['Active Min'] = pd.to_numeric(df_clean['Active Min'], errors='coerce')
        df_clean = df_clean[df_clean['Active Min'] >= 0]
        print(f"Rows after validating Active Min: {len(df_clean)}")
    if 'Idle Mean' in df_clean.columns:
        df_clean['Idle Mean'] = pd.to_numeric(df_clean['Idle Mean'], errors='coerce')
        df_clean = df_clean[(df_clean['Idle Mean'] >= 0) & (df_clean['Idle Mean'] <= 86400000)]
        print(f"Rows after validating Idle Mean: {len(df_clean)}")
    if 'Idle Std' in df_clean.columns:
        df_clean['Idle Std'] = pd.to_numeric(df_clean['Idle Std'], errors='coerce')
        df_clean = df_clean[df_clean['Idle Std'] >= 0]
        print(f"Rows after validating Idle Std: {len(df_clean)}")
    if 'Idle Max' in df_clean.columns:
        df_clean['Idle Max'] = pd.to_numeric(df_clean['Idle Max'], errors='coerce')
        df_clean = df_clean[df_clean['Idle Max'] >= 0]
        print(f"Rows after validating Idle Max: {len(df_clean)}")
    if 'Idle Min' in df_clean.columns:
        df_clean['Idle Min'] = pd.to_numeric(df_clean['Idle Min'], errors='coerce')
        df_clean = df_clean[df_clean['Idle Min'] >= 0]
        print(f"Rows after validating Idle Min: {len(df_clean)}")
    
    # Remove rows with remaining NaNs in feature columns
    df_clean = df_clean.dropna(subset=feature_columns)
    print(f"Rows after removing remaining NaNs in feature columns: {len(df_clean)}")
    if len(df_clean) == 0:
        raise ValueError("Dataset is empty after removing remaining NaNs.")
    
    return df_clean

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 clean.py <path_to_data.csv>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    input_filename = os.path.basename(input_file)
    output_filename = f"clean_{input_filename}"
    output_path = os.path.join(script_dir, output_filename)
    
    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"Error: File {input_file} not found")
        sys.exit(1)
    
    try:
        cleaned_data = clean_network_data(df)
    except ValueError as e:
        print(f"Error during cleaning: {e}")
        sys.exit(1)
    
    cleaned_data.to_csv(output_path, index=False)
    print(f"Cleaned data saved to {output_path}")
