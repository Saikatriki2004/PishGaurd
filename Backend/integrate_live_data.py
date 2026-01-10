#!/usr/bin/env python3
"""
Live Dataset Integration and Model Training

This script:
1. Fetches live phishing URLs from OpenPhish (free feed)
2. Fetches legitimate URLs from Tranco Top 1M
3. Extracts features using our v3 feature extractor
4. Merges with existing phishing.csv data
5. Trains a calibrated model with real data

Usage:
    python integrate_live_data.py --max-urls 500
"""

import os
import sys
import argparse
import logging
import pickle
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict, Any

import requests
import numpy as np
import pandas as pd
from tqdm import tqdm
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.features.feature_extractor import FeatureExtractor, FEATURE_NAMES

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_TOP_1M = "https://tranco-list.eu/download/4X6KQ/1000000"

MODELS_DIR = Path("models")
DATASETS_DIR = Path("datasets")

# Feature schema v3.0
FEATURE_SCHEMA = {
    "version": "3.0",
    "num_base_features": 30,
    "num_failure_indicators": 3,
    "total_features": 33,
    "feature_names": FEATURE_NAMES + [
        "http_fetch_failed", "whois_lookup_failed", "dns_lookup_failed"
    ]
}


# ============================================================================
# DATA FETCHING
# ============================================================================

def fetch_openphish_urls(max_urls: int = 500) -> List[str]:
    """Fetch live phishing URLs from OpenPhish free feed."""
    logger.info("[FETCH] Downloading OpenPhish feed...")
    try:
        resp = requests.get(OPENPHISH_FEED, timeout=30)
        resp.raise_for_status()
        urls = [line.strip() for line in resp.text.strip().split('\n') if line.strip()]
        logger.info(f"[FETCH] Got {len(urls)} phishing URLs from OpenPhish")
        return urls[:max_urls]
    except Exception as e:
        logger.error(f"[FETCH] Failed to fetch OpenPhish: {e}")
        return []


def fetch_tranco_urls(max_urls: int = 1000) -> List[str]:
    """Fetch legitimate URLs from Tranco top 1M list."""
    logger.info("[FETCH] Downloading Tranco top domains...")
    try:
        resp = requests.get(TRANCO_TOP_1M, timeout=60)
        resp.raise_for_status()
        
        domains = []
        for line in resp.text.strip().split('\n')[:max_urls]:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                domains.append(f"https://{parts[1]}")
        
        logger.info(f"[FETCH] Got {len(domains)} legitimate domains from Tranco")
        return domains
    except Exception as e:
        logger.error(f"[FETCH] Failed to fetch Tranco: {e}")
        # Fallback to known legitimate domains
        return [
            "https://google.com", "https://youtube.com", "https://facebook.com",
            "https://amazon.com", "https://twitter.com", "https://instagram.com",
            "https://linkedin.com", "https://github.com", "https://microsoft.com",
            "https://apple.com", "https://netflix.com", "https://spotify.com",
        ] * 50  # Repeat for balance


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features_for_url(url: str, label: int) -> Tuple[str, List[int], int, bool]:
    """
    Extract features for a single URL.
    
    Returns:
        Tuple of (url, features, label, success)
    """
    try:
        extractor = FeatureExtractor(url)
        features = extractor.get_features_with_failure_indicators()
        return (url, features, label, True)
    except Exception as e:
        logger.debug(f"Feature extraction failed for {url}: {e}")
        return (url, [0] * 33, label, False)


def extract_features_batch(urls: List[str], labels: List[int], 
                          max_workers: int = 10, 
                          desc: str = "Extracting") -> pd.DataFrame:
    """
    Extract features for multiple URLs in parallel.
    
    Args:
        urls: List of URLs to extract features from
        labels: Corresponding labels (-1=phishing, 1=legitimate)
        max_workers: Number of parallel workers
        desc: Progress bar description
        
    Returns:
        DataFrame with URL, features, and label columns
    """
    results = []
    failed = 0
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(extract_features_for_url, url, label): (url, label)
            for url, label in zip(urls, labels)
        }
        
        for future in tqdm(as_completed(futures), total=len(futures), desc=desc):
            url, features, label, success = future.result()
            if success:
                results.append({
                    'url': url,
                    'features': features,
                    'label': label
                })
            else:
                failed += 1
    
    logger.info(f"[EXTRACT] Successfully extracted {len(results)}/{len(urls)} URLs ({failed} failed)")
    
    # Convert to DataFrame with expanded features
    if not results:
        return pd.DataFrame()
    
    df = pd.DataFrame(results)
    
    # Expand features list into columns
    feature_df = pd.DataFrame(
        df['features'].tolist(),
        columns=FEATURE_SCHEMA['feature_names']
    )
    feature_df['label'] = df['label']
    feature_df['url'] = df['url']
    
    return feature_df


# ============================================================================
# DATA MERGING
# ============================================================================

def load_existing_dataset() -> pd.DataFrame:
    """Load existing phishing.csv and normalize column names."""
    csv_path = DATASETS_DIR / "phishing.csv"
    if not csv_path.exists():
        logger.warning(f"[DATA] {csv_path} not found")
        return pd.DataFrame()
    
    df = pd.read_csv(csv_path)
    logger.info(f"[DATA] Loaded {len(df)} rows from existing dataset")
    
    # Map old column names to new feature names
    column_mapping = {
        'UsingIP': 'using_ip_address',
        'LongURL': 'url_length',
        'ShortURL': 'is_shortener',
        'Symbol@': 'has_at_symbol',
        'Redirecting//': 'has_double_slash_redirect',
        'PrefixSuffix-': 'has_dash_in_domain',
        'SubDomains': 'subdomain_count',
        'HTTPS': 'has_https',
        'DomainRegLen': 'domain_registration_length',
        'Favicon': 'external_favicon',
        'NonStdPort': 'non_standard_port',
        'HTTPSDomainURL': 'https_in_domain_name',
        'RequestURL': 'external_resources_ratio',
        'AnchorURL': 'unsafe_anchors_ratio',
        'LinksInScriptTags': 'external_scripts_ratio',
        'ServerFormHandler': 'suspicious_form_handler',
        'InfoEmail': 'has_mailto_links',
        'AbnormalURL': 'abnormal_url_whois',
        'WebsiteForwarding': 'redirect_count',
        'StatusBarCust': 'status_bar_manipulation',
        'DisableRightClick': 'right_click_disabled',
        'UsingPopupWindow': 'popup_windows',
        'IframeRedirection': 'iframe_present',
        'AgeofDomain': 'domain_age',
        'DNSRecording': 'has_dns_record',
        'WebsiteTraffic': 'url_entropy',  # Map old dead feature to new
        'PageRank': 'homoglyph_detected',  # Map old dead feature to new
        'GoogleIndex': 'certificate_age',  # Map old dead feature to new
        'LinksPointingToPage': 'external_links_count',
        'StatsReport': 'statistical_report_match',
        'class': 'label'
    }
    
    # Rename columns
    df = df.rename(columns=column_mapping)
    
    # Add failure indicators (assume no failures for existing data)
    df['http_fetch_failed'] = 0
    df['whois_lookup_failed'] = 0
    df['dns_lookup_failed'] = 0
    
    # Drop unnecessary columns
    if 'Index' in df.columns:
        df = df.drop(columns=['Index'])
    
    return df


def merge_datasets(existing_df: pd.DataFrame, new_df: pd.DataFrame) -> pd.DataFrame:
    """Merge existing and new datasets."""
    if existing_df.empty:
        logger.info(f"[MERGE] Using new dataset only: {len(new_df)} rows")
        return new_df
    if new_df.empty:
        logger.info(f"[MERGE] Using existing dataset only: {len(existing_df)} rows")
        return existing_df
    
    logger.info(f"[MERGE] Existing: {len(existing_df)} rows, New: {len(new_df)} rows")
    
    # Combine datasets - simple concat since existing data lacks URLs
    combined = pd.concat([existing_df, new_df], ignore_index=True)
    
    # Only deduplicate if both have URL column
    if 'url' in existing_df.columns and 'url' in new_df.columns:
        combined = combined.drop_duplicates(subset=['url'], keep='last')
    
    logger.info(f"[MERGE] Combined dataset: {len(combined)} rows")
    return combined



# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_calibrated_model(X: np.ndarray, y: np.ndarray) -> CalibratedClassifierCV:
    """Train calibrated GradientBoostingClassifier."""
    logger.info("[TRAIN] Training calibrated model...")
    
    # Split for calibration
    X_train, X_cal, y_train, y_cal = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Base model with optimized hyperparameters
    base_model = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=5,
        min_samples_split=10,
        min_samples_leaf=5,
        subsample=0.8,
        random_state=42
    )
    
    # Calibrate
    calibrated_model = CalibratedClassifierCV(
        estimator=base_model,
        method='isotonic',
        cv=5
    )
    calibrated_model.fit(X, y)
    
    return calibrated_model


def evaluate_model(model: CalibratedClassifierCV, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
    """Evaluate model and return metrics."""
    y_pred = model.predict(X)
    
    report = classification_report(y, y_pred, target_names=['phishing', 'legitimate'], output_dict=True)
    cm = confusion_matrix(y, y_pred)
    
    return {
        'classification_report': report,
        'confusion_matrix': cm.tolist(),
        'accuracy': report['accuracy'],
        'phishing_recall': report['phishing']['recall'],
        'phishing_precision': report['phishing']['precision'],
    }


def save_model(model: CalibratedClassifierCV, metrics: Dict[str, Any]):
    """Save model and metadata."""
    MODELS_DIR.mkdir(exist_ok=True)
    
    model_path = MODELS_DIR / "model.pkl"
    metadata_path = MODELS_DIR / "model_metadata.json"
    
    # Save model
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    # Save metadata
    metadata = {
        "schema": FEATURE_SCHEMA,
        "model_type": "CalibratedClassifierCV",
        "base_estimator": "GradientBoostingClassifier",
        "calibration_method": "isotonic",
        "is_calibrated": True,
        "expected_input_shape": FEATURE_SCHEMA["total_features"],
        "trained_on": datetime.now().isoformat(),
        "metrics": metrics
    }
    
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"[SAVE] Model saved to {model_path}")
    logger.info(f"[SAVE] Metadata saved to {metadata_path}")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Integrate live phishing data and train model")
    parser.add_argument('--max-phishing', type=int, default=200, 
                       help='Max phishing URLs to fetch from OpenPhish')
    parser.add_argument('--max-legitimate', type=int, default=200,
                       help='Max legitimate URLs to fetch from Tranco')
    parser.add_argument('--workers', type=int, default=5,
                       help='Parallel workers for feature extraction')
    parser.add_argument('--skip-fetch', action='store_true',
                       help='Skip fetching new URLs, use existing data only')
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("PHISHING DETECTION - LIVE DATA INTEGRATION")
    print("="*60 + "\n")
    
    # Step 1: Load existing data
    print("[1/5] Loading existing dataset...")
    existing_df = load_existing_dataset()
    
    new_df = pd.DataFrame()
    
    if not args.skip_fetch:
        # Step 2: Fetch live URLs
        print("\n[2/5] Fetching live phishing URLs...")
        phishing_urls = fetch_openphish_urls(args.max_phishing)
        
        print("\n[3/5] Fetching legitimate URLs...")
        legitimate_urls = fetch_tranco_urls(args.max_legitimate)
        
        # Step 4: Extract features
        if phishing_urls or legitimate_urls:
            print("\n[4/5] Extracting features (this may take a while)...")
            
            all_urls = phishing_urls + legitimate_urls
            all_labels = [-1] * len(phishing_urls) + [1] * len(legitimate_urls)
            
            new_df = extract_features_batch(
                all_urls, all_labels, 
                max_workers=args.workers,
                desc="Feature Extraction"
            )
    else:
        print("\n[2-4/5] Skipping URL fetch (--skip-fetch)")
    
    # Step 5: Merge and train
    print("\n[5/5] Merging datasets and training model...")
    
    merged_df = merge_datasets(existing_df, new_df)
    
    if merged_df.empty:
        print("[ERROR] No data available for training!")
        return 1
    
    # Prepare features and labels
    feature_cols = FEATURE_SCHEMA['feature_names']
    available_cols = [c for c in feature_cols if c in merged_df.columns]
    
    if len(available_cols) < len(feature_cols):
        missing = set(feature_cols) - set(available_cols)
        logger.warning(f"[TRAIN] Missing columns (filling with 0): {missing}")
        for col in missing:
            merged_df[col] = 0
    
    X = merged_df[feature_cols].values
    y = merged_df['label'].values
    
    # Split for evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model = train_calibrated_model(X_train, y_train)
    
    # Evaluate
    print("\n" + "="*60)
    print("MODEL EVALUATION")
    print("="*60)
    
    metrics = evaluate_model(model, X_test, y_test)
    
    print(f"\n[ACCURACY]: {metrics['accuracy']:.2%}")
    print(f"[PHISHING RECALL]: {metrics['phishing_recall']:.2%}")
    print(f"[PHISHING PRECISION]: {metrics['phishing_precision']:.2%}")
    print(f"\nConfusion Matrix (test set):")
    print(f"  [TN={metrics['confusion_matrix'][0][0]:4d}, FP={metrics['confusion_matrix'][0][1]:4d}]")
    print(f"  [FN={metrics['confusion_matrix'][1][0]:4d}, TP={metrics['confusion_matrix'][1][1]:4d}]")
    
    # Save model
    save_model(model, metrics)
    
    print("\n" + "="*60)
    print("[OK] Training complete! Model saved to models/model.pkl")
    print("="*60 + "\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
