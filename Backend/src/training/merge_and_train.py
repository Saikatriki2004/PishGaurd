#!/usr/bin/env python3
"""
Phishing Dataset Merge and Model Training Pipeline

Production-grade script for:
1. Merging multiple Kaggle phishing URL datasets
2. Safe deduplication with security-first conflict resolution
3. Class balancing
4. Stratified train/val/test splitting with no leakage
5. Feature extraction using feature_extractor.py
6. GradientBoostingClassifier training
7. Artifact generation (model, schema, stats)

Usage:
    python merge_and_train.py
    python merge_and_train.py --sample 5000
    python merge_and_train.py --skip-extraction  # Use cached features
"""

import os
import sys
import json
import pickle
import hashlib
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse
import unicodedata

import pandas as pd
import numpy as np
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# Dataset configurations
DATASET_CONFIGS = {
    'phiusiil': {
        'file': 'datasets/phiusiil.csv',
        'url_candidates': ['url', 'URL', 'website', 'domain', 'WEBSITE_URL'],
        'label_candidates': ['label', 'Label', 'class', 'CLASS', 'result', 'target', 'LABEL'],
    },
    'phishstorm': {
        'file': 'datasets/phishstorm.csv',
        'url_candidates': ['url', 'URL', 'website', 'domain'],
        'label_candidates': ['label', 'Label', 'class', 'result', 'target', 'is_phishing'],
    },
    'phishing_site_urls': {
        'file': 'datasets/phishing_site_urls.csv',
        'url_candidates': ['url', 'URL', 'website', 'domain'],
        'label_candidates': ['label', 'Label', 'class', 'result', 'target', 'Label'],
    },
}

# Label normalization mapping
PHISHING_LABELS = {'phishing', 'bad', 'malicious', '1', '-1', 1, -1}
LEGITIMATE_LABELS = {'legitimate', 'good', 'benign', '0', 0}

# Feature names (must match feature_extractor.py order)
FEATURE_NAMES = [
    'using_ip', 'long_url', 'short_url', 'symbol_at', 'redirecting',
    'prefix_suffix', 'sub_domains', 'https', 'domain_reg_len', 'favicon',
    'non_std_port', 'https_domain_url', 'request_url', 'anchor_url',
    'links_in_script_tags', 'server_form_handler', 'info_email', 'abnormal_url',
    'website_forwarding', 'status_bar_cust', 'disable_right_click',
    'using_popup_window', 'iframe_redirection', 'age_of_domain', 'dns_recording',
    'website_traffic', 'page_rank', 'google_index', 'links_pointing_to_page',
    'stats_report'
]

EXPECTED_FEATURE_COUNT = 30

# Paths
BASE_DIR = Path(__file__).parent
PICKLE_DIR = BASE_DIR / 'pickle'
DATASETS_DIR = BASE_DIR / 'datasets'


# ============================================================================
# URL CANONICALIZATION
# ============================================================================

def canonicalize_url(url: str) -> str:
    """
    Canonicalize URL for consistent deduplication.
    
    - Remove scheme (http/https)
    - Remove trailing slash
    - Remove default ports (:80, :443)
    - Normalize punycode
    - Lowercase domain
    - Keep path and query
    """
    if not url or not isinstance(url, str):
        return ''
    
    url = url.strip().lower()
    
    # Add scheme if missing for proper parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        
        # Normalize domain (handle punycode)
        domain = parsed.netloc
        
        # Remove default ports
        if domain.endswith(':80'):
            domain = domain[:-3]
        elif domain.endswith(':443'):
            domain = domain[:-4]
        
        # Normalize punycode to unicode
        try:
            domain = domain.encode('idna').decode('ascii')
        except (UnicodeError, UnicodeDecodeError):
            pass
        
        # Reconstruct without scheme
        path = parsed.path.rstrip('/')
        query = parsed.query
        
        canonical = domain + path
        if query:
            canonical += '?' + query
        
        return canonical
    except Exception:
        return url.strip().lower()


def compute_url_hash(canonical_url: str) -> str:
    """Compute SHA256 hash of canonical URL for split verification."""
    return hashlib.sha256(canonical_url.encode('utf-8')).hexdigest()


# ============================================================================
# DATA INGESTION
# ============================================================================

def find_column(df: pd.DataFrame, candidates: List[str], purpose: str) -> str:
    """Find the first matching column from candidates."""
    found = []
    for col in candidates:
        if col in df.columns:
            found.append(col)
    
    if not found:
        raise ValueError(f"No {purpose} column found. Candidates: {candidates}, Available: {list(df.columns)}")
    
    if len(found) > 1:
        logger.warning(f"Multiple {purpose} columns found: {found}. Using: {found[0]}")
    
    return found[0]


def normalize_label(value) -> Optional[int]:
    """Normalize label value to 0 (legitimate) or 1 (phishing)."""
    if pd.isna(value):
        return None
    
    # Convert to string for comparison
    str_val = str(value).strip().lower()
    
    if str_val in [str(x).lower() for x in PHISHING_LABELS]:
        return 1
    elif str_val in [str(x).lower() for x in LEGITIMATE_LABELS]:
        return 0
    
    # Try numeric
    try:
        num = float(value)
        if num == 1 or num == -1:
            return 1
        elif num == 0:
            return 0
    except (ValueError, TypeError):
        pass
    
    return None


def load_dataset(name: str, config: Dict) -> pd.DataFrame:
    """Load and normalize a single dataset."""
    filepath = BASE_DIR / config['file']
    
    if not filepath.exists():
        raise FileNotFoundError(f"Dataset not found: {filepath}")
    
    logger.info(f"Loading {name} from {filepath}")
    
    # Try different encodings
    for encoding in ['utf-8', 'latin-1', 'cp1252']:
        try:
            df = pd.read_csv(filepath, encoding=encoding, low_memory=False)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError(f"Could not decode {filepath}")
    
    logger.info(f"  Loaded {len(df)} rows, columns: {list(df.columns)}")
    
    # Find URL and label columns
    url_col = find_column(df, config['url_candidates'], 'URL')
    label_col = find_column(df, config['label_candidates'], 'label')
    
    logger.info(f"  Using URL column: {url_col}, Label column: {label_col}")
    
    # Normalize
    result = pd.DataFrame()
    result['url'] = df[url_col].astype(str).str.strip()
    result['label'] = df[label_col].apply(normalize_label)
    result['source'] = name
    
    # Drop invalid rows
    initial_count = len(result)
    result = result.dropna(subset=['url', 'label'])
    result = result[result['url'].str.len() > 3]
    result = result[~result['url'].isin(['nan', 'None', ''])]
    
    dropped = initial_count - len(result)
    if dropped > 0:
        logger.info(f"  Dropped {dropped} invalid rows")
    
    # Lowercase URLs
    result['url'] = result['url'].str.lower()
    
    # Add canonical URL
    result['canonical_url'] = result['url'].apply(canonicalize_url)
    
    # Convert label to int
    result['label'] = result['label'].astype(int)
    
    logger.info(f"  Final: {len(result)} valid rows")
    logger.info(f"  Labels: {result['label'].value_counts().to_dict()}")
    
    return result


# ============================================================================
# MERGE AND DEDUPLICATION
# ============================================================================

def merge_datasets(datasets: Dict[str, pd.DataFrame]) -> Tuple[pd.DataFrame, Dict]:
    """
    Merge datasets with security-first deduplication.
    
    If duplicate URLs have conflicting labels, always resolve to PHISHING (1).
    """
    stats = {
        'datasets': {},
        'total_before_dedup': 0,
        'duplicates_removed': 0,
        'conflicts_resolved': 0,
    }
    
    # Concatenate all datasets
    all_dfs = []
    for name, df in datasets.items():
        stats['datasets'][name] = len(df)
        all_dfs.append(df)
    
    merged = pd.concat(all_dfs, ignore_index=True)
    stats['total_before_dedup'] = len(merged)
    
    logger.info(f"Total rows before deduplication: {len(merged)}")
    
    # Group by canonical URL
    conflicts = 0
    resolved_rows = []
    
    for canonical_url, group in tqdm(merged.groupby('canonical_url'), desc='Deduplicating'):
        if len(group) == 1:
            resolved_rows.append(group.iloc[0])
        else:
            # Check for conflicting labels
            labels = group['label'].unique()
            
            if len(labels) > 1:
                conflicts += 1
                # Security-first: resolve to phishing
                row = group.iloc[0].copy()
                row['label'] = 1
                resolved_rows.append(row)
            else:
                # No conflict, take first
                resolved_rows.append(group.iloc[0])
    
    deduped = pd.DataFrame(resolved_rows).reset_index(drop=True)
    
    stats['duplicates_removed'] = len(merged) - len(deduped)
    stats['conflicts_resolved'] = conflicts
    
    logger.info(f"After deduplication: {len(deduped)} rows")
    logger.info(f"Duplicates removed: {stats['duplicates_removed']}")
    logger.info(f"Conflicts resolved (→ phishing): {conflicts}")
    
    return deduped, stats


# ============================================================================
# CLASS BALANCING
# ============================================================================

def balance_classes(df: pd.DataFrame, max_ratio: float = 0.65) -> Tuple[pd.DataFrame, Dict]:
    """
    Balance classes by downsampling majority class.
    
    Never oversample phishing with synthetic data.
    """
    stats = {
        'before': df['label'].value_counts().to_dict(),
        'balanced': False,
        'downsampled_class': None,
        'downsampled_count': 0,
    }
    
    label_counts = df['label'].value_counts()
    total = len(df)
    
    majority_label = label_counts.idxmax()
    majority_count = label_counts.max()
    minority_count = label_counts.min()
    
    majority_ratio = majority_count / total
    
    logger.info(f"Class distribution: {label_counts.to_dict()}")
    logger.info(f"Majority ratio: {majority_ratio:.2%}")
    
    if majority_ratio > max_ratio:
        # Calculate target count for balanced ratio
        target_majority = int(minority_count * (max_ratio / (1 - max_ratio)))
        
        logger.info(f"Downsampling class {majority_label} from {majority_count} to {target_majority}")
        
        # Separate classes
        majority_df = df[df['label'] == majority_label]
        minority_df = df[df['label'] != majority_label]
        
        # Downsample majority
        majority_sampled = majority_df.sample(n=target_majority, random_state=RANDOM_SEED)
        
        # Combine
        df = pd.concat([majority_sampled, minority_df], ignore_index=True)
        
        stats['balanced'] = True
        stats['downsampled_class'] = int(majority_label)
        stats['downsampled_count'] = majority_count - target_majority
    
    stats['after'] = df['label'].value_counts().to_dict()
    
    return df, stats


# ============================================================================
# SAMPLING
# ============================================================================

def apply_sampling(df: pd.DataFrame, sample_size: int) -> pd.DataFrame:
    """Apply stratified sampling to limit dataset size."""
    if sample_size >= len(df):
        logger.info(f"Sample size {sample_size} >= dataset size {len(df)}, no sampling applied")
        return df
    
    logger.info(f"Applying stratified sampling: {len(df)} -> {sample_size}")
    
    # Stratified sample
    sampled, _ = train_test_split(
        df,
        train_size=sample_size,
        stratify=df['label'],
        random_state=RANDOM_SEED
    )
    
    return sampled.reset_index(drop=True)


# ============================================================================
# TRAIN/VAL/TEST SPLIT
# ============================================================================

def create_splits(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Create stratified train/val/test splits with no leakage.
    
    Split: 70% train, 15% val, 15% test
    """
    # Shuffle
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    
    # First split: 70% train, 30% temp
    train_df, temp_df = train_test_split(
        df,
        train_size=0.70,
        stratify=df['label'],
        random_state=RANDOM_SEED
    )
    
    # Second split: 50% of temp = 15% each
    val_df, test_df = train_test_split(
        temp_df,
        train_size=0.50,
        stratify=temp_df['label'],
        random_state=RANDOM_SEED
    )
    
    logger.info(f"Split sizes - Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")
    
    # Verify no leakage
    train_urls = set(train_df['canonical_url'])
    val_urls = set(val_df['canonical_url'])
    test_urls = set(test_df['canonical_url'])
    
    train_val_overlap = train_urls & val_urls
    train_test_overlap = train_urls & test_urls
    val_test_overlap = val_urls & test_urls
    
    if train_val_overlap or train_test_overlap or val_test_overlap:
        raise ValueError(
            f"DATA LEAKAGE DETECTED!\n"
            f"Train-Val overlap: {len(train_val_overlap)}\n"
            f"Train-Test overlap: {len(train_test_overlap)}\n"
            f"Val-Test overlap: {len(val_test_overlap)}"
        )
    
    logger.info("✓ No URL leakage detected across splits")
    
    return train_df, val_df, test_df


# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features_batch(df: pd.DataFrame, desc: str = "Extracting") -> Tuple[np.ndarray, List[str]]:
    """
    Extract features for all URLs in a dataframe.
    
    Uses feature_extractor.py with graceful error handling.
    Returns neutral values (0) on failure.
    """
    from feature_extractor import FeatureExtractor
    
    features = []
    failed_urls = []
    
    for idx, row in tqdm(df.iterrows(), total=len(df), desc=desc):
        url = row['url']
        try:
            extractor = FeatureExtractor(url)
            feats = extractor.get_features()
            
            # Validate feature count
            if len(feats) != EXPECTED_FEATURE_COUNT:
                raise ValueError(f"Feature count mismatch: {len(feats)} != {EXPECTED_FEATURE_COUNT}")
            
            features.append(feats)
        except Exception as e:
            # Graceful degradation: use neutral values
            logger.debug(f"Feature extraction failed for {url}: {e}")
            features.append([0] * EXPECTED_FEATURE_COUNT)
            failed_urls.append(url)
    
    if failed_urls:
        logger.warning(f"Feature extraction failed for {len(failed_urls)} URLs (using neutral values)")
    
    return np.array(features), failed_urls


# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_model(X_train: np.ndarray, y_train: np.ndarray,
                X_val: np.ndarray, y_val: np.ndarray) -> GradientBoostingClassifier:
    """
    Train GradientBoostingClassifier with validation sanity checks.
    """
    logger.info("Training GradientBoostingClassifier...")
    
    model = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=5,
        min_samples_split=10,
        min_samples_leaf=5,
        subsample=0.8,
        random_state=RANDOM_SEED,
        verbose=1
    )
    
    model.fit(X_train, y_train)
    
    # Validation sanity check
    val_pred = model.predict(X_val)
    val_precision = precision_score(y_val, val_pred, pos_label=1, zero_division=0)
    val_recall = recall_score(y_val, val_pred, pos_label=1, zero_division=0)
    
    logger.info(f"Validation - Precision: {val_precision:.3f}, Recall: {val_recall:.3f}")
    
    # Sanity checks
    unique_preds = np.unique(val_pred)
    if len(unique_preds) == 1:
        raise ValueError(f"PATHOLOGICAL MODEL: All predictions are {unique_preds[0]}")
    
    random_baseline = 0.5
    if val_recall < random_baseline * 0.5:
        logger.warning(f"Recall {val_recall:.3f} is below 50% of random baseline!")
    
    return model


def evaluate_model(model: GradientBoostingClassifier,
                   X_test: np.ndarray, y_test: np.ndarray) -> Dict:
    """Evaluate model on test set."""
    y_pred = model.predict(X_test)
    
    metrics = {
        'precision': float(precision_score(y_test, y_pred, pos_label=1, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, pos_label=1, zero_division=0)),
        'f1': float(f1_score(y_test, y_pred, pos_label=1, zero_division=0)),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
    }
    
    logger.info("\n" + "="*60)
    logger.info("TEST SET EVALUATION")
    logger.info("="*60)
    logger.info(f"Precision (phishing): {metrics['precision']:.3f}")
    logger.info(f"Recall (phishing):    {metrics['recall']:.3f}")
    logger.info(f"F1-Score:             {metrics['f1']:.3f}")
    logger.info(f"\nConfusion Matrix:")
    logger.info(f"  TN={metrics['confusion_matrix'][0][0]}, FP={metrics['confusion_matrix'][0][1]}")
    logger.info(f"  FN={metrics['confusion_matrix'][1][0]}, TP={metrics['confusion_matrix'][1][1]}")
    logger.info("="*60)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    return metrics


# ============================================================================
# ARTIFACT GENERATION
# ============================================================================

def generate_feature_schema() -> Dict:
    """Generate feature schema with hash for validation."""
    schema = {
        'version': '1.0.0',
        'feature_count': EXPECTED_FEATURE_COUNT,
        'features': FEATURE_NAMES,
        'schema_hash': hashlib.sha256(
            json.dumps(FEATURE_NAMES, sort_keys=True).encode()
        ).hexdigest()[:16],
        'generated_at': datetime.now().isoformat(),
    }
    return schema


def save_artifacts(model: GradientBoostingClassifier,
                   stats: Dict,
                   metrics: Dict,
                   merged_df: pd.DataFrame) -> None:
    """Save all artifacts."""
    
    # Ensure directories exist
    PICKLE_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Save model
    model_path = PICKLE_DIR / 'model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    logger.info(f"✓ Saved model: {model_path}")
    
    # 2. Save feature schema
    schema = generate_feature_schema()
    schema_path = BASE_DIR / 'feature_schema.json'
    with open(schema_path, 'w') as f:
        json.dump(schema, f, indent=2)
    logger.info(f"✓ Saved feature schema: {schema_path}")
    
    # 3. Save dataset stats
    stats['metrics'] = metrics
    stats['generated_at'] = datetime.now().isoformat()
    stats_path = BASE_DIR / 'dataset_stats.json'
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    logger.info(f"✓ Saved dataset stats: {stats_path}")
    
    # 4. Save merged dataset
    csv_path = BASE_DIR / 'merged_phishing_urls.csv'
    merged_df[['url', 'label', 'source']].to_csv(csv_path, index=False)
    logger.info(f"✓ Saved merged dataset: {csv_path}")


# ============================================================================
# MAIN PIPELINE
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='Phishing Dataset Merge and Model Training')
    parser.add_argument('--sample', type=int, default=None,
                        help='Sample size for faster testing (stratified)')
    parser.add_argument('--skip-extraction', action='store_true',
                        help='Skip feature extraction (use cached features)')
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("PHISHING DATASET MERGE AND MODEL TRAINING")
    logger.info("="*60)
    
    all_stats = {}
    
    # ----------------------------------------
    # STEP 1: Data Ingestion
    # ----------------------------------------
    logger.info("\n[STEP 1] Loading datasets...")
    
    datasets = {}
    for name, config in DATASET_CONFIGS.items():
        try:
            datasets[name] = load_dataset(name, config)
        except FileNotFoundError as e:
            logger.warning(f"Skipping {name}: {e}")
    
    if not datasets:
        raise ValueError("No datasets found! Please download and place CSV files in datasets/")
    
    # ----------------------------------------
    # STEP 2-3: Merge and Deduplicate
    # ----------------------------------------
    logger.info("\n[STEP 2-3] Merging and deduplicating...")
    
    merged_df, merge_stats = merge_datasets(datasets)
    all_stats.update(merge_stats)
    
    # ----------------------------------------
    # STEP 4: Class Balancing
    # ----------------------------------------
    logger.info("\n[STEP 4] Balancing classes...")
    
    merged_df, balance_stats = balance_classes(merged_df)
    all_stats['balancing'] = balance_stats
    
    # ----------------------------------------
    # STEP 5: Sampling (Optional)
    # ----------------------------------------
    if args.sample:
        logger.info(f"\n[STEP 5] Applying sampling (n={args.sample})...")
        merged_df = apply_sampling(merged_df, args.sample)
        all_stats['sampling'] = {'applied': True, 'sample_size': args.sample}
    else:
        all_stats['sampling'] = {'applied': False}
    
    # ----------------------------------------
    # STEP 6: Train/Val/Test Split
    # ----------------------------------------
    logger.info("\n[STEP 6] Creating train/val/test splits...")
    
    train_df, val_df, test_df = create_splits(merged_df)
    all_stats['splits'] = {
        'train': len(train_df),
        'val': len(val_df),
        'test': len(test_df),
    }
    
    # ----------------------------------------
    # STEP 7: Feature Extraction
    # ----------------------------------------
    if not args.skip_extraction:
        logger.info("\n[STEP 7] Extracting features...")
        logger.warning("This may take a long time for large datasets!")
        
        X_train, failed_train = extract_features_batch(train_df, "Train features")
        X_val, failed_val = extract_features_batch(val_df, "Val features")
        X_test, failed_test = extract_features_batch(test_df, "Test features")
        
        y_train = train_df['label'].values
        y_val = val_df['label'].values
        y_test = test_df['label'].values
        
        all_stats['feature_extraction'] = {
            'failed_train': len(failed_train),
            'failed_val': len(failed_val),
            'failed_test': len(failed_test),
        }
        
        # Cache features for potential reuse
        np.save(BASE_DIR / 'cache_X_train.npy', X_train)
        np.save(BASE_DIR / 'cache_X_val.npy', X_val)
        np.save(BASE_DIR / 'cache_X_test.npy', X_test)
        np.save(BASE_DIR / 'cache_y_train.npy', y_train)
        np.save(BASE_DIR / 'cache_y_val.npy', y_val)
        np.save(BASE_DIR / 'cache_y_test.npy', y_test)
        logger.info("✓ Cached features for potential reuse")
    else:
        logger.info("\n[STEP 7] Loading cached features...")
        X_train = np.load(BASE_DIR / 'cache_X_train.npy')
        X_val = np.load(BASE_DIR / 'cache_X_val.npy')
        X_test = np.load(BASE_DIR / 'cache_X_test.npy')
        y_train = np.load(BASE_DIR / 'cache_y_train.npy')
        y_val = np.load(BASE_DIR / 'cache_y_val.npy')
        y_test = np.load(BASE_DIR / 'cache_y_test.npy')
    
    # ----------------------------------------
    # STEP 8: Model Training
    # ----------------------------------------
    logger.info("\n[STEP 8] Training model...")
    
    model = train_model(X_train, y_train, X_val, y_val)
    
    # ----------------------------------------
    # STEP 9: Evaluation
    # ----------------------------------------
    logger.info("\n[STEP 9] Evaluating on test set...")
    
    metrics = evaluate_model(model, X_test, y_test)
    
    # ----------------------------------------
    # STEP 10: Save Artifacts
    # ----------------------------------------
    logger.info("\n[STEP 10] Saving artifacts...")
    
    save_artifacts(model, all_stats, metrics, merged_df)
    
    # ----------------------------------------
    # VERIFICATION
    # ----------------------------------------
    logger.info("\n[VERIFICATION] Running integrity checks...")
    
    # Verify model loads
    with open(PICKLE_DIR / 'model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)
    assert hasattr(loaded_model, 'predict'), "Model verification failed!"
    logger.info("✓ Model loads successfully")
    
    # Verify feature schema
    with open(BASE_DIR / 'feature_schema.json', 'r') as f:
        loaded_schema = json.load(f)
    assert loaded_schema['feature_count'] == EXPECTED_FEATURE_COUNT
    logger.info("✓ Feature schema validated")
    
    logger.info("\n" + "="*60)
    logger.info("PIPELINE COMPLETED SUCCESSFULLY")
    logger.info("="*60)
    logger.info(f"Model saved to: {PICKLE_DIR / 'model.pkl'}")
    logger.info(f"Schema saved to: {BASE_DIR / 'feature_schema.json'}")
    logger.info(f"Stats saved to: {BASE_DIR / 'dataset_stats.json'}")
    logger.info("="*60)


if __name__ == '__main__':
    main()
