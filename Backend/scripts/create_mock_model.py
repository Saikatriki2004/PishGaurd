"""
Generate mock_model.pkl for infrastructure testing.

This script creates a calibrated mock classifier that matches the expected
feature schema of the phishing detection pipeline.

Usage:
    python scripts/create_mock_model.py
    
Or auto-generated when USE_MOCK_MODEL=true and model file is missing.
"""
import os
import pickle
import numpy as np


def create_mock_model():
    """
    Create calibrated mock classifier matching feature schema.
    
    The mock model:
    - Accepts 27 features (24 base + 3 failure indicators)
    - Returns calibrated probabilities
    - Uses stratified random predictions
    
    Returns:
        str: Path to created model file
    """
    from sklearn.dummy import DummyClassifier
    from sklearn.calibration import CalibratedClassifierCV
    
    np.random.seed(42)
    
    # Match expected feature count: 24 base features + 3 failure indicators
    X = np.random.rand(200, 27)
    y = np.random.choice([-1, 1], 200)  # -1 = phishing, 1 = legitimate
    
    # DummyClassifier with stratified strategy for realistic distribution
    base = DummyClassifier(strategy="stratified", random_state=42)
    
    # CalibratedClassifierCV with cross-validation (handles newer sklearn versions)
    # Note: cv="prefit" is deprecated in newer sklearn, using cv=2 instead
    calibrated = CalibratedClassifierCV(base, cv=2)
    calibrated.fit(X, y)
    
    # Ensure models directory exists
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "mock_model.pkl")
    
    with open(out_path, "wb") as f:
        pickle.dump(calibrated, f)
    
    print(f"[MOCK] Created mock model at {out_path}")
    return out_path


if __name__ == "__main__":
    create_mock_model()
