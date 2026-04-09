"""
ml/scripts/train.py

Train PhishGuard's LightGBM phishing detection model.

ALGORITHM CHOICE — WHY LightGBM:
  Speed:          Trains 20K samples in ~10 seconds on CPU
  Accuracy:       Typically 97-99% on phishing datasets with good features
  Inference:      <5ms per prediction (critical for API latency)
  Missing values: Handles -1 sentinels natively (no imputation needed)
  Explainability: SHAP values show per-feature contribution per prediction
  Size:           Serialized model ~2-5MB (small enough to embed if needed)

TRAINING STRATEGY:
  - 70/15/15 train/validation/test split
  - Early stopping on validation AUC (prevents overfitting)
  - Class weights to handle any remaining imbalance
  - Threshold calibration on validation set
  - Full evaluation on held-out test set

TARGET METRICS (must hit before deployment):
  Precision:  > 96%   (false positive rate < 4%)
  Recall:     > 94%   (catches > 94% of phishing)
  AUC-ROC:    > 0.99
  Latency:    < 5ms per prediction

USAGE:
  python3 ml/scripts/train.py [--data ml/data/dataset.csv] [--output ml/models/]
  python3 ml/scripts/train.py --quick  # Quick mode: smaller dataset for testing
"""

import sys
import json
import time
import argparse
import pickle
import math
from pathlib import Path

import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    classification_report, roc_auc_score,
    precision_recall_curve, confusion_matrix,
    average_precision_score,
)

sys.path.insert(0, str(Path(__file__).parent))
from features import FEATURE_NAMES, extract_features

# ── Paths ─────────────────────────────────────────────────────────────────────
MODELS_DIR = Path(__file__).parent.parent / 'models'
DATA_DIR   = Path(__file__).parent.parent / 'data'
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ── LightGBM hyperparameters ──────────────────────────────────────────────────
# Tuned for phishing detection on URL + domain + content features.
# These are sensible defaults — run a hyperparameter search for production.

LGBM_PARAMS = {
    # Boosting
    'objective':        'binary',
    'metric':           ['binary_logloss', 'auc'],
    'boosting_type':    'gbdt',
    'n_estimators':     800,
    'learning_rate':    0.05,

    # Tree structure
    'num_leaves':       63,        # 2^6 - 1; increase for more complex patterns
    'max_depth':        -1,        # no limit, controlled by num_leaves
    'min_child_samples':20,        # min samples per leaf (regularization)
    'min_child_weight': 1e-3,

    # Regularization
    'reg_alpha':        0.1,       # L1
    'reg_lambda':       0.1,       # L2
    'feature_fraction': 0.8,       # subsample features per tree
    'bagging_fraction': 0.8,       # subsample rows per tree
    'bagging_freq':     5,

    # Class imbalance
    'is_unbalance':     False,     # we handle via class_weight
    'scale_pos_weight': 1.0,       # set dynamically from data

    # Misc
    'random_state':     42,
    'n_jobs':           -1,
    'verbose':          -1,        # suppress LightGBM output (we use callbacks)
}

# Early stopping — stop if validation AUC doesn't improve for N rounds
EARLY_STOPPING_ROUNDS = 50


def load_dataset(data_path: Path, quick_mode: bool = False) -> tuple:
    """
    Load and split the dataset into train/val/test.

    Returns: X_train, X_val, X_test, y_train, y_val, y_test
    """
    print(f"[Data] Loading {data_path}...")
    df = pd.read_csv(data_path)

    if quick_mode:
        # For testing: use 2K samples per class
        phish = df[df['label'] == 1].sample(min(2000, sum(df['label']==1)), random_state=42)
        legit = df[df['label'] == 0].sample(min(2000, sum(df['label']==0)), random_state=42)
        df = pd.concat([phish, legit]).sample(frac=1, random_state=42)
        print(f"[Data] Quick mode: {len(df):,} samples")

    print(f"[Data] Total samples: {len(df):,}")
    print(f"[Data] Phishing:      {sum(df['label']==1):,} ({100*sum(df['label']==1)//len(df)}%)")
    print(f"[Data] Legitimate:    {sum(df['label']==0):,} ({100*sum(df['label']==0)//len(df)}%)")

    # Verify all expected features are present
    missing = set(FEATURE_NAMES) - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing features: {missing}")

    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df['label'].values.astype(np.int32)

    # Stratified split: 70% train, 15% val, 15% test
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=0.176, random_state=42, stratify=y_trainval
    )
    # 0.176 of 0.85 ≈ 0.15 of total → 70/15/15 split

    print(f"[Data] Split: {len(X_train):,} train / {len(X_val):,} val / {len(X_test):,} test")
    return X_train, X_val, X_test, y_train, y_val, y_test


def train_model(
    X_train, y_train, X_val, y_val,
    class_weight_ratio: float = 1.0,
) -> lgb.LGBMClassifier:
    """
    Train the LightGBM model with early stopping.

    class_weight_ratio: ratio of negative to positive class count.
    Setting scale_pos_weight = ratio helps with imbalanced classes.
    """
    params = {**LGBM_PARAMS, 'scale_pos_weight': class_weight_ratio}

    model = lgb.LGBMClassifier(**params)

    print(f"\n[Training] LightGBM with {params['n_estimators']} max estimators")
    print(f"[Training] Early stopping: {EARLY_STOPPING_ROUNDS} rounds on val AUC")
    print(f"[Training] Features: {len(FEATURE_NAMES)}")

    t0 = time.time()

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        eval_metric='auc',
        callbacks=[
            lgb.early_stopping(EARLY_STOPPING_ROUNDS, verbose=False),
            lgb.log_evaluation(50),  # print every 50 rounds
        ],
    )

    elapsed = time.time() - t0
    n_trees = model.best_iteration_ or model.n_estimators

    print(f"\n[Training] Complete in {elapsed:.1f}s")
    print(f"[Training] Best iteration: {n_trees} trees")
    print(f"[Training] Val AUC: {model.best_score_['valid_0']['auc']:.4f}")

    return model


def calibrate_threshold(model, X_val, y_val, target_precision: float = 0.96) -> float:
    """
    Find the classification threshold that achieves target precision
    while maximizing recall.

    Default target: 96% precision (4% false positive rate).
    This means: if we say something is phishing, we're right 96% of the time.

    Returns the optimal threshold (between 0 and 1).
    """
    y_scores = model.predict_proba(X_val)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_val, y_scores)

    # Find threshold that achieves target precision
    best_threshold = 0.5  # default
    best_recall    = 0.0

    for precision, recall, threshold in zip(precisions, recalls, thresholds):
        if precision >= target_precision and recall > best_recall:
            best_recall    = recall
            best_threshold = float(threshold)

    print(f"\n[Threshold] Target precision: {target_precision:.0%}")
    print(f"[Threshold] Optimal threshold: {best_threshold:.4f}")
    print(f"[Threshold] Achieves recall:   {best_recall:.4f}")

    return best_threshold


def evaluate_model(model, X_test, y_test, threshold: float) -> dict:
    """
    Full evaluation on the held-out test set.
    Returns metrics dict and prints a detailed report.
    """
    y_scores  = model.predict_proba(X_test)[:, 1]
    y_pred    = (y_scores >= threshold).astype(int)

    auc       = roc_auc_score(y_test, y_scores)
    avg_prec  = average_precision_score(y_test, y_scores)
    cm        = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    metrics = {
        'auc_roc':          round(auc, 4),
        'avg_precision':    round(avg_prec, 4),
        'precision':        round(precision, 4),
        'recall':           round(recall, 4),
        'f1':               round(f1, 4),
        'false_positive_rate': round(fpr, 4),
        'threshold':        round(threshold, 4),
        'test_samples':     len(y_test),
        'tp': int(tp), 'fp': int(fp), 'fn': int(fn), 'tn': int(tn),
    }

    print("\n" + "="*60)
    print("EVALUATION RESULTS (held-out test set)")
    print("="*60)
    print(f"  AUC-ROC:           {auc:.4f}  {'✓' if auc > 0.99 else '✗ (target: >0.99)'}")
    print(f"  Avg Precision:     {avg_prec:.4f}")
    print(f"  Precision:         {precision:.4f}  {'✓' if precision > 0.96 else '✗ (target: >0.96)'}")
    print(f"  Recall:            {recall:.4f}  {'✓' if recall > 0.94 else '✗ (target: >0.94)'}")
    print(f"  F1 Score:          {f1:.4f}")
    print(f"  False Positive Rate:{fpr:.4f}  {'✓' if fpr < 0.04 else '✗ (target: <0.04)'}")
    print(f"\n  Confusion Matrix:")
    print(f"    True Positives:  {tp:>6,}  (phishing caught)")
    print(f"    False Positives: {fp:>6,}  (legit flagged as phishing)")
    print(f"    False Negatives: {fn:>6,}  (phishing missed)")
    print(f"    True Negatives:  {tn:>6,}  (legit passed correctly)")
    print(f"\n  Decision threshold: {threshold:.4f}")

    return metrics


def print_feature_importance(model, top_n: int = 15):
    """Print top feature importances by gain (most predictive features)."""
    importances = model.feature_importances_
    feature_imp = sorted(
        zip(FEATURE_NAMES, importances),
        key=lambda x: x[1], reverse=True
    )

    print(f"\n[Feature Importance] Top {top_n} by gain:")
    max_imp = feature_imp[0][1] if feature_imp else 1
    for name, imp in feature_imp[:top_n]:
        bar_len = int(30 * imp / max_imp)
        bar = '█' * bar_len + '░' * (30 - bar_len)
        print(f"  {name:<30} {bar} {imp:.0f}")


def save_artifacts(model, threshold: float, metrics: dict, output_dir: Path):
    """
    Save all model artifacts needed by the backend inference service.

    Files saved:
      model.pkl          — serialized LightGBM model
      model.txt          — LightGBM text format (for inspection)
      metadata.json      — threshold, metrics, feature names, version
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save model (pickle format for Python inference)
    model_path = output_dir / 'model.pkl'
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"\n[Save] Model: {model_path} ({model_path.stat().st_size/1024:.0f}KB)")

    # Save model in LightGBM text format (human-readable, portable)
    txt_path = output_dir / 'model.txt'
    model.booster_.save_model(str(txt_path))
    print(f"[Save] Model text: {txt_path} ({txt_path.stat().st_size/1024:.0f}KB)")

    # Save metadata
    metadata = {
        'threshold':     threshold,
        'metrics':       metrics,
        'feature_names': FEATURE_NAMES,
        'feature_count': len(FEATURE_NAMES),
        'model_version': '1.0.0',
        'lgbm_version':  lgb.__version__,
        'trained_at':    time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'n_estimators':  model.best_iteration_ or model.n_estimators,
        'description':   'PhishGuard LightGBM phishing detection model',
    }

    meta_path = output_dir / 'metadata.json'
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[Save] Metadata: {meta_path}")

    return model_path, meta_path


def validate_deployment_readiness(metrics: dict) -> bool:
    """
    Check if the model meets minimum production quality thresholds.
    Returns True if ready for deployment, False otherwise.
    """
    targets = {
        'precision':           0.96,
        'recall':              0.94,
        'auc_roc':             0.99,
        'false_positive_rate': 0.04,  # max allowed
    }

    all_pass = True
    print("\n[Deployment Readiness Check]")
    for metric, target in targets.items():
        actual = metrics[metric]
        if metric == 'false_positive_rate':
            passed = actual <= target
        else:
            passed = actual >= target
        status = '✓ PASS' if passed else '✗ FAIL'
        print(f"  {metric:<25} {actual:.4f}  (target: {'≤' if metric=='false_positive_rate' else '≥'}{target})  {status}")
        if not passed:
            all_pass = False

    return all_pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Train PhishGuard LightGBM model')
    parser.add_argument('--data',   default=str(DATA_DIR / 'dataset.csv'),
                        help='Path to dataset CSV')
    parser.add_argument('--output', default=str(MODELS_DIR),
                        help='Directory to save model artifacts')
    parser.add_argument('--quick',  action='store_true',
                        help='Quick mode: 4K samples, fast training')
    parser.add_argument('--target-precision', type=float, default=0.96,
                        help='Target precision for threshold calibration')
    args = parser.parse_args()

    data_path  = Path(args.data)
    output_dir = Path(args.output)

    print("\n" + "="*60)
    print("PhishGuard ML — Model Training")
    print("="*60)

    # ── Load data ─────────────────────────────────────────────────────────
    if not data_path.exists():
        print(f"\n[Error] Dataset not found: {data_path}")
        print("Run: python3 ml/scripts/build_dataset.py first")
        sys.exit(1)

    X_train, X_val, X_test, y_train, y_val, y_test = load_dataset(
        data_path, quick_mode=args.quick
    )

    # ── Class weight ratio ────────────────────────────────────────────────
    n_neg = sum(y_train == 0)
    n_pos = sum(y_train == 1)
    ratio = n_neg / n_pos if n_pos > 0 else 1.0
    print(f"\n[Class balance] Neg/Pos ratio: {ratio:.2f}")

    # ── Train ─────────────────────────────────────────────────────────────
    model = train_model(X_train, y_train, X_val, y_val, class_weight_ratio=ratio)

    # ── Feature importance ────────────────────────────────────────────────
    print_feature_importance(model)

    # ── Calibrate threshold ───────────────────────────────────────────────
    threshold = calibrate_threshold(model, X_val, y_val, args.target_precision)

    # ── Evaluate on test set ──────────────────────────────────────────────
    metrics = evaluate_model(model, X_test, y_test, threshold)

    # ── Deployment readiness check ────────────────────────────────────────
    ready = validate_deployment_readiness(metrics)

    # ── Save artifacts ────────────────────────────────────────────────────
    save_artifacts(model, threshold, metrics, output_dir)

    # ── Final verdict ─────────────────────────────────────────────────────
    print("\n" + "="*60)
    if ready:
        print("✓ MODEL READY FOR DEPLOYMENT")
        print(f"  Load from: {output_dir}/model.pkl")
        print(f"  Threshold: {threshold:.4f}")
        print(f"  AUC:       {metrics['auc_roc']:.4f}")
    else:
        print("✗ MODEL DOES NOT MEET DEPLOYMENT THRESHOLDS")
        print("  Review training data quality and feature engineering")
        print("  Re-run with more data or tune hyperparameters")
    print("="*60)

    return 0 if ready else 1


if __name__ == '__main__':
    sys.exit(main())
