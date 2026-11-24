"""
PackGuard Stage 2 v6 — Pure-NumPy Evaluation & Calibration Metrics.
Zero PyTorch / Transformers dependencies (safe for lightweight CPU-only evaluation).
"""

from typing import Any, Dict, Optional

import numpy as np


def compute_roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Exact rank-based ROC-AUC with tie averaging."""
    y_true = np.asarray(y_true, dtype=np.int64)
    y_score = np.asarray(y_score, dtype=np.float64)
    pos = y_true == 1
    neg = y_true == 0
    n_pos = int(pos.sum())
    n_neg = int(neg.sum())
    if n_pos == 0 or n_neg == 0:
        return 0.5
    order = np.argsort(y_score)
    ranks = np.empty_like(order, dtype=np.float64)
    sorted_scores = y_score[order]
    i = 0
    n = len(sorted_scores)
    while i < n:
        j = i + 1
        while j < n and sorted_scores[j] == sorted_scores[i]:
            j += 1
        avg_rank = 0.5 * (i + j - 1) + 1.0
        ranks[order[i:j]] = avg_rank
        i = j
    sum_pos_ranks = ranks[pos].sum()
    return float((sum_pos_ranks - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


def evaluate_metrics_at_threshold(
    y_true: np.ndarray,
    y_score: np.ndarray,
    threshold: float,
) -> Dict[str, Any]:
    y_true = np.asarray(y_true, dtype=np.int64)
    y_score = np.asarray(y_score, dtype=np.float64)
    preds = (y_score >= threshold).astype(np.int64)
    tp = int(((preds == 1) & (y_true == 1)).sum())
    fn = int(((preds == 0) & (y_true == 1)).sum())
    tn = int(((preds == 0) & (y_true == 0)).sum())
    fp = int(((preds == 1) & (y_true == 0)).sum())

    recall = tp / max(1, tp + fn)
    specificity = tn / max(1, tn + fp)
    fpr = fp / max(1, tn + fp)
    precision = tp / max(1, tp + fp)
    f1 = 2.0 * precision * recall / max(1e-9, precision + recall)
    auc = compute_roc_auc(y_true, y_score)

    return {
        "threshold": round(float(threshold), 4),
        "roc_auc": round(auc, 5),
        "recall": round(recall, 5),
        "benign_specificity": round(specificity, 5),
        "fpr": round(fpr, 5),
        "precision": round(precision, 5),
        "f1": round(f1, 5),
        "tp": tp,
        "fn": fn,
        "tn": tn,
        "fp": fp,
        "benign_median_prob": round(float(np.median(y_score[y_true == 0])), 5) if (y_true == 0).any() else 0.0,
        "malware_median_prob": round(float(np.median(y_score[y_true == 1])), 5) if (y_true == 1).any() else 0.0,
    }


def calibrate_threshold_for_specificity(
    y_true: np.ndarray,
    y_score: np.ndarray,
    target_specificity: float = 0.97,
) -> Dict[str, Any]:
    """Sweeps thresholds in [0.10, 0.995] to maximize recall while enforcing benign_specificity >= target."""
    best: Optional[Dict[str, Any]] = None
    best_fallback: Optional[Dict[str, Any]] = None

    grid = np.concatenate([np.linspace(0.10, 0.95, 171), np.linspace(0.955, 0.995, 41)])
    for tau in grid:
        m = evaluate_metrics_at_threshold(y_true, y_score, float(tau))
        if best_fallback is None or (m["benign_specificity"] + m["recall"]) > (
            best_fallback["benign_specificity"] + best_fallback["recall"]
        ):
            best_fallback = m
        if m["benign_specificity"] >= target_specificity:
            if best is None or m["recall"] > best["recall"] or (
                m["recall"] == best["recall"] and m["benign_specificity"] > best["benign_specificity"]
            ):
                best = m

    return best if best is not None else best_fallback
