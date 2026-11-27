"""
PackGuard Stage 2 v7 — Pure-NumPy Evaluation, MIL Package Aggregation & Calibration Metrics.
Zero PyTorch / Transformers dependencies (safe for ultra-lightweight CPU-only inference).
"""

import math
import re
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

MIL_FEATURE_DIM = 25

RE_CAP_SENS_SOURCE = re.compile(
    r"(?:\bprocess\.env\b|\bos\.(?:userInfo|hostname|networkInterfaces|homedir)\b|"
    r"\.(?:ssh|npmrc|aws|(?:bash|zsh)_history)\b|\bdocument\.cookie\b|\blocalStorage\b)",
    re.I,
)
RE_CAP_NET_SINK = re.compile(
    r"(?:https?\.(?:request|get)\b|\bfetch\s*\(|axios\.|sendBeacon\b|XMLHttpRequest\b|"
    r"WebSocket\b|net\.(?:Socket|connect)\b|dns\.(?:lookup|resolve)\b|"
    r"\b(?:curl|wget|nslookup)\s|Invoke-WebRequest\b|stratum\+tcp)",
    re.I,
)
RE_CAP_EXEC_SINK = re.compile(
    r"(?:child_process|\bexec(?:Sync|File)?\s*\(|\bspawn(?:Sync)?\s*\(|\beval\s*\(|"
    r"new\s+Function\b|\bFunction\s*\(|vm\.runIn|module\.constructor\._load|"
    r"/bin/(?:sh|bash)|\bpowershell\b)",
    re.I,
)
RE_CAP_DYN_EVAL = re.compile(
    r"(?:\beval\s*\(|new\s+Function\b|\bFunction\s*\(|vm\.runIn)",
    re.I,
)
RE_CAP_DECODE = re.compile(
    r"(?:Buffer\.from\s*\(|\batob\s*\(|fromCharCode\b|\[DECODED_LITERALS\])",
    re.I,
)

TACTIC_LABELS = (
    "benign",
    "install_hook_exec",
    "obfuscated_loader",
    "credential_stealer",
    "env_network_exfil",
    "browser_skimmer",
    "reverse_shell_dropper",
    "crypto_miner",
)


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
    target_specificity: float = 0.975,
) -> Dict[str, Any]:
    """Sweeps thresholds in [0.10, 0.997] to maximize recall while enforcing benign_specificity >= target."""
    best: Optional[Dict[str, Any]] = None
    best_fallback: Optional[Dict[str, Any]] = None

    grid = np.concatenate([np.linspace(0.10, 0.95, 171), np.linspace(0.952, 0.997, 91)])
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


def extract_package_mil_features(
    win_logits: np.ndarray,
    win_meta: Optional[Sequence[Dict[str, Any]]] = None,
    tac_logits: Optional[np.ndarray] = None,
    windows: Optional[Sequence[str]] = None,
) -> np.ndarray:
    """
    Extracts a 24-feature Multi-Instance Learning (MIL) summary vector from a package's
    binary logits `[W, 2]`, optional 8-class tactic logits `[W, 8]`, and package-wide
    source-vs-sink static capabilities so a lightweight neural package aggregator can
    separate benign utilities (local source reads or passive decoders with no sink)
    from true malicious payload chains without hardcoded regex rules.
    """
    if len(win_logits) == 0:
        return np.zeros((MIL_FEATURE_DIM,), dtype=np.float32)

    margins = (win_logits[:, 1] - win_logits[:, 0]).astype(np.float64)
    shifted = win_logits - np.max(win_logits, axis=-1, keepdims=True)
    exps = np.exp(shifted)
    probs = exps[:, 1] / np.sum(exps, axis=-1)

    top_idx = int(np.argmax(margins))
    sorted_m = np.sort(margins)[::-1]
    top1_m = float(sorted_m[0])
    top2_m = float(sorted_m[1]) if len(sorted_m) >= 2 else top1_m
    mean_m = float(np.mean(margins))
    std_m = float(np.std(margins)) if len(margins) >= 2 else 0.0
    m_max = np.max(margins)
    lse_m = float(m_max + np.log(np.mean(np.exp(margins - m_max))))

    max_p = float(np.max(probs))
    frac_hi = float(np.mean(probs >= 0.50))
    log_w = math.log1p(len(margins))

    has_inst = 0.0
    inst_max_m = 0.0
    if win_meta:
        inst_margins = [float(margins[i]) for i, m in enumerate(win_meta[: len(margins)]) if m.get("is_install")]
        if inst_margins:
            has_inst = 1.0
            inst_max_m = max(inst_margins)

    # [10..15]: Tactic-head distribution & entropy features
    top_tac_benign_p = 0.0
    top_tac_mal_max_p = 0.0
    top_tac_norm_ent = 0.0
    max_tac_hook_load = 0.0
    max_tac_steal_exfil = 0.0
    max_tac_shell_miner = 0.0
    if tac_logits is not None and len(tac_logits) == len(win_logits) and tac_logits.shape[1] >= 8:
        t_shift = tac_logits.astype(np.float64) - np.max(tac_logits, axis=-1, keepdims=True)
        t_exp = np.exp(t_shift)
        tac_probs = t_exp / np.maximum(np.sum(t_exp, axis=-1, keepdims=True), 1e-12)
        top_p = tac_probs[top_idx, :8]
        top_tac_benign_p = float(top_p[0])
        top_tac_mal_max_p = float(np.max(top_p[1:8]))
        top_tac_norm_ent = float(-np.sum(top_p * np.log(top_p + 1e-9)) / math.log(8.0))
        max_tac_hook_load = float(np.max(tac_probs[:, 1] + tac_probs[:, 2]))
        max_tac_steal_exfil = float(np.max(tac_probs[:, 3] + tac_probs[:, 4] + tac_probs[:, 5]))
        max_tac_shell_miner = float(np.max(tac_probs[:, 6] + tac_probs[:, 7]))

    # [16..24]: Package-wide source-vs-sink & manifest capabilities (9 features)
    cap_feats = [0.0] * 9
    if windows:
        joined = "\n".join(windows)
        sens_source = bool(RE_CAP_SENS_SOURCE.search(joined))
        net_sink = bool(RE_CAP_NET_SINK.search(joined))
        exec_sink = bool(RE_CAP_EXEC_SINK.search(joined))
        dyn_eval = bool(RE_CAP_DYN_EVAL.search(joined))
        decode_op = bool(RE_CAP_DECODE.search(joined))
        has_inst_bool = bool(has_inst > 0.5)
        cap_feats = [
            1.0 if (sens_source and not net_sink and not exec_sink and not has_inst_bool) else 0.0,
            1.0 if (decode_op and not dyn_eval and not exec_sink and not has_inst_bool) else 0.0,
            1.0 if (not sens_source and not net_sink and not exec_sink and not dyn_eval and not has_inst_bool) else 0.0,
            1.0 if (net_sink and not sens_source and not exec_sink and not dyn_eval and not has_inst_bool) else 0.0,
            1.0 if (sens_source and net_sink) else 0.0,
            1.0 if (decode_op and (dyn_eval or exec_sink)) else 0.0,
            1.0 if (exec_sink and net_sink) else 0.0,
            1.0 if "[DECODED_LITERALS]" in joined else 0.0,
            1.0 if "version_shape=high_major_99+" in joined else 0.0,
        ]

    return np.array(
        [
            top1_m, top2_m, lse_m, mean_m, std_m, max_p, frac_hi, log_w, has_inst, inst_max_m,
            top_tac_benign_p, top_tac_mal_max_p, top_tac_norm_ent,
            max_tac_hook_load, max_tac_steal_exfil, max_tac_shell_miner,
            *cap_feats,
        ],
        dtype=np.float32,
    )


def score_package_mil_logit(
    win_logits: np.ndarray,
    win_meta: Optional[Sequence[Dict[str, Any]]],
    mil_cfg: Optional[Dict[str, Any]],
    tac_logits: Optional[np.ndarray] = None,
    windows: Optional[Sequence[str]] = None,
) -> float:
    """Computes the uncentered package-level logit before `(logit - bias) / temp` calibration."""
    if len(win_logits) == 0:
        return -30.0
    shifted = win_logits - np.max(win_logits, axis=-1, keepdims=True)
    exps = np.exp(shifted)
    win_probs = exps[:, 1] / np.sum(exps, axis=-1)
    raw_max = float(np.max(win_probs))

    if mil_cfg and mil_cfg.get("enabled"):
        feat = extract_package_mil_features(win_logits, win_meta, tac_logits=tac_logits, windows=windows)
        w1 = np.asarray(mil_cfg["w1"], dtype=np.float32)
        dim = int(w1.shape[1])
        feat_s = feat[:dim]
        b1 = np.asarray(mil_cfg["b1"], dtype=np.float32)
        w2 = np.asarray(mil_cfg["w2"], dtype=np.float32)
        b2 = np.asarray(mil_cfg["b2"], dtype=np.float32)
        mean = np.asarray(mil_cfg["feat_mean"], dtype=np.float32)[:dim]
        scale = np.asarray(mil_cfg["feat_scale"], dtype=np.float32)[:dim]

        x = (feat_s - mean) / np.maximum(scale, 1e-5)
        h_pre = x @ w1.T + b1
        h = 0.5 * h_pre * (1.0 + np.tanh(0.79788456 * (h_pre + 0.044715 * (h_pre ** 3))))
        return float((h @ w2.T + b2)[0])

    p_clip = min(1.0 - 1e-6, max(1e-6, raw_max))
    return float(math.log(p_clip / (1.0 - p_clip)))


def score_package_with_mil_weights(
    win_logits: np.ndarray,
    win_meta: Optional[Sequence[Dict[str, Any]]],
    mil_cfg: Optional[Dict[str, Any]],
    tac_logits: Optional[np.ndarray] = None,
    windows: Optional[Sequence[str]] = None,
) -> float:
    """
    Computes package-level P(malicious) using learned 24-feature (or legacy 10-feature) MIL
    neural weights and centered temperature-scaled calibration if `mil_cfg` is provided,
    otherwise falls back cleanly to exact `max(softmax(win_logits)[:, 1])`.
    """
    if len(win_logits) == 0:
        return 0.0
    if not mil_cfg:
        shifted = win_logits - np.max(win_logits, axis=-1, keepdims=True)
        exps = np.exp(shifted)
        win_probs = exps[:, 1] / np.sum(exps, axis=-1)
        return float(np.max(win_probs))

    logit = score_package_mil_logit(win_logits, win_meta, mil_cfg, tac_logits=tac_logits, windows=windows)
    bias = float(mil_cfg.get("logit_bias", 0.0))
    temp = max(float(mil_cfg.get("logit_temperature", 1.0)), 1e-3)
    cal_logit = max(-30.0, min(30.0, (logit - bias) / temp))
    return float(1.0 / (1.0 + math.exp(-cal_logit)))
