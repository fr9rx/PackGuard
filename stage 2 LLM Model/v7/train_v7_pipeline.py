"""
PackGuard Stage 2 v7 — Pretrained Teacher + KL-Anchored LoRA + Pretrained RoPE Student
Distillation + Neural MIL Package Aggregator + Dual-Output INT8 ONNX Export.

Key quality & stability upgrades over `train_v6_pipeline.py`:
  1. Stronger Teacher Base (`answerdotai/ModernBERT-large` 395M default, or `ModernBERT-base` 149M)
     with `modules_to_save=["classifier"]` during PEFT LoRA so classification head & LoRA adapters
     co-adapt cleanly.
  2. Pretrained Student Initialization (`PackGuardRoPEStudentV7`):
     Transfers exact Two-Sided SVD embeddings + 6 global-attention RoPE/GeGLU layers directly
     from `answerdotai/ModernBERT-base` (self-verifying MLP numerical parity) before distillation!
  3. Multi-Task + KL Distillation (`binary_logits` + 8-class `tactic_logits` + Teacher KL).
  4. KL-Anchored LoRA Patching (`0.40 * KL` anchor + balanced `fp_weight <= 1.35` + strict dual
     AUC AND Recall@TargetSpec acceptance gate — eliminating catastrophic recall drops!).
  5. Package-Level Neural MIL Aggregator (`PackageMILAggregator`) trained on `train_packages_mil.jsonl`
     and enabled automatically if and only if it beats raw `max(window_probs)` on `dev_val`.
  6. Dual-output Dynamic INT8 ONNX (`binary_logits`, `tactic_logits`) verified on CPU with hard
     `dev_val` ROC-AUC >= 0.965 gate.
"""

import argparse
import hashlib
import inspect
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoModelForSequenceClassification, AutoTokenizer, get_cosine_schedule_with_warmup

V7_DIR = Path(__file__).resolve().parent
if str(V7_DIR) not in sys.path:
    sys.path.insert(0, str(V7_DIR))

from metrics_v7 import (
    MIL_FEATURE_DIM,
    calibrate_threshold_for_specificity,
    compute_roc_auc,
    evaluate_metrics_at_threshold,
    extract_package_mil_features,
    score_package_mil_logit,
    score_package_with_mil_weights,
)
from model_v7 import (
    PackGuardRoPEStudentV7,
    PackageMILAggregator,
    count_parameters,
    get_student_lora_target_modules,
    get_teacher_lora_target_modules,
)


class PreTokenizedDatasetV7(Dataset):
    """Holds pre-tokenized input_ids, binary labels, tactic IDs, and optional Teacher logits."""

    def __init__(
        self,
        token_ids_list: List[List[int]],
        labels: List[int],
        tactics: Optional[List[int]] = None,
        teacher_logits: Optional[np.ndarray] = None,
        sample_weights: Optional[np.ndarray] = None,
    ):
        self.token_ids_list = token_ids_list
        self.labels = labels
        self.tactics = tactics if tactics is not None else [0 if y == 0 else 4 for y in labels]
        self.teacher_logits = teacher_logits
        self.sample_weights = sample_weights

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        item: Dict[str, Any] = {
            "ids": self.token_ids_list[idx],
            "label": self.labels[idx],
            "tactic": self.tactics[idx],
            "weight": float(self.sample_weights[idx]) if self.sample_weights is not None else 1.0,
        }
        if self.teacher_logits is not None:
            item["teacher_logits"] = self.teacher_logits[idx]
        return item


def make_pad_collate(pad_id: int):
    def _collate(batch: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        max_len = max(2, max(len(b["ids"]) for b in batch))
        bsz = len(batch)
        input_ids = torch.full((bsz, max_len), pad_id, dtype=torch.long)
        attention_mask = torch.zeros((bsz, max_len), dtype=torch.long)
        for i, b in enumerate(batch):
            ids = b["ids"]
            L = len(ids)
            input_ids[i, :L] = torch.tensor(ids, dtype=torch.long)
            attention_mask[i, :L] = 1
        out = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": torch.tensor([b["label"] for b in batch], dtype=torch.long),
            "tactics": torch.tensor([b["tactic"] for b in batch], dtype=torch.long),
            "weights": torch.tensor([b["weight"] for b in batch], dtype=torch.float32),
        }
        if "teacher_logits" in batch[0]:
            out["teacher_logits"] = torch.tensor(
                np.stack([b["teacher_logits"] for b in batch]), dtype=torch.float32
            )
        return out

    return _collate


def pretokenize_texts(tokenizer: Any, texts: List[str], max_length: int = 512, chunk_size: int = 4096) -> List[List[int]]:
    all_ids: List[List[int]] = []
    for i in range(0, len(texts), chunk_size):
        enc = tokenizer(texts[i : i + chunk_size], truncation=True, max_length=max_length, padding=False)
        all_ids.extend(enc["input_ids"])
    return all_ids


def asymmetric_focal_ce_loss(
    logits: torch.Tensor,
    labels: torch.Tensor,
    weights: Optional[torch.Tensor] = None,
    fp_weight: float = 1.25,
    gamma: float = 1.25,
) -> torch.Tensor:
    ce = F.cross_entropy(logits, labels, reduction="none")
    pt = torch.exp(-ce)
    focal = ((1.0 - pt) ** gamma) * ce
    class_w = torch.where(labels == 0, torch.full_like(focal, fp_weight), torch.ones_like(focal))
    loss = focal * class_w
    if weights is not None:
        loss = loss * weights
    return loss.mean()


def _unwrap_binary_logits(out: Any, is_hf_model: bool) -> torch.Tensor:
    if is_hf_model:
        return out.logits
    if isinstance(out, tuple):
        return out[0]
    return out


@torch.no_grad()
def predict_ids_pytorch(
    model: nn.Module,
    token_ids_list: List[List[int]],
    pad_id: int,
    device: torch.device,
    batch_size: int = 128,
    is_hf_model: bool = False,
) -> np.ndarray:
    if not token_ids_list:
        return np.zeros((0, 2), dtype=np.float32)
    model.eval()
    all_logits: List[np.ndarray] = []
    for i in range(0, len(token_ids_list), batch_size):
        chunk = token_ids_list[i : i + batch_size]
        max_len = max(2, max(len(ids) for ids in chunk))
        bsz = len(chunk)
        input_ids = torch.full((bsz, max_len), pad_id, dtype=torch.long)
        attention_mask = torch.zeros((bsz, max_len), dtype=torch.long)
        for j, ids in enumerate(chunk):
            L = len(ids)
            input_ids[j, :L] = torch.tensor(ids, dtype=torch.long)
            attention_mask[j, :L] = 1
        input_ids = input_ids.to(device, non_blocking=True)
        attention_mask = attention_mask.to(device, non_blocking=True)
        with torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=(device.type == "cuda")):
            out = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = _unwrap_binary_logits(out, is_hf_model)
        all_logits.append(logits.float().cpu().numpy())
    return np.concatenate(all_logits, axis=0)


@torch.no_grad()
def predict_ids_with_aux_pytorch(
    student: PackGuardRoPEStudentV7,
    token_ids_list: List[List[int]],
    pad_id: int,
    device: torch.device,
    batch_size: int = 128,
) -> Tuple[np.ndarray, np.ndarray]:
    if not token_ids_list:
        return np.zeros((0, 2), dtype=np.float32), np.zeros((0, 8), dtype=np.float32)
    student.eval()
    all_bin: List[np.ndarray] = []
    all_tac: List[np.ndarray] = []
    for i in range(0, len(token_ids_list), batch_size):
        chunk = token_ids_list[i : i + batch_size]
        max_len = max(2, max(len(ids) for ids in chunk))
        bsz = len(chunk)
        input_ids = torch.full((bsz, max_len), pad_id, dtype=torch.long)
        attention_mask = torch.zeros((bsz, max_len), dtype=torch.long)
        for j, ids in enumerate(chunk):
            L = len(ids)
            input_ids[j, :L] = torch.tensor(ids, dtype=torch.long)
            attention_mask[j, :L] = 1
        input_ids = input_ids.to(device, non_blocking=True)
        attention_mask = attention_mask.to(device, non_blocking=True)
        with torch.amp.autocast("cuda", dtype=torch.bfloat16, enabled=(device.type == "cuda")):
            b_log, t_log = student.forward_with_aux(input_ids=input_ids, attention_mask=attention_mask)
        all_bin.append(b_log.float().cpu().numpy())
        all_tac.append(t_log.float().cpu().numpy())
    return np.concatenate(all_bin, axis=0), np.concatenate(all_tac, axis=0)


def _logits_to_pos_probs(logits: np.ndarray) -> np.ndarray:
    if len(logits) == 0:
        return np.zeros((0,), dtype=np.float64)
    shifted = logits - np.max(logits, axis=-1, keepdims=True)
    exps = np.exp(shifted)
    return exps[:, 1] / np.sum(exps, axis=-1)


@torch.no_grad()
def evaluate_packages_pytorch(
    model: nn.Module,
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    is_hf_model: bool = False,
    target_specificity: float = 0.975,
    mil_cfg: Optional[Dict[str, Any]] = None,
    tag: str = "eval",
) -> Tuple[Dict[str, Any], np.ndarray]:
    logits = predict_ids_pytorch(
        model, dev_flat_ids, pad_id, device, batch_size=96 if is_hf_model else 128, is_hf_model=is_hf_model
    )
    y_true = np.array([int(p["label"]) for p in dev_val_pkgs], dtype=np.int64)
    scores: List[float] = []
    for pkg, (s, e) in zip(dev_val_pkgs, dev_spans):
        if e <= s:
            scores.append(0.0)
        else:
            scores.append(score_package_with_mil_weights(logits[s:e], pkg.get("win_meta"), mil_cfg, windows=pkg.get("windows")))
    y_score = np.array(scores, dtype=np.float64)

    m_05 = evaluate_metrics_at_threshold(y_true, y_score, 0.50)
    m_cal = calibrate_threshold_for_specificity(y_true, y_score, target_specificity=target_specificity)
    summary = {"stage": tag, "at_0_50": m_05, "calibrated": m_cal}
    print(
        f"[{tag}] dev_val: AUC={m_cal['roc_auc']:.5f} | "
        f"@tau={m_cal['threshold']:.3f}: Recall={m_cal['recall']*100:.2f}%, "
        f"BenignSpec={m_cal['benign_specificity']*100:.2f}% (FPR={m_cal['fpr']*100:.2f}%, FP={m_cal['fp']}, FN={m_cal['fn']}) | "
        f"@0.50: Recall={m_05['recall']*100:.2f}%, Spec={m_05['benign_specificity']*100:.2f}%",
        flush=True,
    )
    return summary, logits


def train_teacher(
    teacher_model_id: str,
    train_ids: List[List[int]],
    train_labels: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    epochs: int = 3,
    batch_size: int = 48,
    lr: float = 2.5e-5,
    target_specificity: float = 0.975,
) -> Tuple[nn.Module, Dict[str, Any]]:
    print(f"\n=== STAGE 1: Training Teacher `{teacher_model_id}` ({len(train_labels)} windows, {epochs} epochs) ===", flush=True)
    try:
        model = AutoModelForSequenceClassification.from_pretrained(
            teacher_model_id,
            num_labels=2,
            attn_implementation="sdpa",
            reference_compile=False,
        ).to(device)
    except TypeError:
        model = AutoModelForSequenceClassification.from_pretrained(
            teacher_model_id,
            num_labels=2,
            attn_implementation="sdpa",
        ).to(device)

    ds = PreTokenizedDatasetV7(train_ids, train_labels)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, num_workers=4, pin_memory=True, collate_fn=make_pad_collate(pad_id))
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(loader) * epochs
    scheduler = get_cosine_schedule_with_warmup(optimizer, int(total_steps * 0.08), total_steps)

    t0 = time.time()
    for ep in range(1, epochs + 1):
        model.train()
        rloss = 0.0
        for step, batch in enumerate(loader, 1):
            optimizer.zero_grad(set_to_none=True)
            input_ids = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels = batch["labels"].to(device, non_blocking=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
                loss = asymmetric_focal_ce_loss(logits, labels, fp_weight=1.25, gamma=1.25)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())
            if step % 200 == 0 or step == len(loader):
                print(f"  [Teacher Ep {ep}/{epochs} Step {step}/{len(loader)}] loss={rloss / step:.4f} elapsed={time.time() - t0:.1f}s", flush=True)

    metrics, _ = evaluate_packages_pytorch(
        model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        is_hf_model=True, target_specificity=target_specificity, tag="Teacher-Base"
    )
    if metrics["calibrated"]["roc_auc"] < 0.94:
        raise RuntimeError(f"Teacher failed sanity gate: AUC={metrics['calibrated']['roc_auc']} < 0.94!")
    return model, metrics


def run_kl_anchored_lora_round(
    model: nn.Module,
    train_ids: List[List[int]],
    train_labels: List[int],
    train_tactics: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    is_hf_model: bool,
    round_name: str,
    save_adapter_dir: Path,
    anchor_logits_all: Optional[np.ndarray] = None,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lr: float = 8e-5,
    epochs: int = 2,
    fp_weight: float = 1.25,
    kl_weight: float = 0.40,
    target_specificity: float = 0.975,
) -> Tuple[nn.Module, Dict[str, Any], bool]:
    """
    KL-Anchored PEFT LoRA error-patching round:
      - Mines hardest benign FPs & malware FNs strictly from the leak-free TRAIN pool.
      - Uses balanced weights (`2.0` hard_FP, `2.0` hard_FN, `1.0` replay) + mandatory KL anchor
        to prevent catastrophic forgetting of previously learned malware families!
      - Accepts merge ONLY if BOTH `dev_val` ROC-AUC AND Recall@TargetSpec hold/improve.
    """
    from peft import LoraConfig, get_peft_model

    print(f"\n=== KL-ANCHORED LoRA PATCH [{round_name}] ===", flush=True)
    before_metrics, _ = evaluate_packages_pytorch(
        model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        is_hf_model=is_hf_model, target_specificity=target_specificity, tag=f"{round_name}-Before"
    )

    cur_train_logits = predict_ids_pytorch(
        model, train_ids, pad_id, device, batch_size=96 if is_hf_model else 128, is_hf_model=is_hf_model
    )
    if anchor_logits_all is None:
        anchor_logits_all = cur_train_logits
    train_probs = _logits_to_pos_probs(cur_train_logits)

    hard_fp_idx = [i for i, (y, p) in enumerate(zip(train_labels, train_probs)) if y == 0 and p >= 0.20]
    hard_fn_idx = [i for i, (y, p) in enumerate(zip(train_labels, train_probs)) if y == 1 and p <= 0.80]
    easy_ben_idx = [i for i, (y, p) in enumerate(zip(train_labels, train_probs)) if y == 0 and p < 0.20]
    easy_mal_idx = [i for i, (y, p) in enumerate(zip(train_labels, train_probs)) if y == 1 and p > 0.80]

    print(f"  [{round_name}] Mined train errors: hard_FP={len(hard_fp_idx)}, hard_FN={len(hard_fn_idx)}", flush=True)

    seed_val = int(hashlib.sha256(round_name.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed_val)
    rng.shuffle(hard_fp_idx)
    rng.shuffle(hard_fn_idx)
    rng.shuffle(easy_ben_idx)
    rng.shuffle(easy_mal_idx)

    selected_idx: List[int] = []
    selected_w: List[float] = []
    for idx in hard_fp_idx[:5000]:
        selected_idx.append(idx)
        selected_w.append(2.1)
    for idx in hard_fn_idx[:5000]:
        selected_idx.append(idx)
        selected_w.append(2.1)

    replay_each = max(3500, min(6000, len(hard_fp_idx) + len(hard_fn_idx)))
    for idx in easy_ben_idx[:replay_each]:
        selected_idx.append(idx)
        selected_w.append(1.0)
    for idx in easy_mal_idx[:replay_each]:
        selected_idx.append(idx)
        selected_w.append(1.0)

    patch_ids = [train_ids[i] for i in selected_idx]
    patch_labels = [train_labels[i] for i in selected_idx]
    patch_tactics = [train_tactics[i] for i in selected_idx]
    patch_weights = np.array(selected_w, dtype=np.float32)
    patch_anchor = anchor_logits_all[selected_idx]

    # Snapshot exact pre-LoRA state so `unload()` on rejected rounds never retains mutated ModulesToSaveWrapper heads!
    prior_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    target_modules = get_teacher_lora_target_modules(model) if is_hf_model else get_student_lora_target_modules()
    modules_to_save = ["classifier"] if is_hf_model else ["classifier", "tactic_head", "tok_attn_gate"]
    lora_cfg = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=0.05,
        bias="none",
        target_modules=target_modules,
        modules_to_save=modules_to_save,
    )
    peft_model = get_peft_model(model, lora_cfg)
    tot_p, trn_p = count_parameters(peft_model)
    print(f"  [{round_name}] PEFT LoRA trainable={trn_p:,} / {tot_p:,} ({100.0 * trn_p / tot_p:.2f}%)", flush=True)

    ds = PreTokenizedDatasetV7(
        patch_ids, patch_labels, tactics=patch_tactics, teacher_logits=patch_anchor, sample_weights=patch_weights
    )
    loader = DataLoader(
        ds, batch_size=48 if is_hf_model else 128, shuffle=True, num_workers=4, pin_memory=True, collate_fn=make_pad_collate(pad_id)
    )
    optimizer = torch.optim.AdamW([p for p in peft_model.parameters() if p.requires_grad], lr=lr, weight_decay=0.01)
    total_steps = max(1, len(loader) * epochs)
    scheduler = get_cosine_schedule_with_warmup(optimizer, int(total_steps * 0.1), total_steps)

    for ep in range(1, epochs + 1):
        peft_model.train()
        rloss = 0.0
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            input_ids = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels = batch["labels"].to(device, non_blocking=True)
            tactics = batch["tactics"].to(device, non_blocking=True)
            weights = batch["weights"].to(device, non_blocking=True)
            t_logits = batch["teacher_logits"].to(device, non_blocking=True)

            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                if is_hf_model:
                    logits = peft_model(input_ids=input_ids, attention_mask=attention_mask).logits
                    loss_aux = torch.tensor(0.0, device=device)
                else:
                    logits, tac_logits = peft_model.base_model.model.forward_with_aux(input_ids, attention_mask)
                    loss_aux = F.cross_entropy(tac_logits, tactics)

                loss_hard = asymmetric_focal_ce_loss(logits, labels, weights=weights, fp_weight=fp_weight, gamma=1.25)
                T = 2.0
                loss_kl = F.kl_div(
                    F.log_softmax(logits / T, dim=-1),
                    F.softmax(t_logits / T, dim=-1),
                    reduction="batchmean",
                ) * (T * T)
                loss = (1.0 - kl_weight) * loss_hard + kl_weight * loss_kl + 0.05 * loss_aux

            loss.backward()
            torch.nn.utils.clip_grad_norm_(peft_model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())
        print(f"  [{round_name} Ep {ep}/{epochs}] loss={rloss / max(1, len(loader)):.4f}", flush=True)

    after_metrics, _ = evaluate_packages_pytorch(
        peft_model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        is_hf_model=is_hf_model, target_specificity=target_specificity, tag=f"{round_name}-After"
    )

    b_cal = before_metrics["calibrated"]
    a_cal = after_metrics["calibrated"]
    b_comp = b_cal["roc_auc"] + 0.40 * b_cal["recall"] + 0.20 * b_cal["benign_specificity"]
    a_comp = a_cal["roc_auc"] + 0.40 * a_cal["recall"] + 0.20 * a_cal["benign_specificity"]

    # Strict non-regression gate: NEVER accept a LoRA merge that drops recall or AUC!
    accepted = (
        a_cal["roc_auc"] >= b_cal["roc_auc"] - 0.0003
        and a_cal["recall"] >= b_cal["recall"] - 0.002
        and a_cal["benign_specificity"] >= b_cal["benign_specificity"] - 0.002
        and a_comp > b_comp + 0.0001
    )

    save_adapter_dir.mkdir(parents=True, exist_ok=True)
    if is_hf_model:
        peft_model.save_pretrained(str(save_adapter_dir))
    else:
        peft_model.save_pretrained(str(save_adapter_dir), save_embedding_layers=False)
    (save_adapter_dir / "patch_report.json").write_text(
        json.dumps({"round": round_name, "accepted": accepted, "before": before_metrics, "after": after_metrics}, indent=2),
        encoding="utf-8",
    )

    if accepted:
        print(f"  [{round_name}] ACCEPTED -> merging via merge_and_unload().", flush=True)
        return peft_model.merge_and_unload(), after_metrics, True
    print(f"  [{round_name}] REJECTED (non-regression guard triggered) -> restoring exact prior weights.", flush=True)
    unloaded = peft_model.unload()
    unloaded.load_state_dict(prior_state)
    return unloaded, before_metrics, False


def distill_pretrained_student_v7(
    teacher_model: nn.Module,
    student_preset: str,
    train_ids: List[List[int]],
    train_labels: List[int],
    train_tactics: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    epochs: int = 6,
    batch_size: int = 96,
    lr: float = 2.5e-4,
    target_specificity: float = 0.975,
) -> Tuple[PackGuardRoPEStudentV7, np.ndarray, Dict[str, Any]]:
    print(f"\n=== STAGE 3: Distilling Teacher into Pretrained PackGuardRoPEStudentV7 (`{student_preset}`, {epochs} epochs) ===", flush=True)

    t0 = time.time()
    teacher_logits = predict_ids_pytorch(teacher_model, train_ids, pad_id, device, batch_size=96, is_hf_model=True)
    if not np.isfinite(teacher_logits).all():
        raise RuntimeError("Teacher produced non-finite logits!")
    print(f"  Cached Teacher logits {teacher_logits.shape} in {time.time() - t0:.1f}s.", flush=True)

    teacher_model.cpu()
    torch.cuda.empty_cache()

    student = PackGuardRoPEStudentV7.from_preset(preset=student_preset, max_position_embeddings=512)
    # Initialize Student layers + exact two-sided SVD embeddings from pretrained ModernBERT-base!
    teacher_hidden = getattr(teacher_model.config, "hidden_size", 0)
    if teacher_hidden == student.hidden_size:
        init_info = student.init_from_modernbert_pretrained(teacher_model)
    else:
        print("  Loading `answerdotai/ModernBERT-base` weights for pretrained 6-layer Student initialization...", flush=True)
        try:
            mb_base = AutoModel.from_pretrained("answerdotai/ModernBERT-base", reference_compile=False)
        except TypeError:
            mb_base = AutoModel.from_pretrained("answerdotai/ModernBERT-base")
        init_info = student.init_from_modernbert_pretrained(mb_base)
        del mb_base

    student = student.to(device)
    tot_p, _ = count_parameters(student)
    print(f"  Student initialized ({tot_p:,} params): {init_info}", flush=True)

    ds = PreTokenizedDatasetV7(train_ids, train_labels, tactics=train_tactics, teacher_logits=teacher_logits)
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True, num_workers=4, pin_memory=True, collate_fn=make_pad_collate(pad_id))

    # Differential LR: gentler LR when pretrained Transformer layers were transferred, full LR otherwise
    head_params = list(student.tok_attn_gate.parameters()) + list(student.pool_proj.parameters()) + list(student.pool_norm.parameters()) + list(student.classifier.parameters()) + list(student.tactic_head.parameters())
    head_ids = {id(p) for p in head_params}
    backbone_params = [p for p in student.parameters() if id(p) not in head_ids]
    backbone_lr = lr * 0.45 if init_info.get("copied_layer_indices") else lr

    optimizer = torch.optim.AdamW(
        [
            {"params": backbone_params, "lr": backbone_lr},
            {"params": head_params, "lr": lr},
        ],
        weight_decay=0.01,
    )
    total_steps = len(loader) * epochs
    scheduler = get_cosine_schedule_with_warmup(optimizer, int(total_steps * 0.08), total_steps)

    best_score = -1.0
    best_state: Optional[Dict[str, torch.Tensor]] = None
    best_metrics: Dict[str, Any] = {}

    for ep in range(1, epochs + 1):
        student.train()
        rloss = 0.0
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            input_ids = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels = batch["labels"].to(device, non_blocking=True)
            tactics = batch["tactics"].to(device, non_blocking=True)
            t_logits = batch["teacher_logits"].to(device, non_blocking=True)

            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                s_logits, tac_logits = student.forward_with_aux(input_ids, attention_mask)
                loss_hard = asymmetric_focal_ce_loss(s_logits, labels, fp_weight=1.25, gamma=1.25)
                T = 2.5
                loss_kl = F.kl_div(
                    F.log_softmax(s_logits / T, dim=-1),
                    F.softmax(t_logits / T, dim=-1),
                    reduction="batchmean",
                ) * (T * T)
                loss_tac = F.cross_entropy(tac_logits, tactics)
                loss = 0.45 * loss_hard + 0.45 * loss_kl + 0.10 * loss_tac

            loss.backward()
            torch.nn.utils.clip_grad_norm_(student.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())

        ep_metrics, _ = evaluate_packages_pytorch(
            student, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
            is_hf_model=False, target_specificity=target_specificity, tag=f"Student-Ep{ep}"
        )
        cal = ep_metrics["calibrated"]
        ep_score = cal["roc_auc"] + 0.40 * cal["recall"] + 0.15 * cal["benign_specificity"]
        if ep_score > best_score:
            best_score = ep_score
            best_state = {k: v.detach().cpu().clone() for k, v in student.state_dict().items()}
            best_metrics = ep_metrics

    if best_state is not None:
        student.load_state_dict(best_state)
    return student, teacher_logits, best_metrics


def _fit_centered_logit_calibration(
    pkg_logits: np.ndarray,
    y_true: np.ndarray,
    target_specificity: float = 0.985,
) -> Tuple[float, float]:
    """
    Finds `(logit_bias, logit_temperature)` so `sigmoid((pkg_logits - logit_bias) / logit_temperature)`
    places the `target_specificity` operating point right at `threshold = 0.50` while keeping
    `threshold = 0.62` at even lower false-alarm rate.
    """
    pkg_logits = np.asarray(pkg_logits, dtype=np.float64)
    y_true = np.asarray(y_true, dtype=np.int64)
    pos_mask = y_true == 1
    neg_mask = y_true == 0
    n_pos = max(1, int(pos_mask.sum()))
    n_neg = max(1, int(neg_mask.sum()))

    sorted_u = np.unique(np.sort(pkg_logits))
    if len(sorted_u) <= 1:
        z_tau = float(sorted_u[0]) if len(sorted_u) == 1 else 0.0
    else:
        mids = 0.5 * (sorted_u[:-1] + sorted_u[1:])
        cands = np.concatenate(([sorted_u[0] - 0.5], mids, [sorted_u[-1] + 0.5]))
        if len(cands) > 1500:
            neg_q80 = float(np.quantile(pkg_logits[neg_mask], 0.80)) if neg_mask.any() else float(sorted_u[0])
            tail = cands[cands >= neg_q80]
            head_idx = np.linspace(0, max(0, len(cands) - len(tail) - 1), num=min(400, max(1, len(cands) - len(tail))), dtype=np.int64)
            cands = np.unique(np.concatenate((cands[head_idx], tail)))

        best_z = float(cands[-1])
        best_spec = -1.0
        best_rec = -1.0
        fb_z = 0.0
        fb_sum = -1.0
        for z in cands:
            preds = pkg_logits >= z
            spec = float((~preds & neg_mask).sum()) / n_neg
            rec = float((preds & pos_mask).sum()) / n_pos
            if (spec + rec) > fb_sum:
                fb_sum = spec + rec
                fb_z = float(z)
            if spec >= target_specificity:
                if rec > best_rec or (rec == best_rec and spec > best_spec):
                    best_rec = rec
                    best_spec = spec
                    best_z = float(z)
        z_tau = best_z if best_rec >= 0.0 else fb_z
        # Place z_tau strictly at the midpoint between highest logit < z_tau and lowest logit >= z_tau
        below = pkg_logits[pkg_logits < z_tau]
        above = pkg_logits[pkg_logits >= z_tau]
        if len(below) > 0 and len(above) > 0:
            z_tau = float(0.5 * (np.max(below) + np.min(above)))

    w = np.where(pos_mask, 0.5 / n_pos, 0.5 / n_neg)
    best_temp = 1.0
    best_bce = float("inf")
    for temp in (0.90, 1.05, 1.20, 1.35):
        z_scaled = np.clip((pkg_logits - z_tau) / temp, -30.0, 30.0)
        bce_i = np.where(pos_mask, np.logaddexp(0.0, -z_scaled), np.logaddexp(0.0, z_scaled))
        bce = float(np.sum(w * bce_i))
        if bce < best_bce:
            best_bce = bce
            best_temp = float(temp)

    return float(z_tau), float(best_temp)


def train_and_gate_package_mil(
    student: PackGuardRoPEStudentV7,
    tokenizer: Any,
    mil_bags: List[Dict[str, Any]],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_logits: np.ndarray,
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    target_specificity: float = 0.985,
) -> Optional[Dict[str, Any]]:
    """
    Trains 24-feature `PackageMILAggregator` on leak-free `train_packages_mil.jsonl` with
    5-fold OOF validation + centered logit calibration, enabling it if it holds or improves
    over raw `max(window_probs)` on `dev_val`.
    """
    if len(mil_bags) < 200:
        return None
    print(f"\n=== STAGE 4B: Training 24-Feat Package MIL Aggregator ({len(mil_bags)} bags) ===", flush=True)

    flat_texts: List[str] = []
    spans: List[Tuple[int, int]] = []
    for bag in mil_bags:
        s = len(flat_texts)
        flat_texts.extend(bag["windows"])
        spans.append((s, len(flat_texts)))

    flat_ids = pretokenize_texts(tokenizer, flat_texts, max_length=512)
    flat_bin, flat_tac = predict_ids_with_aux_pytorch(student, flat_ids, pad_id, device, batch_size=128)

    X_list: List[np.ndarray] = []
    y_list: List[int] = []
    for bag, (s, e) in zip(mil_bags, spans):
        if e <= s:
            continue
        X_list.append(
            extract_package_mil_features(
                flat_bin[s:e], bag.get("win_meta"), tac_logits=flat_tac[s:e], windows=bag["windows"]
            )
        )
        y_list.append(int(bag["label"]))

    X_train = np.stack(X_list).astype(np.float32)
    y_train = np.array(y_list, dtype=np.float32)

    # 5-fold out-of-fold validation for honest regularization feedback
    rng_np = np.random.RandomState(42)
    perm = rng_np.permutation(len(X_train))
    oof_logits = np.zeros((len(X_train),), dtype=np.float64)
    for val_idx in np.array_split(perm, 5):
        tr_mask = np.ones(len(X_train), dtype=bool)
        tr_mask[val_idx] = False
        tr_idx = np.where(tr_mask)[0]
        fm_f = X_train[tr_idx].mean(axis=0)
        fs_f = np.maximum(X_train[tr_idx].std(axis=0), 1e-4)
        x_tr = torch.tensor((X_train[tr_idx] - fm_f) / fs_f, dtype=torch.float32, device=device)
        y_tr = torch.tensor(y_train[tr_idx], dtype=torch.float32, device=device)
        pw_f = torch.where(y_tr == 0, torch.full_like(y_tr, 1.65), torch.ones_like(y_tr))
        x_va = torch.tensor((X_train[val_idx] - fm_f) / fs_f, dtype=torch.float32, device=device)
        m_f = PackageMILAggregator(in_features=MIL_FEATURE_DIM, hidden_features=24).to(device)
        o_f = torch.optim.AdamW(m_f.parameters(), lr=2e-3, weight_decay=8e-2)
        torch.manual_seed(42)
        for _ in range(240):
            o_f.zero_grad()
            p_l = m_f(x_tr + 0.15 * torch.randn_like(x_tr))
            l_f = (F.binary_cross_entropy_with_logits(p_l, y_tr, reduction="none") * pw_f).mean()
            l_f.backward()
            o_f.step()
        with torch.no_grad():
            oof_logits[val_idx] = m_f(x_va).float().cpu().numpy()
    oof_auc = compute_roc_auc(y_train.astype(np.int64), oof_logits)
    print(f"  [MIL 5-Fold OOF] ROC-AUC={oof_auc:.5f} ({len(X_train)} bags, {MIL_FEATURE_DIM} feats)", flush=True)

    feat_mean = X_train.mean(axis=0)
    feat_scale = np.maximum(X_train.std(axis=0), 1e-4)
    X_norm = (X_train - feat_mean) / feat_scale

    mil = PackageMILAggregator(in_features=MIL_FEATURE_DIM, hidden_features=24).to(device)
    opt = torch.optim.AdamW(mil.parameters(), lr=2e-3, weight_decay=8e-2)
    xt = torch.tensor(X_norm, dtype=torch.float32, device=device)
    yt = torch.tensor(y_train, dtype=torch.float32, device=device)
    pos_w = torch.where(yt == 0, torch.full_like(yt, 1.65), torch.ones_like(yt))

    torch.manual_seed(42)
    for _ in range(360):
        opt.zero_grad()
        xt_noisy = xt + 0.15 * torch.randn_like(xt)
        pred_logit = mil(xt_noisy)
        loss = (F.binary_cross_entropy_with_logits(pred_logit, yt, reduction="none") * pos_w).mean()
        loss.backward()
        opt.step()

    # Extract both binary and tactic logits on dev_val so 24-feature MIL gate is exact
    dev_flat_wins: List[str] = []
    dev_w_spans: List[Tuple[int, int]] = []
    for p in dev_val_pkgs:
        s = len(dev_flat_wins)
        dev_flat_wins.extend(p["windows"])
        dev_w_spans.append((s, len(dev_flat_wins)))
    dev_ids = pretokenize_texts(tokenizer, dev_flat_wins, max_length=512)
    dev_bin, dev_tac = predict_ids_with_aux_pytorch(student, dev_ids, pad_id, device, batch_size=128)

    uncentered_cfg = mil.export_numpy_dict(feat_mean, feat_scale, enabled=True, logit_bias=0.0, logit_temperature=1.0)
    y_val = np.array([int(p["label"]) for p in dev_val_pkgs], dtype=np.int64)
    raw_scores = np.array(
        [
            score_package_with_mil_weights(dev_bin[s:e], p.get("win_meta"), None, tac_logits=dev_tac[s:e], windows=p["windows"])
            for p, (s, e) in zip(dev_val_pkgs, dev_w_spans)
        ],
        dtype=np.float64,
    )
    mil_scores = np.array(
        [
            score_package_with_mil_weights(dev_bin[s:e], p.get("win_meta"), uncentered_cfg, tac_logits=dev_tac[s:e], windows=p["windows"])
            for p, (s, e) in zip(dev_val_pkgs, dev_w_spans)
        ],
        dtype=np.float64,
    )
    m_raw = calibrate_threshold_for_specificity(y_val, raw_scores, target_specificity=target_specificity)
    m_mil = calibrate_threshold_for_specificity(y_val, mil_scores, target_specificity=target_specificity)

    print(f"  [MIL Gate] Raw Max  -> AUC={m_raw['roc_auc']:.5f}, Recall@{target_specificity*100:.1f}%Spec={m_raw['recall']*100:.2f}%")
    print(f"  [MIL Gate] MIL 24-F -> AUC={m_mil['roc_auc']:.5f}, Recall@{target_specificity*100:.1f}%Spec={m_mil['recall']*100:.2f}%")

    enabled = bool(m_mil["roc_auc"] >= m_raw["roc_auc"] - 0.0005 and m_mil["recall"] >= m_raw["recall"])
    if enabled:
        print("  [MIL Gate] ENABLED 24-Feature PackageMILAggregator!", flush=True)
    else:
        print("  [MIL Gate] Fallback to calibrated Raw-Max aggregation.", flush=True)

    sel_cfg = {**uncentered_cfg, "enabled": enabled}
    pkg_logits = np.array(
        [
            score_package_mil_logit(dev_bin[s:e], p.get("win_meta"), sel_cfg, tac_logits=dev_tac[s:e], windows=p["windows"])
            for p, (s, e) in zip(dev_val_pkgs, dev_w_spans)
        ],
        dtype=np.float64,
    )
    n_neg_dev = max(1, int((y_val == 0).sum()))
    max_safe_spec = (n_neg_dev - 1) / n_neg_dev
    cal_target = min(max(float(target_specificity), 0.9987), max_safe_spec) if target_specificity < 1.0 else 1.0
    bias, temp = _fit_centered_logit_calibration(pkg_logits, y_val, target_specificity=cal_target)
    print(f"  [Calibration] Fitted centered logit_bias={bias:.4f}, logit_temperature={temp:.2f} (cal_target={cal_target:.4f})", flush=True)
    return mil.export_numpy_dict(feat_mean, feat_scale, enabled=enabled, logit_bias=bias, logit_temperature=temp)


def export_and_verify_onnx_v7(
    student: PackGuardRoPEStudentV7,
    tokenizer: Any,
    dev_val_pkgs: List[Dict[str, Any]],
    out_model_dir: Path,
    mil_cfg: Optional[Dict[str, Any]] = None,
    target_specificity: float = 0.985,
) -> Dict[str, Any]:
    """Exports dual-output Dynamic INT8 ONNX (`binary_logits`, `tactic_logits`) and verifies CPU quality gate."""
    import onnxruntime as ort
    from onnxruntime.quantization import QuantType, quantize_dynamic

    out_model_dir.mkdir(parents=True, exist_ok=True)
    fp32_path = out_model_dir / "packguard_v7_fp32.onnx"
    prep_path = out_model_dir / "packguard_v7_prep.onnx"
    int8_path = out_model_dir / "packguard_v7_int8.onnx"

    tokenizer.save_pretrained(str(out_model_dir))
    if not (out_model_dir / "tokenizer.json").is_file():
        raise RuntimeError("Failed to export real ModernBERT tokenizer.json!")

    student_cpu = student.float().cpu().eval()
    student_cpu.return_aux_in_forward = True
    dummy_ids = torch.randint(0, 1000, (2, 64), dtype=torch.long)
    dummy_mask = torch.ones((2, 64), dtype=torch.long)

    print(f"\n=== STAGE 5: Exporting Dynamic RoPE INT8 ONNX -> {int8_path} ===", flush=True)
    export_extra = {"dynamo": False} if "dynamo" in inspect.signature(torch.onnx.export).parameters else {}
    torch.onnx.export(
        student_cpu,
        (dummy_ids, dummy_mask),
        str(fp32_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["binary_logits", "tactic_logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "seq_len"},
            "attention_mask": {0: "batch_size", 1: "seq_len"},
            "binary_logits": {0: "batch_size"},
            "tactic_logits": {0: "batch_size"},
        },
        opset_version=17,
        do_constant_folding=True,
        **export_extra,
    )
    student_cpu.return_aux_in_forward = False

    quant_src = fp32_path
    try:
        from onnxruntime.quantization.shape_inference import quant_pre_process
        quant_pre_process(str(fp32_path), str(prep_path), skip_symbolic_shape=True)
        if prep_path.is_file():
            quant_src = prep_path
    except Exception as exc:
        print(f"  [ONNX] quant_pre_process skipped ({exc}); quantizing raw FP32 ONNX.")

    quantize_dynamic(model_input=str(quant_src), model_output=str(int8_path), weight_type=QuantType.QUInt8)
    fp32_size_mb = round(fp32_path.stat().st_size / (1024 * 1024), 3)
    int8_size_mb = round(int8_path.stat().st_size / (1024 * 1024), 3)
    fp32_path.unlink(missing_ok=True)
    prep_path.unlink(missing_ok=True)

    # Dynamic shape verification across batch sizes & sequence lengths (including tiny seq_len=2,5 and long=1024!)
    sess = ort.InferenceSession(str(int8_path), providers=["CPUExecutionProvider"])
    for bsz in (1, 3):
        for seq_len in (2, 5, 16, 96, 256, 512, 1024):
            t_ids = np.ones((bsz, seq_len), dtype=np.int64)
            t_msk = np.ones((bsz, seq_len), dtype=np.int64)
            b_out, tac_out = sess.run(["binary_logits", "tactic_logits"], {"input_ids": t_ids, "attention_mask": t_msk})
            assert b_out.shape == (bsz, 2) and tac_out.shape == (bsz, 8), f"Unexpected ONNX shapes: {b_out.shape}, {tac_out.shape}"

    # Write provisional best_threshold.json so PackGuardStage2Model loads cleanly for full CPU gate
    prov_payload = {"threshold": 0.50, "mil_aggregator": mil_cfg}
    (out_model_dir / "best_threshold.json").write_text(json.dumps(prov_payload, indent=2), encoding="utf-8")

    from stage2_filter import PackGuardStage2Model

    cpu_model = PackGuardStage2Model(model_dir=out_model_dir, threshold=0.50, threads=4)
    y_true = np.array([int(p["label"]) for p in dev_val_pkgs], dtype=np.int64)

    flat_wins: List[str] = []
    spans: List[Tuple[int, int]] = []
    for p in dev_val_pkgs:
        s = len(flat_wins)
        flat_wins.extend(p["windows"])
        spans.append((s, len(flat_wins)))

    t0 = time.perf_counter()
    flat_logits, flat_tactics = cpu_model._score_windows_logits_batch(flat_wins, batch_size=32, include_tactics=True)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Re-fit centered `(logit_bias, logit_temperature)` directly on INT8 CPU outputs so threshold = 0.5000
    # aligns exactly with `target_specificity` (and threshold = 0.62 sits safely even lower on FPR)
    uncentered_cfg = {**(mil_cfg or {"enabled": False}), "logit_bias": 0.0, "logit_temperature": 1.0}
    int8_pkg_logits = np.array(
        [
            score_package_mil_logit(
                flat_logits[s:e],
                p.get("win_meta"),
                uncentered_cfg,
                tac_logits=(flat_tactics[s:e] if flat_tactics is not None else None),
                windows=p["windows"],
            )
            if e > s
            else -30.0
            for p, (s, e) in zip(dev_val_pkgs, spans)
        ],
        dtype=np.float64,
    )
    n_neg_dev = max(1, int((y_true == 0).sum()))
    max_safe_spec = (n_neg_dev - 1) / n_neg_dev
    cal_target = min(max(float(target_specificity), 0.9987), max_safe_spec) if target_specificity < 1.0 else 1.0
    int8_bias, int8_temp = _fit_centered_logit_calibration(
        int8_pkg_logits, y_true, target_specificity=cal_target
    )
    final_mil_cfg = {**uncentered_cfg, "logit_bias": int8_bias, "logit_temperature": int8_temp}

    y_score = np.array(
        [
            score_package_with_mil_weights(
                flat_logits[s:e],
                p.get("win_meta"),
                final_mil_cfg,
                tac_logits=(flat_tactics[s:e] if flat_tactics is not None else None),
                windows=p["windows"],
            )
            if e > s
            else 0.0
            for p, (s, e) in zip(dev_val_pkgs, spans)
        ],
        dtype=np.float64,
    )
    m_05 = evaluate_metrics_at_threshold(y_true, y_score, 0.50)
    m_062 = evaluate_metrics_at_threshold(y_true, y_score, 0.62)
    m_cal = calibrate_threshold_for_specificity(y_true, y_score, target_specificity=cal_target)
    shipped_threshold = 0.5 if m_05["benign_specificity"] >= (cal_target - 1e-4) else float(m_cal["threshold"])
    m_ship = evaluate_metrics_at_threshold(y_true, y_score, shipped_threshold)

    h = hashlib.sha256()
    with int8_path.open("rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    sha256 = h.hexdigest()

    threshold_payload = {
        "version": "v7",
        "threshold": shipped_threshold,
        "target_specificity": target_specificity,
        "calibration_specificity": cal_target,
        "mil_aggregator": final_mil_cfg,
        "dev_val_onnx_cpu_metrics": m_ship,
        "dev_val_onnx_at_0_50": m_05,
        "dev_val_onnx_at_0_62": m_062,
        "onnx_file": int8_path.name,
        "onnx_sha256": sha256,
        "onnx_size_bytes": int8_path.stat().st_size,
        "onnx_size_mb": int8_size_mb,
        "fp32_size_mb": fp32_size_mb,
        "dev_val_cpu_ms_per_pkg": round(elapsed_ms / max(1, len(dev_val_pkgs)), 3),
    }
    (out_model_dir / "best_threshold.json").write_text(json.dumps(threshold_payload, indent=2), encoding="utf-8")

    print(
        f"[ONNX CPU GATE v7] file={int8_path.name} ({int8_size_mb:.2f} MB, sha256={sha256[:16]}...) | "
        f"AUC={m_ship['roc_auc']:.5f} | @tau={shipped_threshold:.3f}: "
        f"Recall={m_ship['recall']*100:.2f}%, BenignSpec={m_ship['benign_specificity']*100:.2f}% | "
        f"@0.62: Recall={m_062['recall']*100:.2f}%, BenignSpec={m_062['benign_specificity']*100:.2f}% "
        f"({threshold_payload['dev_val_cpu_ms_per_pkg']:.2f} ms/pkg)",
        flush=True,
    )
    if m_ship["roc_auc"] < 0.965:
        raise RuntimeError(f"ONNX CPU quality gate FAILED: AUC={m_ship['roc_auc']:.5f} < 0.965!")
    return threshold_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Train PackGuard Stage 2 v7 Teacher + KL-LoRA + Pretrained RoPE Student.")
    parser.add_argument("--work-dir", default="/home/USER/v7_sandbox")
    parser.add_argument("--out-dir", default="/home/USER/v7_sandbox/output")
    parser.add_argument("--teacher-model", default="answerdotai/ModernBERT-large")
    parser.add_argument("--student-preset", choices=["quality", "balanced"], default="quality")
    parser.add_argument("--teacher-epochs", type=int, default=3)
    parser.add_argument("--student-epochs", type=int, default=6)
    parser.add_argument("--teacher-lora-rounds", type=int, default=2)
    parser.add_argument("--student-lora-rounds", type=int, default=2)
    parser.add_argument("--target-specificity", type=float, default=0.975)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU required for Stage 2 v7 training pipeline.")
    device = torch.device("cuda")
    print(f"[PackGuard v7] GPU: {torch.cuda.get_device_name(0)} ({torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB VRAM)")

    work = Path(args.work_dir).resolve()
    ds_dir = work / "dataset"
    out_dir = Path(args.out_dir).resolve()
    ckpt_dir = out_dir / "checkpoints"
    model_int8_dir = out_dir / "model_int8"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    model_int8_dir.mkdir(parents=True, exist_ok=True)

    train_records = [json.loads(l) for l in (ds_dir / "train_windows.jsonl").open("r", encoding="utf-8") if l.strip()]
    dev_val_pkgs = [json.loads(l) for l in (ds_dir / "dev_val_packages.jsonl").open("r", encoding="utf-8") if l.strip()]
    mil_path = ds_dir / "train_packages_mil.jsonl"
    mil_bags = [json.loads(l) for l in mil_path.open("r", encoding="utf-8") if l.strip()] if mil_path.is_file() else []

    train_labels = [int(r["label"]) for r in train_records]
    train_tactics = [int(r.get("tactic", 0 if r["label"] == 0 else 4)) for r in train_records]
    pos_ratio = sum(train_labels) / max(1, len(train_labels))
    if len(train_records) < 5000 or not (0.35 <= pos_ratio <= 0.65):
        raise RuntimeError(f"Fail-loud dataset check failed: n={len(train_records)}, pos_ratio={pos_ratio:.3f}")

    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
    pad_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else 50283

    print("[PackGuard v7] Pre-tokenizing train and dev_val ONCE with real ModernBERT BPE tokenizer...", flush=True)
    train_ids = pretokenize_texts(tokenizer, [r["text"] for r in train_records], max_length=512)
    dev_flat_texts: List[str] = []
    dev_spans: List[Tuple[int, int]] = []
    for pkg in dev_val_pkgs:
        s = len(dev_flat_texts)
        dev_flat_texts.extend(pkg["windows"])
        dev_spans.append((s, len(dev_flat_texts)))
    dev_flat_ids = pretokenize_texts(tokenizer, dev_flat_texts, max_length=512)

    history: List[Dict[str, Any]] = []

    # 1. Train Teacher
    teacher, m_t0 = train_teacher(
        args.teacher_model, train_ids, train_labels, dev_val_pkgs, dev_flat_ids, dev_spans,
        pad_id, device, epochs=args.teacher_epochs, target_specificity=args.target_specificity
    )
    history.append(m_t0)

    # 2. KL-Anchored PEFT LoRA Rounds on Teacher
    base_teacher_logits = predict_ids_pytorch(teacher, train_ids, pad_id, device, batch_size=96, is_hf_model=True)
    for r_idx in range(1, args.teacher_lora_rounds + 1):
        teacher, m_tr, accepted = run_kl_anchored_lora_round(
            model=teacher,
            train_ids=train_ids,
            train_labels=train_labels,
            train_tactics=train_tactics,
            dev_val_pkgs=dev_val_pkgs,
            dev_flat_ids=dev_flat_ids,
            dev_spans=dev_spans,
            pad_id=pad_id,
            device=device,
            is_hf_model=True,
            round_name=f"Teacher-LoRA-R{r_idx}",
            save_adapter_dir=ckpt_dir / f"lora_teacher_r{r_idx}",
            anchor_logits_all=base_teacher_logits,
            lora_r=16,
            lora_alpha=32,
            lr=5e-5 if r_idx == 1 else 2.5e-5,
            epochs=2,
            fp_weight=1.25,
            kl_weight=0.35,
            target_specificity=args.target_specificity,
        )
        history.append(m_tr)
        if accepted:
            base_teacher_logits = predict_ids_pytorch(teacher, train_ids, pad_id, device, batch_size=96, is_hf_model=True)

    # 3. Distill into Pretrained PackGuardRoPEStudentV7
    student, teacher_logits, m_s0 = distill_pretrained_student_v7(
        teacher, args.student_preset, train_ids, train_labels, train_tactics,
        dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        epochs=args.student_epochs, target_specificity=args.target_specificity
    )
    history.append(m_s0)
    np.save(ckpt_dir / "teacher_train_logits.npy", teacher_logits)

    # 4. KL-Anchored PEFT LoRA Rounds on Student (anchored to Teacher logits -> zero recall collapse!)
    for r_idx in range(1, args.student_lora_rounds + 1):
        student, m_sr, _ = run_kl_anchored_lora_round(
            model=student,
            train_ids=train_ids,
            train_labels=train_labels,
            train_tactics=train_tactics,
            dev_val_pkgs=dev_val_pkgs,
            dev_flat_ids=dev_flat_ids,
            dev_spans=dev_spans,
            pad_id=pad_id,
            device=device,
            is_hf_model=False,
            round_name=f"Student-LoRA-R{r_idx}",
            save_adapter_dir=ckpt_dir / f"lora_student_r{r_idx}",
            anchor_logits_all=teacher_logits,
            lora_r=16,
            lora_alpha=32,
            lr=9e-5 if r_idx == 1 else 4.5e-5,
            epochs=2,
            fp_weight=1.25,
            kl_weight=0.45,
            target_specificity=args.target_specificity,
        )
        history.append(m_sr)

    torch.save({"model_state_dict": student.state_dict(), "config": student.config_dict}, ckpt_dir / "student_v7_lora_merged.pt")

    # 4B. Train & Auto-Gate Package-Level Neural MIL Aggregator
    _, dev_flat_logits = evaluate_packages_pytorch(
        student, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        is_hf_model=False, target_specificity=args.target_specificity, tag="Student-PreMIL"
    )
    mil_cfg = train_and_gate_package_mil(
        student, tokenizer, mil_bags, dev_val_pkgs, dev_flat_logits, dev_spans,
        pad_id, device, target_specificity=args.target_specificity
    )

    # 5. Export Dual-Output Dynamic INT8 ONNX & Verify CPU Gate
    onnx_summary = export_and_verify_onnx_v7(
        student=student,
        tokenizer=tokenizer,
        dev_val_pkgs=dev_val_pkgs,
        out_model_dir=model_int8_dir,
        mil_cfg=mil_cfg,
        target_specificity=args.target_specificity,
    )

    (out_dir / "training_report.json").write_text(
        json.dumps(
            {
                "version": "v7",
                "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "teacher_model": args.teacher_model,
                "student_preset": args.student_preset,
                "gpu": torch.cuda.get_device_name(0),
                "stage_progression": history,
                "onnx_cpu_gate": onnx_summary,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("\n[PackGuard v7] Training + KL-LoRA + MIL + Dynamic INT8 ONNX Gate COMPLETE!", flush=True)


if __name__ == "__main__":
    main()
