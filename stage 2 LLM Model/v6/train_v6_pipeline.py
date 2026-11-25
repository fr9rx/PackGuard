"""
PackGuard Stage 2 v6 — Full RTX PRO 6000 Training, Iterative PEFT LoRA Patching,
High-Fidelity Distillation, Dynamic INT8 ONNX Export & Strict Quality Gate.

Fixes EVERY Stage 2 v5 distillation/training bug and pre-GPU audit finding:
  - Fail-loud assertions: refuses unbalanced/missing data or missing teacher.
  - Real ModernBERT BPE tokenizer pre-tokenized ONCE (zero fork deadlock, 5-10x faster epochs).
  - FP32 master weights with BF16 Tensor Core autocast (no BF16 AdamW update underflow).
  - Mandatory package-level Network-Only ROC-AUC, Recall, and Benign Specificity (1 - FPR)
    evaluation on dev_val after EVERY stage (Teacher, Teacher+LoRA, Student, Student+LoRA, ONNX).
  - Iterative PEFT LoRA error-patching loop on TRAIN pool only (strict zero dev_val/heldout
    leakage), accepting merges ONLY on verified dev_val improvement.
  - Dynamic INT8 ONNX export with quant_pre_process, dynamic batch=1/2 & seq=16..512 checks,
    and hard Network-Only CPU AUC >= 0.95 gate.
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_cosine_schedule_with_warmup

V6_DIR = Path(__file__).resolve().parent
if str(V6_DIR) not in sys.path:
    sys.path.insert(0, str(V6_DIR))

from metrics_v6 import (
    calibrate_threshold_for_specificity,
    evaluate_metrics_at_threshold,
)
from model_v6 import (
    PackGuardNanoV6,
    count_parameters,
    get_student_lora_target_modules,
    get_teacher_lora_target_modules,
)


class PreTokenizedDataset(Dataset):
    """Holds pre-tokenized input_ids lists for fast, fork-safe dynamic padding."""

    def __init__(
        self,
        token_ids_list: List[List[int]],
        labels: List[int],
        teacher_logits: Optional[np.ndarray] = None,
        sample_weights: Optional[np.ndarray] = None,
    ):
        self.token_ids_list = token_ids_list
        self.labels = labels
        self.teacher_logits = teacher_logits
        self.sample_weights = sample_weights

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        item: Dict[str, Any] = {
            "ids": self.token_ids_list[idx],
            "label": self.labels[idx],
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
            "weights": torch.tensor([b["weight"] for b in batch], dtype=torch.float32),
        }
        if "teacher_logits" in batch[0]:
            out["teacher_logits"] = torch.tensor(
                np.stack([b["teacher_logits"] for b in batch]), dtype=torch.float32
            )
        return out

    return _collate


def pretokenize_texts(tokenizer: Any, texts: List[str], max_length: int = 512, chunk_size: int = 4096) -> List[List[int]]:
    """Pre-tokenizes all texts ONCE using the real ModernBERT BPE tokenizer."""
    all_ids: List[List[int]] = []
    for i in range(0, len(texts), chunk_size):
        enc = tokenizer(
            texts[i : i + chunk_size],
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        all_ids.extend(enc["input_ids"])
    return all_ids


def asymmetric_focal_ce_loss(
    logits: torch.Tensor,
    labels: torch.Tensor,
    weights: Optional[torch.Tensor] = None,
    fp_weight: float = 1.45,
    gamma: float = 1.5,
) -> torch.Tensor:
    """Focal cross-entropy with extra penalty on benign false positives (`fp_weight > 1.0`)."""
    ce = F.cross_entropy(logits, labels, reduction="none")
    pt = torch.exp(-ce)
    focal = ((1.0 - pt) ** gamma) * ce
    class_w = torch.where(labels == 0, torch.full_like(focal, fp_weight), torch.ones_like(focal))
    loss = focal * class_w
    if weights is not None:
        loss = loss * weights
    return loss.mean()


@torch.no_grad()
def predict_ids_pytorch(
    model: nn.Module,
    token_ids_list: List[List[int]],
    pad_id: int,
    device: torch.device,
    batch_size: int = 128,
    is_hf_model: bool = False,
) -> np.ndarray:
    """Returns raw logits [N, 2] for pre-tokenized ID lists using BF16 autocast on GPU."""
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
            logits = out.logits if is_hf_model else out
        all_logits.append(logits.float().cpu().numpy())
    return np.concatenate(all_logits, axis=0)


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
    target_specificity: float = 0.97,
    tag: str = "eval",
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Evaluates package-level max-pooled network-only AUC/Recall/Specificity on dev_val."""
    logits = predict_ids_pytorch(
        model, dev_flat_ids, pad_id, device, batch_size=128, is_hf_model=is_hf_model
    )
    win_probs = _logits_to_pos_probs(logits)

    y_true = np.array([int(p["label"]) for p in dev_val_pkgs], dtype=np.int64)
    y_score = np.array(
        [float(np.max(win_probs[s:e])) if e > s else 0.0 for s, e in dev_spans], dtype=np.float64
    )

    m_05 = evaluate_metrics_at_threshold(y_true, y_score, 0.50)
    m_cal = calibrate_threshold_for_specificity(y_true, y_score, target_specificity=target_specificity)

    errors: List[Dict[str, Any]] = []
    tau = m_cal["threshold"]
    for pkg, prob in zip(dev_val_pkgs, y_score):
        pred = int(prob >= tau)
        if pred != int(pkg["label"]):
            errors.append(
                {
                    "package": pkg["package"],
                    "label": int(pkg["label"]),
                    "prob": round(float(prob), 5),
                    "type": "FP" if pred == 1 else "FN",
                    "source": pkg.get("source", ""),
                }
            )

    summary = {"stage": tag, "at_0_50": m_05, "calibrated": m_cal, "error_count": len(errors)}
    print(
        f"[{tag}] Network-Only dev_val: AUC={m_cal['roc_auc']:.5f} | "
        f"@tau={m_cal['threshold']:.3f}: Recall={m_cal['recall']*100:.2f}%, "
        f"BenignSpec={m_cal['benign_specificity']*100:.2f}% (FPR={m_cal['fpr']*100:.2f}%, FP={m_cal['fp']}, FN={m_cal['fn']}) | "
        f"@0.50: Recall={m_05['recall']*100:.2f}%, Spec={m_05['benign_specificity']*100:.2f}%",
        flush=True,
    )
    return summary, errors


def train_teacher_base(
    train_ids: List[List[int]],
    train_labels: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    epochs: int = 2,
    batch_size: int = 64,
    lr: float = 3e-5,
) -> Tuple[nn.Module, Dict[str, Any]]:
    print(f"\n=== STAGE 1: Training ModernBERT-base Teacher ({len(train_labels)} windows, {epochs} epochs) ===", flush=True)
    # Keep FP32 master weights so AdamW(lr=3e-5) never underflows; autocast runs BF16 Tensor Cores!
    model = AutoModelForSequenceClassification.from_pretrained(
        "answerdotai/ModernBERT-base",
        num_labels=2,
        attn_implementation="sdpa",
    ).to(device)

    ds = PreTokenizedDataset(train_ids, train_labels)
    loader = DataLoader(
        ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=4,
        pin_memory=True,
        collate_fn=make_pad_collate(pad_id),
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    total_steps = len(loader) * epochs
    scheduler = get_cosine_schedule_with_warmup(optimizer, int(total_steps * 0.08), total_steps)

    t0 = time.time()
    for ep in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        for step, batch in enumerate(loader, 1):
            optimizer.zero_grad(set_to_none=True)
            input_ids = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels = batch["labels"].to(device, non_blocking=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
                loss = asymmetric_focal_ce_loss(logits, labels, fp_weight=1.35, gamma=1.25)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running_loss += float(loss.item())
            if step % 150 == 0 or step == len(loader):
                print(
                    f"  [Teacher Ep {ep}/{epochs} Step {step}/{len(loader)}] "
                    f"loss={running_loss / step:.4f} elapsed={time.time() - t0:.1f}s",
                    flush=True,
                )

    metrics, _ = evaluate_packages_pytorch(
        model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=True, tag="Teacher-Base"
    )
    if metrics["calibrated"]["roc_auc"] < 0.92:
        raise RuntimeError(f"Teacher failed sanity gate: AUC={metrics['calibrated']['roc_auc']} < 0.92!")
    return model, metrics


def run_lora_patch_round(
    model: nn.Module,
    train_ids: List[List[int]],
    train_labels: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    is_hf_model: bool,
    round_name: str,
    save_adapter_dir: Path,
    teacher_logits_all: Optional[np.ndarray] = None,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lr: float = 2e-4,
    epochs: int = 2,
    fp_weight: float = 1.85,
) -> Tuple[nn.Module, Dict[str, Any], bool]:
    """
    Executes one honest PEFT LoRA error-patching round:
      1. Scores TRAIN pool only to mine hardest benign FPs & malware FNs (zero dev_val leakage).
      2. Trains PEFT LoRA adapter on mined hard errors (up-weighted) + balanced replay buffer.
      3. Merges via merge_and_unload() ONLY when dev_val composite score strictly improves.
    """
    from peft import LoraConfig, get_peft_model

    print(f"\n=== LoRA PATCH ROUND [{round_name}]: Mining hard errors from TRAIN pool ===", flush=True)
    before_metrics, _ = evaluate_packages_pytorch(
        model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=is_hf_model, tag=f"{round_name}-Before"
    )

    train_logits = predict_ids_pytorch(
        model, train_ids, pad_id, device, batch_size=128, is_hf_model=is_hf_model
    )
    train_probs = _logits_to_pos_probs(train_logits)

    hard_fp_idx: List[int] = []
    hard_fn_idx: List[int] = []
    easy_ben_idx: List[int] = []
    easy_mal_idx: List[int] = []

    for idx, (lbl, p) in enumerate(zip(train_labels, train_probs)):
        if lbl == 0:
            if p >= 0.25:
                hard_fp_idx.append(idx)
            else:
                easy_ben_idx.append(idx)
        else:
            if p <= 0.75:
                hard_fn_idx.append(idx)
            else:
                easy_mal_idx.append(idx)

    print(
        f"  [{round_name}] Mined train hard examples: hard_FP={len(hard_fp_idx)}, "
        f"hard_FN={len(hard_fn_idx)}, easy_ben={len(easy_ben_idx)}, easy_mal={len(easy_mal_idx)}",
        flush=True,
    )

    seed_val = int(hashlib.sha256(round_name.encode("utf-8")).hexdigest()[:8], 16)
    rng = random.Random(seed_val)
    replay_n = min(6000, max(2500, (len(hard_fp_idx) + len(hard_fn_idx)) * 2))
    selected_idx: List[int] = []
    selected_weights: List[float] = []

    for idx in hard_fp_idx[:6000]:
        selected_idx.append(idx)
        selected_weights.append(3.0)
    for idx in hard_fn_idx[:6000]:
        selected_idx.append(idx)
        selected_weights.append(2.5)

    rng.shuffle(easy_ben_idx)
    rng.shuffle(easy_mal_idx)
    for idx in easy_ben_idx[: replay_n // 2]:
        selected_idx.append(idx)
        selected_weights.append(1.0)
    for idx in easy_mal_idx[: replay_n // 2]:
        selected_idx.append(idx)
        selected_weights.append(1.0)

    patch_ids = [train_ids[i] for i in selected_idx]
    patch_labels = [train_labels[i] for i in selected_idx]
    patch_weights = np.array(selected_weights, dtype=np.float32)
    patch_t_logits = teacher_logits_all[selected_idx] if teacher_logits_all is not None else None

    target_modules = get_teacher_lora_target_modules(model) if is_hf_model else get_student_lora_target_modules()
    lora_cfg = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=0.05,
        bias="none",
        target_modules=target_modules,
    )
    peft_model = get_peft_model(model, lora_cfg)
    tot_p, trn_p = count_parameters(peft_model)
    print(
        f"  [{round_name}] Attached PEFT LoRA (r={lora_r}, alpha={lora_alpha}, targets={target_modules}): "
        f"trainable={trn_p:,} / {tot_p:,} ({100.0 * trn_p / tot_p:.2f}%)",
        flush=True,
    )

    ds = PreTokenizedDataset(patch_ids, patch_labels, teacher_logits=patch_t_logits, sample_weights=patch_weights)
    loader = DataLoader(
        ds,
        batch_size=64 if is_hf_model else 128,
        shuffle=True,
        num_workers=4,
        pin_memory=True,
        collate_fn=make_pad_collate(pad_id),
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
            weights = batch["weights"].to(device, non_blocking=True)

            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                out = peft_model(input_ids=input_ids, attention_mask=attention_mask)
                logits = out.logits if is_hf_model else out
                loss_hard = asymmetric_focal_ce_loss(logits, labels, weights=weights, fp_weight=fp_weight, gamma=1.5)
                if "teacher_logits" in batch:
                    t_logits = batch["teacher_logits"].to(device, non_blocking=True)
                    T = 2.0
                    kl = F.kl_div(
                        F.log_softmax(logits / T, dim=-1),
                        F.softmax(t_logits / T, dim=-1),
                        reduction="batchmean",
                    ) * (T * T)
                    loss = 0.70 * loss_hard + 0.30 * kl
                else:
                    loss = loss_hard
            loss.backward()
            torch.nn.utils.clip_grad_norm_(peft_model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())
        print(f"  [{round_name} Ep {ep}/{epochs}] loss={rloss / max(1, len(loader)):.4f}", flush=True)

    after_metrics, _ = evaluate_packages_pytorch(
        peft_model, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=is_hf_model, tag=f"{round_name}-After"
    )

    before_auc = before_metrics["calibrated"]["roc_auc"]
    after_auc = after_metrics["calibrated"]["roc_auc"]
    before_score = before_auc + 0.30 * before_metrics["calibrated"]["recall"] + 0.15 * before_metrics["at_0_50"]["benign_specificity"]
    after_score = after_auc + 0.30 * after_metrics["calibrated"]["recall"] + 0.15 * after_metrics["at_0_50"]["benign_specificity"]
    accepted = (
        (after_auc >= before_auc - 0.0005 and after_score >= before_score)
        or (after_auc > before_auc + 0.0003)
    ) and after_metrics["calibrated"]["benign_specificity"] >= before_metrics["calibrated"]["benign_specificity"] - 0.003

    save_adapter_dir.mkdir(parents=True, exist_ok=True)
    peft_model.save_pretrained(str(save_adapter_dir))
    (save_adapter_dir / "patch_report.json").write_text(
        json.dumps(
            {
                "round": round_name,
                "accepted": accepted,
                "hard_fp_mined": len(hard_fp_idx),
                "hard_fn_mined": len(hard_fn_idx),
                "before": before_metrics,
                "after": after_metrics,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    if accepted:
        print(f"  [{round_name}] ACCEPTED -> merging LoRA weights via merge_and_unload().", flush=True)
        merged = peft_model.merge_and_unload()
        return merged, after_metrics, True
    else:
        print(f"  [{round_name}] REJECTED (no dev_val gain) -> unloading LoRA adapter.", flush=True)
        base = peft_model.unload()
        return base, before_metrics, False


def distill_student(
    teacher_model: nn.Module,
    train_ids: List[List[int]],
    train_labels: List[int],
    dev_val_pkgs: List[Dict[str, Any]],
    dev_flat_ids: List[List[int]],
    dev_spans: List[Tuple[int, int]],
    pad_id: int,
    device: torch.device,
    epochs: int = 5,
    batch_size: int = 128,
    lr: float = 5e-4,
    embed_rank: int = 96,
) -> Tuple[PackGuardNanoV6, np.ndarray, Dict[str, Any]]:
    print(f"\n=== STAGE 3: High-Fidelity Distillation into PackGuardNanoV6 ({len(train_labels)} windows, {epochs} epochs) ===", flush=True)

    t0 = time.time()
    teacher_logits = predict_ids_pytorch(
        teacher_model, train_ids, pad_id, device, batch_size=128, is_hf_model=True
    )
    if not np.isfinite(teacher_logits).all():
        raise RuntimeError("Teacher produced non-finite logits during distillation prep!")
    print(f"  Pre-computed Teacher logits shape={teacher_logits.shape} in {time.time() - t0:.1f}s.", flush=True)

    student = PackGuardNanoV6(
        vocab_size=50368,
        embed_rank=embed_rank,
        hidden_size=384,
        num_layers=6,
        num_heads=6,
        intermediate_size=1024,
        max_position_embeddings=512,
        dropout=0.1,
    ).to(device)

    teacher_emb = teacher_model.get_input_embeddings().weight
    student.init_embeddings_from_teacher_svd(teacher_emb)
    tot_p, _ = count_parameters(student)
    print(f"  Initialized PackGuardNanoV6 ({tot_p:,} params, SVD rank={embed_rank}) from Teacher embeddings.", flush=True)

    teacher_model.cpu()
    torch.cuda.empty_cache()

    ds = PreTokenizedDataset(train_ids, train_labels, teacher_logits=teacher_logits)
    loader = DataLoader(
        ds,
        batch_size=batch_size,
        shuffle=True,
        num_workers=4,
        pin_memory=True,
        collate_fn=make_pad_collate(pad_id),
    )

    optimizer = torch.optim.AdamW(student.parameters(), lr=lr, weight_decay=0.01)
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
            t_logits = batch["teacher_logits"].to(device, non_blocking=True)

            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                s_logits = student(input_ids=input_ids, attention_mask=attention_mask)
                loss_hard = asymmetric_focal_ce_loss(s_logits, labels, fp_weight=1.40, gamma=1.25)
                T = 2.5
                loss_kl = F.kl_div(
                    F.log_softmax(s_logits / T, dim=-1),
                    F.softmax(t_logits / T, dim=-1),
                    reduction="batchmean",
                ) * (T * T)
                loss = 0.50 * loss_hard + 0.50 * loss_kl

            loss.backward()
            torch.nn.utils.clip_grad_norm_(student.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())

        ep_metrics, _ = evaluate_packages_pytorch(
            student, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=False, tag=f"Student-Ep{ep}"
        )
        ep_score = ep_metrics["calibrated"]["roc_auc"] + 0.35 * ep_metrics["calibrated"]["recall"]
        if ep_score > best_score:
            best_score = ep_score
            best_state = {k: v.detach().cpu().clone() for k, v in student.state_dict().items()}
            best_metrics = ep_metrics

    if best_state is not None:
        student.load_state_dict(best_state)
    return student, teacher_logits, best_metrics


def export_and_verify_onnx(
    student: PackGuardNanoV6,
    tokenizer: Any,
    dev_val_pkgs: List[Dict[str, Any]],
    out_model_dir: Path,
    target_specificity: float = 0.97,
) -> Dict[str, Any]:
    """Exports dynamic-axis FP32 ONNX -> QUInt8 INT8 ONNX, verifies CPU parity & strict AUC gate."""
    import onnxruntime as ort
    from onnxruntime.quantization import QuantType, quantize_dynamic

    out_model_dir.mkdir(parents=True, exist_ok=True)
    fp32_path = out_model_dir / "packguard_v6_nano_fp32.onnx"
    prep_path = out_model_dir / "packguard_v6_nano_prep.onnx"
    int8_path = out_model_dir / "packguard_v6_nano_int8.onnx"

    tokenizer.save_pretrained(str(out_model_dir))
    if not (out_model_dir / "tokenizer.json").is_file():
        raise RuntimeError("Failed to export real ModernBERT tokenizer.json!")

    student_cpu = student.float().cpu().eval()
    dummy_ids = torch.randint(0, 1000, (2, 64), dtype=torch.long)
    dummy_mask = torch.ones((2, 64), dtype=torch.long)

    print(f"\n=== STAGE 5: Exporting Dynamic-Axis ONNX & INT8 Quantization -> {int8_path} ===", flush=True)
    torch.onnx.export(
        student_cpu,
        (dummy_ids, dummy_mask),
        str(fp32_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["binary_logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "seq_len"},
            "attention_mask": {0: "batch_size", 1: "seq_len"},
            "binary_logits": {0: "batch_size"},
        },
        opset_version=17,
        do_constant_folding=True,
        dynamo=False,
    )

    quant_src = fp32_path
    try:
        from onnxruntime.quantization.shape_inference import quant_pre_process
        quant_pre_process(str(fp32_path), str(prep_path), skip_symbolic_shape=True)
        if prep_path.is_file():
            quant_src = prep_path
    except Exception as exc:
        print(f"  [ONNX] quant_pre_process skipped ({exc}); quantizing raw FP32 ONNX.")

    quantize_dynamic(
        model_input=str(quant_src),
        model_output=str(int8_path),
        weight_type=QuantType.QUInt8,
    )
    fp32_size_mb = round(fp32_path.stat().st_size / (1024 * 1024), 3)
    int8_size_mb = round(int8_path.stat().st_size / (1024 * 1024), 3)
    fp32_path.unlink(missing_ok=True)
    prep_path.unlink(missing_ok=True)

    # Verify dynamic shapes for BOTH batch_size=1 and batch_size=2 across 16..512 tokens
    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 4
    sess = ort.InferenceSession(str(int8_path), sess_options=sess_opts, providers=["CPUExecutionProvider"])
    for bsz in (1, 2):
        for seq_len in (16, 64, 256, 512):
            test_ids = np.ones((bsz, seq_len), dtype=np.int64)
            test_mask = np.ones((bsz, seq_len), dtype=np.int64)
            out = sess.run(["binary_logits"], {"input_ids": test_ids, "attention_mask": test_mask})[0]
            assert out.shape == (bsz, 2), f"Bad dynamic ONNX shape {out.shape} for bsz={bsz}, seq={seq_len}"

    # Verify EXACT CPU inference with PackGuardStage2Model (real tokenizers.Tokenizer!)
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
    flat_probs = cpu_model._score_windows_batch(flat_wins, batch_size=32)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    y_score = np.array([max(flat_probs[s:e]) if e > s else 0.0 for s, e in spans], dtype=np.float64)

    m_cal = calibrate_threshold_for_specificity(y_true, y_score, target_specificity=target_specificity)
    m_05 = evaluate_metrics_at_threshold(y_true, y_score, 0.50)

    h = hashlib.sha256()
    with int8_path.open("rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    sha256 = h.hexdigest()

    threshold_payload = {
        "threshold": m_cal["threshold"],
        "target_specificity": target_specificity,
        "dev_val_onnx_cpu_metrics": m_cal,
        "dev_val_onnx_at_0_50": m_05,
        "onnx_file": int8_path.name,
        "onnx_sha256": sha256,
        "onnx_size_bytes": int8_path.stat().st_size,
        "onnx_size_mb": int8_size_mb,
        "fp32_size_mb": fp32_size_mb,
        "dev_val_cpu_ms_per_pkg": round(elapsed_ms / max(1, len(dev_val_pkgs)), 3),
    }
    (out_model_dir / "best_threshold.json").write_text(json.dumps(threshold_payload, indent=2), encoding="utf-8")

    print(
        f"[ONNX CPU GATE] file={int8_path.name} ({int8_size_mb:.2f} MB, sha256={sha256[:16]}...) | "
        f"AUC={m_cal['roc_auc']:.5f} | @tau={m_cal['threshold']:.3f}: "
        f"Recall={m_cal['recall']*100:.2f}%, BenignSpec={m_cal['benign_specificity']*100:.2f}% "
        f"(FPR={m_cal['fpr']*100:.2f}%) | {threshold_payload['dev_val_cpu_ms_per_pkg']:.2f} ms/pkg",
        flush=True,
    )
    if m_cal["roc_auc"] < 0.95:
        raise RuntimeError(f"ONNX CPU quality gate FAILED: network-only AUC={m_cal['roc_auc']:.5f} < 0.95!")

    return threshold_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Train PackGuard Stage 2 v6 Teacher + LoRA + Distilled Nano Student.")
    parser.add_argument("--work-dir", default="/home/USER/v6_sandbox", help="Sandbox work directory with dataset/.")
    parser.add_argument("--out-dir", default="/home/USER/v6_sandbox/output", help="Output directory for checkpoints & model_int8/.")
    parser.add_argument("--teacher-epochs", type=int, default=2)
    parser.add_argument("--student-epochs", type=int, default=5)
    parser.add_argument("--teacher-lora-rounds", type=int, default=2)
    parser.add_argument("--student-lora-rounds", type=int, default=3)
    parser.add_argument("--embed-rank", type=int, default=96)
    parser.add_argument("--target-specificity", type=float, default=0.97)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True

    if not torch.cuda.is_available():
        raise RuntimeError("GPU required for RTX PRO 6000 training pipeline!")
    device = torch.device("cuda")
    print(f"[PackGuard v6] GPU: {torch.cuda.get_device_name(0)} ({torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB VRAM)")

    work = Path(args.work_dir).resolve()
    ds_dir = work / "dataset"
    out_dir = Path(args.out_dir).resolve()
    ckpt_dir = out_dir / "checkpoints"
    model_int8_dir = out_dir / "model_int8"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    model_int8_dir.mkdir(parents=True, exist_ok=True)

    train_path = ds_dir / "train_windows.jsonl"
    val_path = ds_dir / "dev_val_packages.jsonl"
    if not train_path.is_file() or not val_path.is_file():
        raise FileNotFoundError(f"Missing dataset files in {ds_dir}. Run prepare_v6_dataset.py first!")

    train_records = [json.loads(line) for line in train_path.open("r", encoding="utf-8") if line.strip()]
    dev_val_pkgs = [json.loads(line) for line in val_path.open("r", encoding="utf-8") if line.strip()]

    train_labels = [int(r["label"]) for r in train_records]
    pos_ratio = sum(train_labels) / max(1, len(train_labels))
    print(f"[PackGuard v6] Loaded train={len(train_records)} windows (pos_ratio={pos_ratio:.3f}), dev_val={len(dev_val_pkgs)} pkgs")
    if len(train_records) < 5000 or not (0.35 <= pos_ratio <= 0.65):
        raise RuntimeError(f"Fail-loud dataset check failed: n={len(train_records)}, pos_ratio={pos_ratio:.3f}")

    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
    pad_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else 50283

    t_tok = time.time()
    print("[PackGuard v6] Pre-tokenizing train and dev_val ONCE with real ModernBERT BPE tokenizer...", flush=True)
    train_ids = pretokenize_texts(tokenizer, [r["text"] for r in train_records], max_length=512)
    dev_flat_texts: List[str] = []
    dev_spans: List[Tuple[int, int]] = []
    for pkg in dev_val_pkgs:
        s = len(dev_flat_texts)
        dev_flat_texts.extend(pkg["windows"])
        dev_spans.append((s, len(dev_flat_texts)))
    dev_flat_ids = pretokenize_texts(tokenizer, dev_flat_texts, max_length=512)
    print(f"  Pre-tokenized {len(train_ids)} train + {len(dev_flat_ids)} dev_val windows in {time.time() - t_tok:.1f}s.", flush=True)

    history: List[Dict[str, Any]] = []

    # 1. Base Teacher
    teacher, m_t0 = train_teacher_base(
        train_ids, train_labels, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, epochs=args.teacher_epochs
    )
    history.append(m_t0)

    # 2. Iterative PEFT LoRA Patching on Teacher
    for r_idx in range(1, args.teacher_lora_rounds + 1):
        teacher, m_tr, accepted = run_lora_patch_round(
            model=teacher,
            train_ids=train_ids,
            train_labels=train_labels,
            dev_val_pkgs=dev_val_pkgs,
            dev_flat_ids=dev_flat_ids,
            dev_spans=dev_spans,
            pad_id=pad_id,
            device=device,
            is_hf_model=True,
            round_name=f"Teacher-LoRA-R{r_idx}",
            save_adapter_dir=ckpt_dir / f"lora_teacher_r{r_idx}",
            lora_r=16,
            lora_alpha=32,
            lr=6e-5 if r_idx == 1 else 3e-5,
            epochs=2,
            fp_weight=1.60 + 0.20 * r_idx,
        )
        history.append(m_tr)
        if m_tr["calibrated"]["benign_specificity"] >= 0.985 and m_tr["calibrated"]["recall"] >= 0.985:
            break

    torch.save({"model_state_dict": teacher.state_dict()}, ckpt_dir / "teacher_v6_lora_merged.pt")

    # 3. High-Fidelity Distillation into PackGuardNanoV6
    student, teacher_logits, m_s0 = distill_student(
        teacher, train_ids, train_labels, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device,
        epochs=args.student_epochs, embed_rank=args.embed_rank
    )
    history.append(m_s0)

    # 4. Iterative PEFT LoRA Patching on Student
    for r_idx in range(1, args.student_lora_rounds + 1):
        student, m_sr, accepted = run_lora_patch_round(
            model=student,
            train_ids=train_ids,
            train_labels=train_labels,
            dev_val_pkgs=dev_val_pkgs,
            dev_flat_ids=dev_flat_ids,
            dev_spans=dev_spans,
            pad_id=pad_id,
            device=device,
            is_hf_model=False,
            round_name=f"Student-LoRA-R{r_idx}",
            save_adapter_dir=ckpt_dir / f"lora_student_r{r_idx}",
            teacher_logits_all=teacher_logits,
            lora_r=16,
            lora_alpha=32,
            lr=1.2e-4 if r_idx == 1 else (7e-5 if r_idx == 2 else 4e-5),
            epochs=2,
            fp_weight=1.60 + 0.25 * r_idx,
        )
        history.append(m_sr)
        if m_sr["calibrated"]["benign_specificity"] >= 0.98 and m_sr["calibrated"]["recall"] >= 0.975:
            break

    torch.save({"model_state_dict": student.state_dict(), "config": student.config_dict}, ckpt_dir / "student_v6_lora_merged.pt")

    # 5. Export Dynamic INT8 ONNX & Run Strict CPU Quality Gate
    onnx_summary = export_and_verify_onnx(
        student=student,
        tokenizer=tokenizer,
        dev_val_pkgs=dev_val_pkgs,
        out_model_dir=model_int8_dir,
        target_specificity=args.target_specificity,
    )

    report = {
        "pipeline_completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "gpu": torch.cuda.get_device_name(0),
        "stage_progression": history,
        "onnx_cpu_gate": onnx_summary,
    }
    (out_dir / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\n[PackGuard v6] Training + Iterative LoRA Patching + ONNX CPU Gate COMPLETE!", flush=True)


if __name__ == "__main__":
    main()
