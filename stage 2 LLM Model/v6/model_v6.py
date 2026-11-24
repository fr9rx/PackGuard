"""
PackGuard Stage 2 v6 — Neural Model Architectures (Teacher + Nano-v6 Student).

Features:
  - Teacher: ModernBERT-base (22L, 768d, 149.6M params) with native PEFT LoRA support.
  - Student: PackGuardNanoV6 (6 Pre-Norm Transformer layers, 384d, nhead=6, ffn=1024,
    Rank-128 SVD factorized vocabulary embeddings initialized from Teacher, max_pos=512).
  - Dynamic Attention Tracing (arbitrary batch_size and seq_len 1..512, zero static reshapes).
  - PEFT LoRA compatibility on BOTH Teacher and Student for iterative error-patching loops,
    followed by clean merge_and_unload() prior to ONNX INT8 export.
  - Clean binary classification output (`binary_logits` shape [B, 2]) verified directly
    with the real ModernBERT BPE tokenizer (never hashed tokens).
"""

import math
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class DynamicMultiHeadSelfAttention(nn.Module):
    """Multi-head self-attention with fully dynamic ONNX-traceable reshapes."""

    def __init__(self, d_model: int = 384, num_heads: int = 6, dropout: float = 0.1):
        super().__init__()
        assert d_model % num_heads == 0
        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = d_model // num_heads
        self.scale = 1.0 / math.sqrt(self.head_dim)

        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        bsz = x.shape[0]
        seq_len = x.shape[1]

        q = self.q_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        scores = torch.matmul(q, k.transpose(-2, -1)) * self.scale
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(1).unsqueeze(2).to(dtype=scores.dtype)
            scores = scores + (1.0 - mask) * -10000.0

        attn = self.dropout(F.softmax(scores, dim=-1))
        ctx = torch.matmul(attn, v)
        ctx = ctx.transpose(1, 2).contiguous().reshape(bsz, seq_len, self.d_model)
        return self.out_proj(ctx)


class PreNormEncoderLayer(nn.Module):
    """Pre-Norm Transformer encoder block with separate q/k/v/out/ffn Linear layers for PEFT LoRA."""

    def __init__(
        self,
        d_model: int = 384,
        num_heads: int = 6,
        dim_feedforward: int = 1024,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.norm1 = nn.LayerNorm(d_model)
        self.self_attn = DynamicMultiHeadSelfAttention(d_model, num_heads, dropout)
        self.drop1 = nn.Dropout(dropout)

        self.norm2 = nn.LayerNorm(d_model)
        self.ffn_in = nn.Linear(d_model, dim_feedforward)
        self.ffn_out = nn.Linear(dim_feedforward, d_model)
        self.act = nn.GELU()
        self.drop_ffn = nn.Dropout(dropout)
        self.drop2 = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        x = x + self.drop1(self.self_attn(self.norm1(x), attention_mask=attention_mask))
        h = self.ffn_out(self.drop_ffn(self.act(self.ffn_in(self.norm2(x)))))
        x = x + self.drop2(h)
        return x


class PackGuardNanoV6(nn.Module):
    """
    PackGuard Stage 2 v6 Compact CPU-Only Neural Classifier (~15.2M params, ~16 MB INT8 ONNX).
    Designed for fast dynamic-length CPU ONNX inference with the real ModernBERT BPE tokenizer
    and full PEFT LoRA patching compatibility.
    """

    def __init__(
        self,
        vocab_size: int = 50368,
        embed_rank: int = 128,
        hidden_size: int = 384,
        num_layers: int = 6,
        num_heads: int = 6,
        intermediate_size: int = 1024,
        max_position_embeddings: int = 512,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.config_dict: Dict[str, int] = {
            "vocab_size": vocab_size,
            "embed_rank": embed_rank,
            "hidden_size": hidden_size,
            "num_layers": num_layers,
            "num_heads": num_heads,
            "intermediate_size": intermediate_size,
            "max_position_embeddings": max_position_embeddings,
        }
        self.vocab_size = vocab_size
        self.max_position_embeddings = max_position_embeddings

        self.tok_sub_embed = nn.Embedding(vocab_size, embed_rank)
        self.tok_proj = nn.Linear(embed_rank, hidden_size, bias=False)
        self.pos_embed = nn.Embedding(max_position_embeddings, hidden_size)
        self.embed_norm = nn.LayerNorm(hidden_size)
        self.embed_drop = nn.Dropout(dropout)

        self.layers = nn.ModuleList(
            [
                PreNormEncoderLayer(
                    d_model=hidden_size,
                    num_heads=num_heads,
                    dim_feedforward=intermediate_size,
                    dropout=dropout,
                )
                for _ in range(num_layers)
            ]
        )
        self.final_norm = nn.LayerNorm(hidden_size)

        self.pool_proj = nn.Linear(hidden_size * 2, hidden_size)
        self.pool_norm = nn.LayerNorm(hidden_size)
        self.pool_act = nn.GELU()
        self.pool_drop = nn.Dropout(dropout)
        self.classifier = nn.Linear(hidden_size, 2)

    @torch.no_grad()
    def init_embeddings_from_teacher_svd(self, teacher_word_embeddings: torch.Tensor) -> None:
        """Initializes [V, R] and [R, H] factorized token embeddings from Teacher ModernBERT via SVD."""
        w = teacher_word_embeddings.detach().float().cpu()
        v_limit = min(w.shape[0], self.vocab_size)
        rank = self.tok_sub_embed.embedding_dim

        u, s, vh = torch.linalg.svd(w[:v_limit], full_matrices=False)
        u_r = u[:, :rank]
        s_r = torch.sqrt(s[:rank].clamp(min=1e-8))
        sub_e = u_r * s_r.unsqueeze(0)
        self.tok_sub_embed.weight.data[:v_limit].copy_(
            sub_e.to(device=self.tok_sub_embed.weight.device, dtype=self.tok_sub_embed.weight.dtype)
        )
        nn.init.orthogonal_(self.tok_proj.weight)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        bsz = input_ids.shape[0]
        seq_len = input_ids.shape[1]

        safe_ids = input_ids.clamp(0, self.vocab_size - 1)
        pos_ids = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(bsz, seq_len)
        pos_ids = pos_ids.clamp(max=self.max_position_embeddings - 1)

        x = self.tok_proj(self.tok_sub_embed(safe_ids)) + self.pos_embed(pos_ids)
        x = self.embed_drop(self.embed_norm(x))

        for layer in self.layers:
            x = layer(x, attention_mask=attention_mask)

        x = self.final_norm(x)

        cls_repr = x[:, 0, :]
        mask_f = attention_mask.unsqueeze(-1).to(dtype=x.dtype)
        mean_repr = (x * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1e-6)
        combined = torch.cat([cls_repr, mean_repr], dim=-1)
        pooled = self.pool_drop(self.pool_act(self.pool_norm(self.pool_proj(combined))))
        return self.classifier(pooled)


def get_student_lora_target_modules() -> List[str]:
    """Returns Linear module leaf names inside PackGuardNanoV6 suitable for PEFT LoRA."""
    return ["q_proj", "k_proj", "v_proj", "out_proj", "ffn_in", "ffn_out", "pool_proj"]


def get_teacher_lora_target_modules(model: nn.Module) -> List[str]:
    """Discovers attention/MLP Linear leaf names inside ModernBERT for PEFT LoRA."""
    preferred = ["Wqkv", "Wo", "Wi", "q_proj", "k_proj", "v_proj", "out_proj", "dense"]
    found = set()
    for name, module in model.named_modules():
        if isinstance(module, nn.Linear):
            leaf = name.rsplit(".", 1)[-1]
            if leaf in preferred and "classifier" not in name:
                found.add(leaf)
    if not found:
        raise RuntimeError("Could not find any Linear projection modules for LoRA in Teacher model.")
    return sorted(found)


def count_parameters(model: nn.Module) -> Tuple[int, int]:
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return total, trainable
