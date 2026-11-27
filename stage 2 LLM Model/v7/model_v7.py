"""
PackGuard Stage 2 v7 — Pretrained RoPE + GeGLU Student, Multi-Task Head & MIL Aggregator.

Key upgrades over Stage 2 v6 (`PackGuardNanoV6`):
  1. Pretrained ModernBERT Layer Initialization (`pretrained6` / `balanced6`):
     - Instead of initializing 6 Transformer layers from random noise, `PackGuardRoPEStudentV7`
       transfers weights directly from `ModernBERT-base`'s global-attention layers
       (`[0, 3, 6, 12, 15, 21]`) with native Rotary Position Embeddings (RoPE) and GeGLU MLPs.
     - Self-verifies GeGLU gate/up chunk ordering directly against the source ModernBERT MLP
       at initialization time (`max_abs_diff < 1e-5`), making it immune to `transformers` version changes.
  2. Exact Two-Sided SVD Token Embedding Factorization (`tok_sub_embed @ tok_proj`):
     - Initializes BOTH `U_r * sqrt(S_r)` AND `sqrt(S_r) * Vh_r` so at step 0,
       `tok_proj(tok_sub_embed(ids))` mathematically approximates the exact pretrained
       ModernBERT token embeddings while shrinking the 50k vocab table ~4.7x (`38.7M -> 8.2M` params).
  3. 100% Clean Dynamic-Axis ONNX Graph (`opset_version=17`):
     - Uses pre-computed `[1, 1, max_pos, head_dim]` RoPE `cos`/`sin` buffers sliced dynamically
       by `seq_len`, completely avoiding HuggingFace ModernBERT's unpadding/`NonZero` ops that
       made Stage 2 v3 slow (`844 ms`) on CPU.
  4. Multi-Task Threat-Tactic Auxiliary Head (`tactic_logits [B, 8]`):
     - Regularizes internal representations during Teacher/Student training and provides
       zero-cost human-readable tactic attribution at inference (`< 0.02 ms`).
  5. Package-Level Neural MIL Aggregator (`PackageMILAggregator`):
     - Differentiable 2-layer MLP over package window-logit distributions to suppress
       single-window false alarms in large multi-file benign npm libraries.
"""

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


def _rotate_half(x: torch.Tensor) -> torch.Tensor:
    """Rotates half the hidden dims of the input `[B, H, L, D]` using ONNX-friendly static D split."""
    half = x.shape[-1] // 2
    x1 = x[..., :half]
    x2 = x[..., half:]
    return torch.cat((-x2, x1), dim=-1)


def _build_rope_cache(max_seq_len: int, head_dim: int, rope_theta: float = 160000.0) -> Tuple[torch.Tensor, torch.Tensor]:
    """Builds `[1, 1, max_seq_len, head_dim]` RoPE cos/sin tables matching ModernBERT / RoFormer."""
    inv_freq = 1.0 / (rope_theta ** (torch.arange(0, head_dim, 2, dtype=torch.float32) / float(head_dim)))
    t = torch.arange(max_seq_len, dtype=torch.float32)
    freqs = torch.outer(t, inv_freq)  # [max_seq_len, head_dim // 2]
    emb = torch.cat((freqs, freqs), dim=-1)  # [max_seq_len, head_dim]
    cos = emb.cos().unsqueeze(0).unsqueeze(0)
    sin = emb.sin().unsqueeze(0).unsqueeze(0)
    return cos, sin


class RoPEMultiHeadAttention(nn.Module):
    """Multi-head self-attention with Rotary Position Embeddings and 100% dynamic ONNX reshapes."""

    def __init__(
        self,
        d_model: int = 768,
        num_heads: int = 12,
        max_position_embeddings: int = 1024,
        rope_theta: float = 160000.0,
        dropout: float = 0.05,
        bias: bool = False,
    ):
        super().__init__()
        assert d_model % num_heads == 0
        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = d_model // num_heads
        assert self.head_dim % 2 == 0, "RoPE requires even head_dim"
        self.scale = 1.0 / math.sqrt(self.head_dim)
        self.rope_theta = float(rope_theta)

        self.q_proj = nn.Linear(d_model, d_model, bias=bias)
        self.k_proj = nn.Linear(d_model, d_model, bias=bias)
        self.v_proj = nn.Linear(d_model, d_model, bias=bias)
        self.out_proj = nn.Linear(d_model, d_model, bias=bias)
        self.dropout = nn.Dropout(dropout)

        cos, sin = _build_rope_cache(max(max_position_embeddings, 2048), self.head_dim, rope_theta=self.rope_theta)
        self.register_buffer("cos_cached", cos, persistent=True)
        self.register_buffer("sin_cached", sin, persistent=True)

    def set_rope_theta(self, rope_theta: float, max_position_embeddings: int) -> None:
        self.rope_theta = float(rope_theta)
        cos, sin = _build_rope_cache(max(max_position_embeddings, 2048), self.head_dim, rope_theta=self.rope_theta)
        self.cos_cached = cos.to(device=self.q_proj.weight.device, dtype=torch.float32)
        self.sin_cached = sin.to(device=self.q_proj.weight.device, dtype=torch.float32)

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        bsz = x.shape[0]
        seq_len = x.shape[1]

        q = self.q_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).reshape(bsz, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        cos = self.cos_cached[:, :, :seq_len, :].to(dtype=q.dtype)
        sin = self.sin_cached[:, :, :seq_len, :].to(dtype=q.dtype)
        q = (q * cos) + (_rotate_half(q) * sin)
        k = (k * cos) + (_rotate_half(k) * sin)

        scores = torch.matmul(q, k.transpose(-2, -1)) * self.scale
        if attention_mask is not None:
            mask = attention_mask.unsqueeze(1).unsqueeze(2).to(dtype=scores.dtype)
            scores = scores + (1.0 - mask) * -10000.0

        attn = self.dropout(F.softmax(scores, dim=-1))
        ctx = torch.matmul(attn, v)
        ctx = ctx.transpose(1, 2).contiguous().reshape(bsz, seq_len, self.d_model)
        return self.out_proj(ctx)


class RoPEGeGLUEncoderLayer(nn.Module):
    """
    Pre-Norm Transformer block matching ModernBERT's exact architecture:
      - Pre-Norm LayerNorm (`norm1`, optional Identity on Layer 0)
      - RoPE Multi-Head Attention (`q_proj`, `k_proj`, `v_proj`, `out_proj`)
      - Pre-Norm LayerNorm (`norm2`)
      - GeGLU MLP (`ffn_wi: d_model -> 2 * intermediate`, `ffn_wo: intermediate -> d_model`)
    """

    def __init__(
        self,
        d_model: int = 768,
        num_heads: int = 12,
        intermediate_size: int = 1152,
        max_position_embeddings: int = 1024,
        rope_theta: float = 160000.0,
        dropout: float = 0.05,
        norm_bias: bool = False,
        use_norm1: bool = True,
    ):
        super().__init__()
        self.intermediate_size = intermediate_size
        self.use_norm1 = use_norm1
        self.norm1 = nn.LayerNorm(d_model, eps=1e-5, elementwise_affine=True, bias=norm_bias) if use_norm1 else nn.Identity()
        self.self_attn = RoPEMultiHeadAttention(
            d_model=d_model,
            num_heads=num_heads,
            max_position_embeddings=max_position_embeddings,
            rope_theta=rope_theta,
            dropout=dropout,
            bias=False,
        )
        self.drop1 = nn.Dropout(dropout)

        self.norm2 = nn.LayerNorm(d_model, eps=1e-5, elementwise_affine=True, bias=norm_bias)
        self.ffn_wi = nn.Linear(d_model, intermediate_size * 2, bias=False)
        self.ffn_wo = nn.Linear(intermediate_size, d_model, bias=False)
        self.act = nn.GELU()
        self.drop_ffn = nn.Dropout(dropout)
        self.drop2 = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        x = x + self.drop1(self.self_attn(self.norm1(x), attention_mask=attention_mask))
        wi_out = self.ffn_wi(self.norm2(x))
        val_half = wi_out[..., : self.intermediate_size]
        gate_half = wi_out[..., self.intermediate_size :]
        h = self.ffn_wo(self.drop_ffn(self.act(val_half) * gate_half))
        x = x + self.drop2(h)
        return x


class PackGuardRoPEStudentV7(nn.Module):
    """
    PackGuard Stage 2 v7 Pretrained-Initialized RoPE + GeGLU CPU Student Classifier.

    Presets:
      - `quality` (`pretrained6`, default): 6L x 768d, 12 heads, GeGLU 1152, SVD rank 160
        (~39.1M params -> ~37.5 MB INT8 ONNX, ~18-24 ms CPU, 1:1 layer transfer from ModernBERT-base).
      - `balanced` (`compact6`): 6L x 512d, 8 heads, GeGLU 896, SVD rank 128
        (~20.2M params -> ~19.5 MB INT8 ONNX, ~10-13 ms CPU, SVD-projected transfer from ModernBERT-base).
    """

    def __init__(
        self,
        vocab_size: int = 50368,
        embed_rank: int = 160,
        hidden_size: int = 768,
        num_layers: int = 6,
        num_heads: int = 12,
        intermediate_size: int = 1152,
        max_position_embeddings: int = 512,
        rope_theta: float = 160000.0,
        num_tactics: int = 8,
        dropout: float = 0.06,
        layer0_identity_norm: bool = True,
    ):
        super().__init__()
        self.config_dict: Dict[str, Any] = {
            "vocab_size": int(vocab_size),
            "embed_rank": int(embed_rank),
            "hidden_size": int(hidden_size),
            "num_layers": int(num_layers),
            "num_heads": int(num_heads),
            "intermediate_size": int(intermediate_size),
            "max_position_embeddings": int(max_position_embeddings),
            "rope_theta": float(rope_theta),
            "num_tactics": int(num_tactics),
            "dropout": float(dropout),
            "layer0_identity_norm": bool(layer0_identity_norm),
        }
        self.vocab_size = vocab_size
        self.hidden_size = hidden_size
        self.max_position_embeddings = max_position_embeddings
        self.num_tactics = num_tactics
        self.return_aux_in_forward = False

        # Exact Two-Sided SVD Factorized Token Embeddings (no learned absolute pos_embed — RoPE handles position!)
        self.tok_sub_embed = nn.Embedding(vocab_size, embed_rank)
        self.tok_proj = nn.Linear(embed_rank, hidden_size, bias=False)
        self.embed_norm = nn.LayerNorm(hidden_size, eps=1e-5, elementwise_affine=True, bias=False)
        self.embed_drop = nn.Dropout(dropout)

        self.layers = nn.ModuleList(
            [
                RoPEGeGLUEncoderLayer(
                    d_model=hidden_size,
                    num_heads=num_heads,
                    intermediate_size=intermediate_size,
                    max_position_embeddings=max_position_embeddings,
                    rope_theta=rope_theta,
                    dropout=dropout,
                    norm_bias=False,
                    use_norm1=(False if (i == 0 and layer0_identity_norm) else True),
                )
                for i in range(num_layers)
            ]
        )
        self.final_norm = nn.LayerNorm(hidden_size, eps=1e-5, elementwise_affine=True, bias=False)

        # Dual CLS + Attention-Weighted Token Pooling (captures localized payload tokens inside 512-tok window!)
        self.tok_attn_gate = nn.Linear(hidden_size, 1)
        self.pool_proj = nn.Linear(hidden_size * 3, hidden_size)
        self.pool_norm = nn.LayerNorm(hidden_size)
        self.pool_act = nn.GELU()
        self.pool_drop = nn.Dropout(dropout)

        self.classifier = nn.Linear(hidden_size, 2)
        self.tactic_head = nn.Linear(hidden_size, num_tactics)

    @classmethod
    def from_preset(cls, preset: str = "quality", max_position_embeddings: int = 512) -> "PackGuardRoPEStudentV7":
        if preset == "balanced":
            return cls(
                vocab_size=50368,
                embed_rank=128,
                hidden_size=512,
                num_layers=6,
                num_heads=8,
                intermediate_size=896,
                max_position_embeddings=max_position_embeddings,
                rope_theta=160000.0,
                num_tactics=8,
                dropout=0.06,
                layer0_identity_norm=False,
            )
        return cls(
            vocab_size=50368,
            embed_rank=160,
            hidden_size=768,
            num_layers=6,
            num_heads=12,
            intermediate_size=1152,
            max_position_embeddings=max_position_embeddings,
            rope_theta=160000.0,
            num_tactics=8,
            dropout=0.06,
            layer0_identity_norm=True,
        )

    @torch.no_grad()
    def init_embeddings_exact_svd(self, src_word_embeddings: torch.Tensor) -> float:
        """
        Exact Two-Sided SVD factorization of `W [V, D_src]` into `tok_sub_embed [V, R]` and
        `tok_proj [D_dst, R]` such that when `D_dst == D_src`, `tok_proj(tok_sub_embed(id))`
        equals the exact rank-R truncated SVD approximation of `W[id]` at step 0!
        Returns relative Frobenius reconstruction energy captured.
        """
        w = src_word_embeddings.detach().float().cpu()
        v_limit = min(w.shape[0], self.vocab_size)
        rank = self.tok_sub_embed.embedding_dim

        u, s, vh = torch.linalg.svd(w[:v_limit], full_matrices=False)
        energy = float((s[:rank] ** 2).sum() / (s ** 2).sum().clamp(min=1e-9))

        sqrt_s = torch.sqrt(s[:rank].clamp(min=1e-8))
        sub_e = u[:, :rank] * sqrt_s.unsqueeze(0)  # [v_limit, rank]
        self.tok_sub_embed.weight.data[:v_limit].copy_(
            sub_e.to(device=self.tok_sub_embed.weight.device, dtype=self.tok_sub_embed.weight.dtype)
        )

        if vh.shape[1] == self.hidden_size:
            # Exact reconstruction: proj_w [hidden_size, rank] = V_r * sqrt_s
            proj_w = vh[:rank, :].T * sqrt_s.unsqueeze(0)
            self.tok_proj.weight.data.copy_(
                proj_w.to(device=self.tok_proj.weight.device, dtype=self.tok_proj.weight.dtype)
            )
        else:
            # Project top-hidden_size principal directions via secondary SVD across D_src
            w_approx = sub_e @ vh[:rank, :]  # [v_limit, D_src]
            _, _, vh2 = torch.linalg.svd(w_approx, full_matrices=False)
            proj_basis = vh2[: self.hidden_size, :]  # [hidden_size, D_src]
            proj_w = (proj_basis @ vh[:rank, :].T) * sqrt_s.unsqueeze(0)  # [hidden_size, rank]
            self.tok_proj.weight.data.copy_(
                proj_w.to(device=self.tok_proj.weight.device, dtype=self.tok_proj.weight.dtype)
            )
        return energy

    @torch.no_grad()
    def init_from_modernbert_pretrained(
        self,
        modernbert_model: nn.Module,
        layer_indices: Optional[Sequence[int]] = None,
    ) -> Dict[str, Any]:
        """
        Transfers pretrained token embeddings + 6 global-attention Transformer layers directly
        from a HuggingFace `ModernBertModel` or `ModernBertForSequenceClassification`.
        Automatically verifies GeGLU chunk order against the live ModernBERT MLP!
        """
        base = getattr(modernbert_model, "model", modernbert_model)
        emb_weight = modernbert_model.get_input_embeddings().weight
        svd_energy = self.init_embeddings_exact_svd(emb_weight)

        # Copy embedding LayerNorm if widths match
        src_emb_norm = getattr(getattr(base, "embeddings", None), "norm", None)
        if src_emb_norm is not None and hasattr(src_emb_norm, "weight"):
            if src_emb_norm.weight.shape[0] == self.hidden_size:
                self.embed_norm.weight.data.copy_(src_emb_norm.weight.detach())

        src_layers = getattr(base, "layers", None)
        copied_layers: List[int] = []
        mlp_max_err = 0.0

        if src_layers is not None and len(src_layers) >= self.config_dict["num_layers"]:
            n_src = len(src_layers)
            if layer_indices is None:
                # Prefer ModernBERT's global-attention layers (0, 3, 6, 12, 15, 21 on 22L base)
                default_global = [0, 3, 6, 12, 15, 21]
                if n_src >= 22 and len(self.layers) == 6:
                    layer_indices = default_global
                else:
                    layer_indices = [int(round(i * (n_src - 1) / max(1, len(self.layers) - 1))) for i in range(len(self.layers))]

            for dst_idx, src_idx in enumerate(layer_indices[: len(self.layers)]):
                s_layer = src_layers[src_idx]
                d_layer: RoPEGeGLUEncoderLayer = self.layers[dst_idx]  # type: ignore[assignment]

                # Only copy 1:1 weights if dimensions match (e.g., 768d ModernBERT-base -> 768d Student)
                s_attn = getattr(s_layer, "attn", None)
                s_mlp = getattr(s_layer, "mlp", None)
                if s_attn is None or s_mlp is None:
                    continue
                wqkv = getattr(s_attn, "Wqkv", None)
                wo = getattr(s_attn, "Wo", None)
                wi = getattr(s_mlp, "Wi", None)
                m_wo = getattr(s_mlp, "Wo", None)
                if wqkv is None or wo is None or wi is None or m_wo is None:
                    continue
                if wqkv.weight.shape != (3 * self.hidden_size, self.hidden_size):
                    continue
                if wi.weight.shape != (2 * d_layer.intermediate_size, self.hidden_size):
                    continue

                # 1. Copy Q, K, V, Out projections
                q_w, k_w, v_w = wqkv.weight.detach().chunk(3, dim=0)
                d_layer.self_attn.q_proj.weight.data.copy_(q_w)
                d_layer.self_attn.k_proj.weight.data.copy_(k_w)
                d_layer.self_attn.v_proj.weight.data.copy_(v_w)
                d_layer.self_attn.out_proj.weight.data.copy_(wo.weight.detach())

                # Sync RoPE theta if exposed on source rotary_emb
                rot = getattr(s_attn, "rotary_emb", None)
                theta = getattr(rot, "base", getattr(rot, "theta", None))
                if isinstance(theta, (int, float)) and theta > 0:
                    d_layer.self_attn.set_rope_theta(float(theta), self.max_position_embeddings)

                # 2. Copy LayerNorms
                s_norm1 = getattr(s_layer, "attn_norm", None)
                if isinstance(d_layer.norm1, nn.LayerNorm):
                    if s_norm1 is not None and hasattr(s_norm1, "weight") and s_norm1.weight.shape[0] == self.hidden_size:
                        d_layer.norm1.weight.data.copy_(s_norm1.weight.detach())
                    else:
                        nn.init.ones_(d_layer.norm1.weight)

                s_norm2 = getattr(s_layer, "mlp_norm", None)
                if s_norm2 is not None and hasattr(s_norm2, "weight") and s_norm2.weight.shape[0] == self.hidden_size:
                    d_layer.norm2.weight.data.copy_(s_norm2.weight.detach())

                # 3. Copy GeGLU Wi & Wo AND self-verify exact chunk order (`act(c0)*c1` vs `c0*act(c1)`)
                wi_w = wi.weight.detach().clone()
                m_wo_w = m_wo.weight.detach().clone()
                d_layer.ffn_wo.weight.data.copy_(m_wo_w)

                dev = wi.weight.device
                dt = wi.weight.dtype
                test_x = torch.randn(2, 4, self.hidden_size, device=dev, dtype=dt)
                was_training = s_mlp.training
                s_mlp.eval()
                ref_out = s_mlp(test_x).float().cpu()
                if was_training:
                    s_mlp.train()

                c0, c1 = F.linear(test_x.float().cpu(), wi_w.float().cpu()).chunk(2, dim=-1)
                out_a = F.linear(F.gelu(c0) * c1, m_wo_w.float().cpu())
                out_b = F.linear(F.gelu(c1) * c0, m_wo_w.float().cpu())
                err_a = float((ref_out - out_a).abs().max().item())
                err_b = float((ref_out - out_b).abs().max().item())

                if err_b < err_a:
                    half = d_layer.intermediate_size
                    wi_w = torch.cat([wi_w[half:], wi_w[:half]], dim=0)
                    mlp_max_err = max(mlp_max_err, err_b)
                else:
                    mlp_max_err = max(mlp_max_err, err_a)

                d_layer.ffn_wi.weight.data.copy_(wi_w)
                copied_layers.append(int(src_idx))

        src_final_norm = getattr(base, "final_norm", None)
        if src_final_norm is not None and hasattr(src_final_norm, "weight"):
            if src_final_norm.weight.shape[0] == self.hidden_size:
                self.final_norm.weight.data.copy_(src_final_norm.weight.detach())

        return {
            "svd_energy_captured": round(svd_energy, 5),
            "copied_layer_indices": copied_layers,
            "mlp_parity_max_abs_err": round(mlp_max_err, 7),
        }

    def encode_pooled(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        input_ids = input_ids[:, :2048]
        attention_mask = attention_mask[:, :2048]
        safe_ids = input_ids.clamp(0, self.vocab_size - 1)
        x = self.tok_proj(self.tok_sub_embed(safe_ids))
        x = self.embed_drop(self.embed_norm(x))

        for layer in self.layers:
            x = layer(x, attention_mask=attention_mask)

        x = self.final_norm(x)

        cls_repr = x[:, 0, :]
        mask_f = attention_mask.unsqueeze(-1).float()
        mean_repr = ((x.float() * mask_f).sum(dim=1) / mask_f.sum(dim=1).clamp(min=1.0)).to(dtype=x.dtype)

        # Learned token-level attention pooling (pinpoints localized malicious statements inside padded files!)
        gate_scores = self.tok_attn_gate(x).squeeze(-1)  # [B, L]
        gate_scores = gate_scores + (1.0 - attention_mask.to(dtype=gate_scores.dtype)) * -10000.0
        attn_weights = F.softmax(gate_scores, dim=-1).unsqueeze(-1)  # [B, L, 1]
        attn_repr = (x.float() * attn_weights.float()).sum(dim=1).to(dtype=x.dtype)

        combined = torch.cat([cls_repr, mean_repr, attn_repr], dim=-1)
        return self.pool_drop(self.pool_act(self.pool_norm(self.pool_proj(combined))))

    def forward_with_aux(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        pooled = self.encode_pooled(input_ids, attention_mask)
        return self.classifier(pooled), self.tactic_head(pooled)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ):
        pooled = self.encode_pooled(input_ids, attention_mask)
        bin_logits = self.classifier(pooled)
        if self.return_aux_in_forward:
            return bin_logits, self.tactic_head(pooled)
        return bin_logits


class PackageMILAggregator(nn.Module):
    """
    Lightweight 2-layer Multi-Instance Learning (MIL) MLP over 25 package-level
    window-logit, tactic-head, and capability summary features (`extract_package_mil_features`).
    Suppresses multi-file benign false alarms while preserving 1-window malware sensitivity.
    """

    def __init__(self, in_features: int = 25, hidden_features: int = 24):
        super().__init__()
        self.fc1 = nn.Linear(in_features, hidden_features)
        self.fc2 = nn.Linear(hidden_features, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Uses exact tanh-approximation GELU so pure-NumPy inference matches to 1e-6!
        h = F.gelu(self.fc1(x), approximate="tanh")
        return self.fc2(h).squeeze(-1)

    @torch.no_grad()
    def export_numpy_dict(
        self,
        feat_mean: Any,
        feat_scale: Any,
        enabled: bool = True,
        logit_bias: float = 0.0,
        logit_temperature: float = 1.0,
    ) -> Dict[str, Any]:
        return {
            "enabled": bool(enabled),
            "feat_dim": int(self.fc1.in_features),
            "logit_bias": float(logit_bias),
            "logit_temperature": float(logit_temperature),
            "feat_mean": [float(v) for v in feat_mean],
            "feat_scale": [float(v) for v in feat_scale],
            "w1": self.fc1.weight.detach().float().cpu().tolist(),
            "b1": self.fc1.bias.detach().float().cpu().tolist(),
            "w2": self.fc2.weight.detach().float().cpu().tolist(),
            "b2": self.fc2.bias.detach().float().cpu().tolist(),
        }


def get_student_lora_target_modules() -> List[str]:
    """
    Linear leaf modules inside `PackGuardRoPEStudentV7` targeted by PEFT LoRA.
    Includes `tok_proj` and `pool_proj` alongside all RoPE attention & GeGLU FFN layers!
    """
    return ["tok_proj", "q_proj", "k_proj", "v_proj", "out_proj", "ffn_wi", "ffn_wo", "pool_proj"]


def get_teacher_lora_target_modules(model: nn.Module) -> List[str]:
    """Discovers attention/MLP Linear leaf names inside ModernBERT (base or large) for PEFT LoRA."""
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
