#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PalmTree(로컬 ep19 + vocab)로 instruction JSONL → embedding JSONL
- 여러 입력 폴더 재귀 처리
- 같은 함수 이름(base_key)이라도 내용(content_hash)이 같으면 스킵, 다르면 추가 저장
- 재실행(resume) 지원: (base_key, content_hash) 존재 시 건너뜀

입력(JSONL; 한 줄당):
  {"func_id": "xxx::0x401000", "instrs": ["mov eax, ecx", "add eax, 1", ...]}

출력(JSONL; 한 줄당, append):
  {
    "key": "<rel_input_path>::<func_id>",       # base_key
    "content_hash": "<sha256_16>",              # 정규화된 instrs 기준
    "source": "<rel_input_path>",
    "func_id": "<func_id>",
    "instr_count": 123,
    "model": "palmtree-local:<ckpt_name>",
    "dim": <D>,
    "vector": [ ... D floats ... ]
  }
"""

import os, sys, json, argparse, re, hashlib, random
from pathlib import Path
from typing import List, Dict, Any, Iterable, Tuple, Set
from tqdm import tqdm
import numpy as np

# (추가) 파이토치 결정성 세팅
try:
    import torch
except Exception:
    torch = None

def make_deterministic(seed: int = 0):
    """PyTorch/NumPy/Random 결정성 세팅."""
    try:
        random.seed(seed)
        np.random.seed(seed)
        if torch is not None:
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
            try:
                torch.use_deterministic_algorithms(True)
            except Exception:
                pass
            try:
                import torch.backends.cudnn as cudnn
                cudnn.benchmark = False
                cudnn.deterministic = True
            except Exception:
                pass
        # cuBLAS 결정성 (GPU 사용 시)
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":16:8")
    except Exception:
        # 결정성 옵션이 일부 환경에서 제한될 수 있으므로 조용히 통과
        pass

# ------------------ IO 유틸 ------------------
def read_jsonl_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def append_jsonl(path: Path, obj: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def load_existing_pairs(out_path: Path) -> Set[Tuple[str, str]]:
    """
    이미 저장된 (base_key, content_hash) 쌍을 수집하여 resume 용도로 사용
    """
    pairs: Set[Tuple[str, str]] = set()
    if out_path.exists():
        for rec in read_jsonl_lines(out_path):
            k = rec.get("key")
            h = rec.get("content_hash")
            if k and h:
                pairs.add((k, h))
    return pairs

# ------------------ 전처리/해시 ------------------
def normalize_instrs(instrs: List[str]) -> str:
    """
    PalmTree encode()가 기대하는 공백 구분 텍스트로 정규화.
    콤마/탭 제거, 다중 공백 축소, 라인 합치기.
    """
    toks = []
    for s in instrs:
        s = re.sub(r"[,\t]+", " ", str(s))
        s = " ".join(s.split())
        if s:
            toks.append(s)
    return " ".join(toks)

def content_hash_from_text(text: str) -> str:
    # 너무 길 필요는 없으니 16자 prefix만 사용
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

# ------------------ 메인 ------------------
def main():
    ap = argparse.ArgumentParser(description="PalmTree(local) embeddings extractor with content-aware resume")
    ap.add_argument("--repo_dir", required=True, help="palmtree 소스 폴더(여기에 eval_utils.py, vocab.py, config.py 등)")
    ap.add_argument("--model_path", required=True, help="체크포인트 파일 경로 (예: .../transformer.ep19)")
    ap.add_argument("--vocab_path", required=True, help="vocab 피클 경로 (예: .../vocab)")
    ap.add_argument("--inp_dir", required=True, help="instruction JSONL 루트 디렉터리 (예: json_data)")
    ap.add_argument("--out_jsonl", required=True, help="결과 embeddings JSONL (append; content_hash 기준 resume)")
    ap.add_argument("--glob", default="**/*.jsonl", help="입력 파일 패턴 (기본 **/*.jsonl)")
    ap.add_argument("--batch_size", type=int, default=32, help="encode 배치 크기")
    args = ap.parse_args()

    # (추가) 결정성 고정
    make_deterministic(0)

    repo_dir = Path(args.repo_dir).resolve()
    model_path = Path(args.model_path).resolve()
    vocab_path = Path(args.vocab_path).resolve()
    inp_dir = Path(args.inp_dir).resolve()
    out_jsonl = Path(args.out_jsonl).resolve()

    assert repo_dir.exists(), f"repo_dir not found: {repo_dir}"
    assert model_path.exists(), f"model_path not found: {model_path}"
    assert vocab_path.exists(), f"vocab_path not found: {vocab_path}"
    assert inp_dir.exists(), f"inp_dir not found: {inp_dir}"

    # 로컬 palmtree 모듈 import
    if str(repo_dir) not in sys.path:
        sys.path.insert(0, str(repo_dir))

    from eval_utils import UsableTransformer
    print(f"[i] Loading model…\n  model={model_path}\n  vocab={vocab_path}")
    pt = UsableTransformer(model_path=str(model_path), vocab_path=str(vocab_path))
    model_tag = f"palmtree-local:{model_path.name}"

    # 기존 (base_key, content_hash) 쌍 로드 → resume
    existing = load_existing_pairs(out_jsonl)
    print(f"[i] existing pairs: {len(existing)}")

    # 입력 파일 수집
    files = sorted(inp_dir.glob(args.glob))
    if not files:
        print(f"[!] no input files: {inp_dir} / pattern={args.glob}")
        return

    # Pre-scan: 파일별 함수 개수 집계 및 출력 + 전체 합계 계산
    file_func_counts: Dict[Path, int] = {}
    total_funcs = 0
    print(f"[i] input files: {len(files)}")
    for fp in files:
        try:
            cnt = 0
            for rec in read_jsonl_lines(fp):
                func_id = rec.get("func_id")
                instrs = rec.get("instrs", [])
                if func_id and isinstance(instrs, list) and len(instrs) > 0:
                    cnt += 1
            file_func_counts[fp] = cnt
            total_funcs += cnt
            print(f"  - {fp.name}: {cnt} functions")
        except Exception as e:
            file_func_counts[fp] = 0
            print(f"  - {fp.name}: (error: {e})")
    print(f"[i] total functions (estimated): {total_funcs}")

    pbar_total = total_funcs if total_funcs > 0 else None
    pbar = tqdm(total=pbar_total, desc="PalmTree embed", unit="func")

    dim_cache: int = -1

    for fp in files:
        rel = fp.relative_to(inp_dir).as_posix()  # key 안정성 위해 / 사용
        buf_texts: List[str] = []
        buf_meta: List[Dict[str, Any]] = []

        def flush():
            nonlocal buf_texts, buf_meta, dim_cache
            if not buf_texts:
                return
            embs = pt.encode(buf_texts)
            embs = np.asarray(embs)
            if dim_cache < 0:
                dim_cache = int(embs.shape[1])
            for i, meta in enumerate(buf_meta):
                append_jsonl(out_jsonl, {
                    "key": meta["key"],
                    "content_hash": meta["content_hash"],
                    "source": meta["source"],
                    "func_id": meta["func_id"],
                    "instr_count": meta["instr_count"],
                    "model": model_tag,
                    "dim": dim_cache,
                    "vector": embs[i].tolist()
                })
            buf_texts.clear()
            buf_meta.clear()

        for rec in read_jsonl_lines(fp):
            func_id = rec.get("func_id")
            instrs = rec.get("instrs", [])
            if not func_id or not isinstance(instrs, list) or not instrs:
                pbar.update(1); continue

            base_key = f"{rel}::{func_id}"

            text = normalize_instrs(instrs)
            if not text:
                pbar.update(1); continue
            h = content_hash_from_text(text)

            pair = (base_key, h)
            if pair in existing:
                pbar.update(1); continue

            buf_texts.append(text)
            buf_meta.append({
                "key": base_key,
                "content_hash": h,
                "source": rel,
                "func_id": func_id,
                "instr_count": len(instrs),
            })

            if len(buf_texts) >= args.batch_size:
                flush()

            pbar.update(1)

        flush()

    pbar.close()
    print(f"[✓] done -> {out_jsonl}")
    print(" - 같은 이름의 함수라도 내용이 같으면 스킵, 다르면 추가로 저장합니다.")
    print(" - 재실행 시 (key, content_hash) 기준으로 자동 resume 됩니다.")

if __name__ == "__main__":
    main()
