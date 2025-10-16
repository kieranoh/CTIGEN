#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, sqlite3, argparse
from pathlib import Path
from typing import Iterable, Dict, Any, Tuple, List
import numpy as np
from tqdm import tqdm
import faiss

# ===============================
# 공통 유틸
# ===============================

def read_jsonl(p: Path) -> Iterable[Dict[str, Any]]:
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def _ensure_column(conn: sqlite3.Connection, table: str, col: str, decl: str):
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table});").fetchall()}
    if col not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl};")
        conn.commit()

def ensure_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
    CREATE TABLE IF NOT EXISTS embeddings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        dim INTEGER NOT NULL,
        vec_f16 BLOB,
        vec_f32 BLOB,
        UNIQUE(key, content_hash)
    );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_key ON embeddings(key);")
    _ensure_column(conn, "embeddings", "vec_f16", "BLOB")
    _ensure_column(conn, "embeddings", "vec_f32", "BLOB")
    conn.commit()
    return conn

def benign_count_dim(conn) -> Tuple[int,int]:
    row = conn.execute("SELECT COUNT(*), MAX(dim) FROM embeddings").fetchone()
    return int(row[0] or 0), int(row[1] or 0)

def load_benign_from_db(conn) -> Tuple[np.ndarray, List[str], int]:
    cur = conn.cursor()
    cols = {r[1] for r in cur.execute("PRAGMA table_info(embeddings);").fetchall()}
    use_f32 = "vec_f32" in cols
    use_f16 = "vec_f16" in cols
    use_vec = "vec" in cols  

    if not (use_f32 or use_f16 or use_vec):
        raise RuntimeError("embeddings 테이블에 vec_f32/vec_f16/vec 컬럼이 없습니다.")

    # vec_f32가 있으면 그걸 우선 사용
    sel_col = "vec_f32" if use_f32 else ("vec_f16" if use_f16 else "vec")
    rows = cur.execute(f"SELECT key, dim, {sel_col} FROM embeddings").fetchall()
    if not rows:
        raise RuntimeError("DB에 benign 임베딩이 없습니다. 먼저 적재하세요.")

    keys, vecs = [], []
    dim = rows[0][1]
    for k, d, blob in rows:
        if d != dim:
            continue
        if sel_col == "vec_f32":
            arr = np.frombuffer(blob, dtype=np.float32, count=dim)
        elif sel_col == "vec_f16":
            arr = np.frombuffer(blob, dtype=np.float16, count=dim).astype(np.float32)
        else:  # legacy vec(float32)
            arr = np.frombuffer(blob, dtype=np.float32, count=dim)
        keys.append(k)
        vecs.append(arr)
    X = np.stack(vecs).astype(np.float32)  # (N,D)
    return X, keys, dim

def l2_normalize_np(X: np.ndarray, eps: float = 1e-12) -> np.ndarray:
    return X / (np.linalg.norm(X, axis=1, keepdims=True) + eps)

def _gpu_available() -> bool:
    try:
        return hasattr(faiss, "StandardGpuResources") and faiss.get_num_gpus() > 0
    except Exception:
        return False

def set_cpu_threads(n: int):
    """FAISS OMP뿐 아니라 BLAS 라이브러리도 제한(공용 서버 CPU 과점유 방지)."""
    if n and n > 0:
        faiss.omp_set_num_threads(int(n))
        os.environ["OMP_NUM_THREADS"] = str(n)
        os.environ["OPENBLAS_NUM_THREADS"] = str(n)
        os.environ["MKL_NUM_THREADS"] = str(n)
        os.environ["NUMEXPR_NUM_THREADS"] = str(n)
        print(f"[i] OMP/BLAS threads = {n}")

def build_faiss_index(
    Xn: np.ndarray,
    nlist: int = 100,
    nprobe: int = 10,
    *,
    use_gpu: bool = False,
    gpu_id: int = 0,
    gpu_fp16: bool = True,
    add_bs: int = 200_000,
    train_max: int = 500_000,
) -> faiss.Index:
    """
    Xn: (N,D) float32, L2-normalized
    - use_gpu=True면 GPU 시도(가용하지 않으면 자동 CPU 폴백)
    - 데이터가 적으면 IVF 대신 Flat(IP) 자동 전환
    - add_bs: 대용량 추가 타일 크기
    - train_max: IVF 학습 최대 샘플 수 (<=0이면 전수 사용 = 무제한)
    """
    N, D = Xn.shape
    need_flat = (N < max(1, nlist * 40))  # 샘플 적으면 IVF 대신 Flat

    def pick_train_set(arr: np.ndarray) -> np.ndarray:
        if train_max is not None and train_max > 0 and arr.shape[0] > train_max:
            rng = np.random.default_rng(1234)
            idx = rng.choice(arr.shape[0], size=train_max, replace=False)
            print(f"[i] IVF train: 샘플 {idx.size}/{arr.shape[0]}")
            return arr[idx]
        return arr

    # ---- GPU 경로 ----
    if use_gpu and _gpu_available():
        res = faiss.StandardGpuResources()
        try:
            res.setTempMemory(512 * 1024 * 1024)
        except Exception:
            pass

        if need_flat:
            print("[i] FAISS GPU Flat(IP) index")
            cfg = faiss.GpuIndexFlatConfig()
            cfg.device = gpu_id
            index = faiss.GpuIndexFlatIP(res, D, cfg)
            for i in tqdm(range(0, N, add_bs), desc="FAISS add(Flat,GPU)", unit="vec", mininterval=0.5):
                index.add(Xn[i:i+add_bs])
            return index

        print("[i] FAISS GPU IVF Flat index (cosine)")
        train_X = pick_train_set(Xn)
        quant = faiss.IndexFlatIP(D)
        cpu_ivf = faiss.IndexIVFFlat(quant, D, nlist, faiss.METRIC_INNER_PRODUCT)
        cpu_ivf.train(train_X)

        co = faiss.GpuClonerOptions()
        co.useFloat16 = bool(gpu_fp16)
        index = faiss.index_cpu_to_gpu(res, gpu_id, cpu_ivf, co)
        for i in tqdm(range(0, N, add_bs), desc="FAISS add(IVF,GPU)", unit="vec", mininterval=0.5):
            index.add(Xn[i:i+add_bs])
        index.nprobe = nprobe
        return index

    # ---- CPU 경로 ----
    if need_flat:
        print("[i] FAISS CPU Flat(IP) index")
        index = faiss.IndexFlatIP(D)
        for i in tqdm(range(0, N, add_bs), desc="FAISS add(Flat,CPU)", unit="vec", mininterval=0.5):
            index.add(Xn[i:i+add_bs])
        return index

    print("[i] FAISS CPU IVF Flat index (cosine)")
    quant = faiss.IndexFlatIP(D)
    index = faiss.IndexIVFFlat(quant, D, nlist, faiss.METRIC_INNER_PRODUCT)
    train_X = pick_train_set(Xn)
    index.train(train_X)
    for i in tqdm(range(0, N, add_bs), desc="FAISS add(IVF,CPU)", unit="vec", mininterval=0.5):
        index.add(Xn[i:i+add_bs])
    index.nprobe = nprobe
    return index

# ===============================
# de-dup(정규화 후 라운딩 키) 유틸
# ===============================

def dedup_by_rounding(X: np.ndarray, decimals: int) -> np.ndarray:
    """
    L2 정규화 후 소수점 'decimals' 자리로 반올림하여 동일 행을 1개만 남김.
    반환: 고유 행의 인덱스 배열
    """
    if decimals <= 0 or X.shape[0] == 0:
        return np.arange(X.shape[0])
    Xn = l2_normalize_np(X.astype(np.float32))
    R = np.round(Xn, decimals=decimals)
    # numpy>=1.24 axis 지원: 같은 행(unique) 추출
    uniq, idx = np.unique(R, axis=0, return_index=True)
    idx.sort()
    return idx

# ===============================
# 1) ingest : JSONL → SQLite (append)
# ===============================

def cmd_ingest(args):
    conn = ensure_db(Path(args.db))
    inp_dir = Path(args.inp_dir).resolve()
    files = sorted(inp_dir.glob(args.glob))
    if not files:
        print(f"[!] 입력 JSONL 없음: {inp_dir} / {args.glob}")
        return

    # 대략 진행률 계산
    total = 0
    for fp in files:
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in f:
                total += 1

    added = 0
    with conn:
        pbar = tqdm(total=total, desc="Ingest", unit="rec")
        for fp in files:
            for rec in read_jsonl(fp):
                key = rec.get("key")
                h   = rec.get("content_hash") or ""
                dim = rec.get("dim")
                vec = rec.get("vector")
                if not key or vec is None or dim is None:
                    pbar.update(1); continue
                arr32 = np.asarray(vec, dtype=np.float32)
                arr16 = arr32.astype(np.float16)

                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO embeddings(key, content_hash, dim, vec_f16, vec_f32) VALUES (?,?,?,?,?)",
                        (key, h, int(dim), arr16.tobytes(), arr32.tobytes())
                    )
                    added += 1
                except Exception:
                    pass
                pbar.update(1)
        pbar.close()
    print(f"[✓] Ingest 완료: +{added} rows → {args.db}")

# ===============================
# 2) detect : benign self kNN 분포 CSV 덤프
# ===============================

def cmd_detect(args):
    set_cpu_threads(args.omp_threads)

    conn = ensure_db(Path(args.db))
    X, _, dim = load_benign_from_db(conn)
    N = X.shape[0]
    print(f"[i] benign: N={N}, dim={dim}")

    if args.self_max and args.self_max < N:
        rng = np.random.default_rng(42)
        idx = rng.choice(N, size=args.self_max, replace=False)
        X = X[idx]; N = X.shape[0]
        print(f"[i] self_max 적용: {N}")

    # (옵션) de-dup으로 중복 줄이기 (threshold 분포 안정화)
    if args.dedup_round and args.dedup_round > 0:
        keep_idx = dedup_by_rounding(X, decimals=int(args.dedup_round))
        if keep_idx.size < X.shape[0]:
            print(f"[i] de-dup(threshold): {X.shape[0]} → {keep_idx.size} (round={args.dedup_round})")
            X = X[keep_idx]

    Xn = l2_normalize_np(X.astype(np.float32))
    print("[i] FAISS index build (CPU/GPU)")
    index = build_faiss_index(
        Xn, nlist=args.nlist, nprobe=args.nprobe,
        use_gpu=args.use_gpu, gpu_id=args.gpu_id, gpu_fp16=bool(args.gpu_fp16),
        add_bs=args.faiss_add_bs, train_max=args.faiss_train_max
    )

    # kNN search (자기자신 제외)
    print("[i] kNN search (자기자신 제외)")
    scores_list = []
    bs = max(1, args.batch)
    for i in tqdm(range(0, N, bs), desc="Detect", unit="batch", mininterval=0.5):
        j = min(i + bs, N)
        D, _ = index.search(Xn[i:j], min(args.k + 1, N))
        # 수치 안정화: [-1, 1]로 잘라줌
        np.clip(D, -1.0, 1.0, out=D)
        kk = min(args.k + 1, D.shape[1])
        if kk <= 1:
            part = np.zeros((j - i,), dtype=np.float32)
        else:
            part = 1.0 - D[:, 1:kk].mean(axis=1)
        scores_list.append(part)
    scores = np.concatenate(scores_list, axis=0)

    out_csv = Path(args.out_csv); out_csv.parent.mkdir(parents=True, exist_ok=True)
    np.savetxt(out_csv, scores, delimiter=",")
    print(f"[✓] Detect 완료 → {out_csv}")

    # ---- 여러 percentile 처리 ----
    q_list = []
    if args.p_range:
        try:
            s, e, st = args.p_range.split(":")
            s, e, st = float(s), float(e), float(st)
            q_list = list(np.around(np.arange(s, e + 1e-9, st), 6))
        except Exception:
            print("[!] --p_range 파싱 실패. 형식: START:END:STEP (예: 55:65:0.1)")

    if args.percentile is not None:
        q_list = sorted(set(q_list + [float(args.percentile)]))

    if q_list:
        thrs = np.percentile(scores, q_list)
        thr_csv = out_csv.with_suffix(".thresholds.csv")
        with thr_csv.open("w", encoding="utf-8") as f:
            f.write("percentile,threshold\n")
            for p, v in zip(q_list, thrs):
                f.write(f"{p:.2f},{v:.12e}\n")
                print(f"[i] {p:.2f}% threshold = {v:.12e}")
        print(f"[✓] Percentile thresholds 저장 → {thr_csv}")

# ===============================
# 3) filter_targets : benign과 유사한 것만 남기기
# ===============================

def cmd_filter_targets(args):
    """
    - threshold 미지정: threshold = percentile( benign-self(kNN), p=--percentile )
        * threshold 계산은 항상 '전수 benign' (또는 self_max 샘플) 기준 인덱스에서 수행
        * ref_max는 threshold 계산에 전혀 영향 X
    - threshold 지정: 해당 값 사용 (threshold 계산 스킵)
    이후 target 판정은 ref_max로 줄인 benign 집합 인덱스를 사용.
    """
    set_cpu_threads(args.omp_threads)

    conn = ensure_db(Path(args.db))
    X_full, bn_keys_full, dim = load_benign_from_db(conn)
    N_full = X_full.shape[0]
    print(f"[i] benign: N={N_full}, dim={dim}")
    print(f"[i] K={args.k}")
    bs = max(1, args.batch)

    # ---- 1) threshold ----
    if args.threshold is not None:
        thresh = float(args.threshold)
        print(f"[i] 고정 threshold 사용 = {thresh:.12e}")
    else:
        if args.self_max and args.self_max < N_full:
            rng = np.random.default_rng(42)
            idx_thr = rng.choice(N_full, size=args.self_max, replace=False)
            X_thr = X_full[idx_thr]
            print(f"[i] self_max(threshold) 적용: {X_thr.shape[0]}")
        else:
            X_thr = X_full  # 전수

        # (옵션) threshold 계산용 de-dup
        if args.dedup_round and args.dedup_round > 0:
            keep_idx = dedup_by_rounding(X_thr, decimals=int(args.dedup_round))
            if keep_idx.size < X_thr.shape[0]:
                print(f"[i] de-dup(threshold): {X_thr.shape[0]} → {keep_idx.size} (round={args.dedup_round})")
                X_thr = X_thr[keep_idx]

        print("[i] (threshold) 인덱스 빌드 (full benign, CPU/GPU)")
        Xn_full = l2_normalize_np(X_full.astype(np.float32))
        index_thr = build_faiss_index(
            Xn_full, nlist=args.nlist, nprobe=args.nprobe,
            use_gpu=args.use_gpu, gpu_id=args.gpu_id, gpu_fp16=bool(args.gpu_fp16),
            add_bs=args.faiss_add_bs, train_max=args.faiss_train_max
        )

        print("[i] threshold 계산(kNN of benign self, full index)")
        Xn_thr = l2_normalize_np(X_thr.astype(np.float32))
        thr_scores = []
        for i in tqdm(range(0, Xn_thr.shape[0], bs), desc="Benign self", unit="batch", mininterval=0.5):
            j = min(i + bs, Xn_thr.shape[0])
            D, _ = index_thr.search(Xn_thr[i:j], min(args.k + 1, N_full))
            np.clip(D, -1.0, 1.0, out=D)  # 수치 안정화
            kk = min(args.k + 1, D.shape[1])
            if kk <= 1:
                part = np.zeros((j - i,), dtype=np.float32)
            else:
                part = 1.0 - D[:, 1:kk].mean(axis=1)
            thr_scores.append(part)
        thr_scores = np.concatenate(thr_scores, axis=0)
        thresh = float(np.percentile(thr_scores, args.percentile))
        print(f"[i] threshold = {thresh:.12e} (percentile={args.percentile})")

        del index_thr, Xn_full, Xn_thr, thr_scores

    # ---- 2) ref 인덱스 ----
    X_ref, bn_keys_ref = X_full, bn_keys_full
    if args.ref_max and args.ref_max < N_full:
        rng = np.random.default_rng(43)
        idx_ref = rng.choice(N_full, size=args.ref_max, replace=False)
        X_ref = X_full[idx_ref]
        bn_keys_ref = [bn_keys_full[i] for i in idx_ref]
        print(f"[i] ref_max 적용: {X_ref.shape[0]}")

    print("[i] (target) 인덱스 빌드 (ref subset, CPU/GPU)")
    Xn_ref = l2_normalize_np(X_ref.astype(np.float32))
    index = build_faiss_index(
        Xn_ref, nlist=args.nlist, nprobe=args.nprobe,
        use_gpu=args.use_gpu, gpu_id=args.gpu_id, gpu_fp16=bool(args.gpu_fp16),
        add_bs=args.faiss_add_bs, train_max=args.faiss_train_max
    )

    # ---- 3) target 처리 ----
    tgt_dir = Path(args.target_dir)
    files = sorted(tgt_dir.glob(args.glob))
    out_csv  = Path(args.out_csv);  out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_json = Path(args.out_jsonl); out_json.parent.mkdir(parents=True, exist_ok=True)

    kept = total = 0
    with out_csv.open("w", encoding="utf-8") as fcsv, out_json.open("w", encoding="utf-8") as fj:
        fcsv.write("key,score,threshold,decision\n")
        buf_vecs, buf_meta = [], []

        def flush():
            nonlocal kept, total, buf_vecs, buf_meta
            if not buf_vecs:
                return
            Q = np.stack(buf_vecs).astype(np.float32)
            Qn = l2_normalize_np(Q)
            kq = min(args.k, max(1, index.ntotal))
            D, _ = index.search(Qn, kq)
            np.clip(D, -1.0, 1.0, out=D)  # 수치 안정화
            scores = np.zeros((Qn.shape[0],), dtype=np.float32) if D.shape[1] == 0 else (1.0 - D.mean(axis=1))
            for s, meta in zip(scores, buf_meta):
                total += 1
                decision = "keep" if s < thresh else "drop"
                if args.export_all or decision == "keep":
                    fcsv.write(f"{meta['key']},{s:.12e},{thresh:.12e},{decision}\n")
                    fj.write(json.dumps({
                        "key": meta["key"],
                        "source": meta["source"],
                        "func_id": meta["func_id"],
                        "score": float(s),
                        "threshold": thresh,
                        "decision": decision
                    }, ensure_ascii=False) + "\n")
                if decision == "keep":
                    kept += 1
            buf_vecs.clear(); buf_meta.clear()

        for fp in files:
            rel = fp.relative_to(tgt_dir).as_posix()
            for rec in read_jsonl(fp):
                vec = rec.get("vector"); dim_r = rec.get("dim")
                fid = rec.get("func_id", "")
                if vec is None or dim_r != dim:
                    continue
                key = rec.get("key") or f"{rel}::{fid}"
                buf_vecs.append(np.asarray(vec, dtype=np.float32))
                buf_meta.append({"key": key, "source": rel, "func_id": fid})
                if len(buf_vecs) >= bs:
                    flush()
        flush()

    print(f"[OK] filter_targets 완료 (총 {total}개, keep={kept})")

# ===============================
# CLI
# ===============================

def main():
    ap = argparse.ArgumentParser(description="Anomaly detection with benign DB + target filtering (FAISS CPU/GPU)")
    sub = ap.add_subparsers(dest="mode", required=True)

    # ingest
    ap_in = sub.add_parser("ingest", help="JSONL 임베딩을 SQLite DB에 적재(append)")
    ap_in.add_argument("--inp_dir", required=True)
    ap_in.add_argument("--glob", default="**/*.jsonl")
    ap_in.add_argument("--db", required=True)

    # detect
    ap_de = sub.add_parser("detect", help="benign 자체 kNN 거리 분포 CSV 저장")
    ap_de.add_argument("--db", required=True)
    ap_de.add_argument("--out_csv", required=True)
    ap_de.add_argument("--k", type=int, default=10)
    ap_de.add_argument("--batch", type=int, default=1024)
    ap_de.add_argument("--self_max", type=int, default=0, help="benign 샘플 크기(0=전수)")
    ap_de.add_argument("--nlist", type=int, default=100, help="FAISS IVF nlist")
    ap_de.add_argument("--nprobe", type=int, default=10, help="FAISS IVF nprobe")
    ap_de.add_argument("--percentile", type=float, default=None, help="옵션: detect 시 threshold도 함께 출력")
    ap_de.add_argument("--p_range", type=str, default="", help="연속 percentile 범위: 'START:END:STEP' (예: 55:65:0.1)")
    ap_de.add_argument("--dedup_round", type=int, default=0, help="threshold 계산용 de-dup 라운딩 자리수(0=미사용)")
    ap_de.add_argument("--omp_threads", type=int, default=0, help="CPU OMP 스레드 수(0=기본)")
    # GPU 옵션
    ap_de.add_argument("--use_gpu", action="store_true", help="GPU 사용(faiss-gpu 필요)")
    ap_de.add_argument("--gpu_id", type=int, default=0, help="사용할 GPU ID")
    ap_de.add_argument("--gpu_fp16", type=int, default=1, help="GPU index에 FP16 사용(1=사용)")
    ap_de.add_argument("--faiss_add_bs", type=int, default=200000, help="FAISS index.add 타일 크기")
    ap_de.add_argument("--faiss_train_max", type=int, default=500000, help="IVF 학습 최대 샘플 수 (<=0이면 전수 사용)")

    # filter_targets
    ap_ft = sub.add_parser("filter_targets", help="target 임베딩 필터링")
    ap_ft.add_argument("--db", required=True)
    ap_ft.add_argument("--target_dir", required=True)
    ap_ft.add_argument("--glob", default="**/*.jsonl")
    ap_ft.add_argument("--out_csv", required=True)
    ap_ft.add_argument("--out_jsonl", required=True)
    ap_ft.add_argument("--k", type=int, default=10)
    ap_ft.add_argument("--percentile", type=float, default=95.0)
    ap_ft.add_argument("--batch", type=int, default=512)
    ap_ft.add_argument("--self_max", type=int, default=0, help="threshold 계산용 benign 샘플 크기(0=전수)")
    ap_ft.add_argument("--ref_max", type=int, default=0, help="참조 benign 최대 개수(0=전수)")
    ap_ft.add_argument("--nlist", type=int, default=100)
    ap_ft.add_argument("--nprobe", type=int, default=10)
    ap_ft.add_argument("--export_all", action="store_true")
    ap_ft.add_argument("--threshold", type=float, default=None, help="고정 threshold 값 (주어지면 percentile 계산 생략)")
    ap_ft.add_argument("--dedup_round", type=int, default=0, help="threshold 계산용 de-dup 라운딩 자리수(0=미사용)")
    ap_ft.add_argument("--omp_threads", type=int, default=0, help="CPU OMP 스레드 수(0=기본)")
    # GPU 옵션
    ap_ft.add_argument("--use_gpu", action="store_true", help="GPU 사용(faiss-gpu 필요)")
    ap_ft.add_argument("--gpu_id", type=int, default=0, help="사용할 GPU ID")
    ap_ft.add_argument("--gpu_fp16", type=int, default=1, help="GPU index에 FP16 사용(1=사용)")
    ap_ft.add_argument("--faiss_add_bs", type=int, default=200000, help="FAISS index.add 타일 크기")
    ap_ft.add_argument("--faiss_train_max", type=int, default=500000, help="IVF 학습 최대 샘플 수 (<=0이면 전수 사용)")

    args = ap.parse_args()

    if args.mode == "ingest":
        cmd_ingest(args)
    elif args.mode == "detect":
        cmd_detect(args)
    elif args.mode == "filter_targets":
        cmd_filter_targets(args)

if __name__ == "__main__":
    main()
