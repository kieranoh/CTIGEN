#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import argparse
from pathlib import Path

def collect_funcnames_from_results(results_path: Path):
    """
    1번 파일(JSONL)에서 key를 기준으로 ::로 split,
    두 번째 요소(FUN_XXXXXX)를 함수명으로 추출.
    """
    funcnames = set()
    with results_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            key = obj.get("key", "")
            if not key or "::" not in key:
                continue

            parts = key.split("::")
            if len(parts) >= 2:
                name = parts[1].strip()
                if name:
                    funcnames.add(name)
    return funcnames


def main():
    ap = argparse.ArgumentParser(description="file2(JSONL)에서 file1(JSONL) key 기반 함수 제외 후 file3(JSONL)로 저장")
    ap.add_argument("file1", help="1번: results.jsonl (key에서 함수명 추출)")
    ap.add_argument("file2", help="2번: target.json (jsonl 형식, 각 줄이 {Function Name: ...})")
    ap.add_argument("file3", help="3번: 출력 JSONL (2번 형식 그대로, 1번 함수 제외)")
    args = ap.parse_args()

    file1 = Path(args.file1)
    file2 = Path(args.file2)
    file3 = Path(args.file3)

    # 1️⃣ file1에서 제외할 함수명 집합 추출
    exclude_names = collect_funcnames_from_results(file1)
    print(f"[i] 제외할 함수 {len(exclude_names)}개 로드 완료")

    # 2️⃣ file2를 라인 단위로 읽으며 제외
    kept, removed = 0, 0
    file3.parent.mkdir(parents=True, exist_ok=True)
    with file2.open("r", encoding="utf-8", errors="ignore") as fin, \
         file3.open("w", encoding="utf-8") as fout:

        for line in fin:
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                continue

            name = (obj.get("Function Name") or "").strip()
            if name in exclude_names:
                removed += 1
                continue

            fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
            kept += 1

    print(f"[✓] 완료: {kept}개 남김 / {removed}개 제거 → {file3}")

if __name__ == "__main__":
    main()
