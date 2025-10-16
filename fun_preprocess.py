import json
from pathlib import Path
from tqdm import tqdm

INPUT_FOLDER = "./DikeDataset/out_jsonl"
OUTPUT_FOLDER = "./DikeDataset/pre_process_jsonl"


def preprocess(file_name: Path, out_path: Path):

    result = []
    kept_lines = 0
    skipped_lines = 0
    
    try:
        with open(file_name,'r',encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                obj = json.loads(line)
                fun_name = obj.get("func_id","")
                
                fun_name = str(fun_name)

                skip_prefixes = ["FUN_", "Catch@", "Unwind@", "Catch_All@", "thunk_FUN_"]

                if any(fun_name.startswith(prefix) for prefix in skip_prefixes):
                    skipped_lines += 1
                    continue
                result.append(obj)
                kept_lines += 1
            
        if result:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, 'w', encoding='utf-8') as out_f:
                for r in result:
                    out_f.write(json.dumps(r, ensure_ascii=False) + "\n")
            return True, kept_lines, skipped_lines
        else:
            return False, kept_lines, skipped_lines

    except Exception as e:
        print(f"[!] Error processing {file_name}: {e}")
        return False, kept_lines, skipped_lines

def main():
    src = Path(INPUT_FOLDER)
    dst = Path(OUTPUT_FOLDER)

    kept_files = 0     
    skipped_files = 0  

    kept_lines_total = 0
    skipped_lines_total = 0

    cand = [p for p in src.rglob("*") if p.is_file()]
    print(f"[i] 후보 파일: {len(cand)}개")
    pbar = tqdm(cand, desc="Scanning", unit="file", dynamic_ncols=True)
    for p in pbar:
        rel = p.relative_to(src)
        out_path = dst / rel
        out_path.parent.mkdir(parents=True, exist_ok=True)

        saved, kept_lines, skipped_lines = preprocess(p, out_path)

        kept_lines_total += kept_lines
        skipped_lines_total += skipped_lines

        if saved:
            kept_files += 1
        else:
            skipped_files += 1

        pbar.set_postfix({
            "files(kept/skip)": f"{kept_files}/{skipped_files}",
            "func_kept": kept_lines_total,
            "func_filtered": skipped_lines_total,
            "last_filtered": skipped_lines  
        })

    total_files = kept_files + skipped_files
    total_lines = kept_lines_total + skipped_lines_total

    print("\n=== 정제 완료 ===")
    print(f"총 파일     : {total_files}")
    print(f"유지 파일    : {kept_files}")
    print(f"제외 파일    : {skipped_files}")
    print(f"총 라인      : {total_lines}")
    print(f"유지 라인    : {kept_lines_total}")
    print(f"스킵 라인    : {skipped_lines_total}")
    print(f"정제본 위치  : {dst}")

if __name__ == "__main__" : 
    main()