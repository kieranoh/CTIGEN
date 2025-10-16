import re
import json
import sys
import os
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────────
load_dotenv()
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
FILTERING_OUTPUT_DIR = os.getenv("FILTERING_OUTPUT_DIR")
INPUT_FILE  = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_degpt_result.json")
OUTPUT_FILE = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_degpt_remove.json")

# ─────────────────────────────────────────────────────────────────────────────────

def remove_comments(code: str) -> str:
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
    return code

def process_json_file(input_path: str, output_path: str):
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read().strip()
    data = None

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))

    def recurse(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "Source Code" and isinstance(v, str):
                    obj[k] = remove_comments(v)
                else:
                    recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(data)

    with open(output_path, 'w', encoding='utf-8') as f_out:
        if isinstance(data, list):
            for obj in data:
                f_out.write(json.dumps(obj, ensure_ascii=False) + '\n')
        else:
            f_out.write(json.dumps(data, ensure_ascii=False) + '\n')

    print(f"JSON with comments removed saved to: {output_path}")

if __name__ == "__main__":
    
    process_json_file(INPUT_FILE, OUTPUT_FILE)
