import json
import os
from dotenv import load_dotenv
from role import RoleModel
import role as role_mod

# ─────────────────────────────────────────────────────────────────────────────────
load_dotenv()
SAMPLE_HASH      = os.getenv("SAMPLE_HASH")
FILTERING_OUTPUT_DIR = os.getenv("FILTERING_OUTPUT_DIR")
INPUT_FILE = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_filtering.json")
OUTPUT_FILE = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_degpt_result.json")
# ─────────────────────────────────────────────────────────────────────────────────

def _get_optimized_from_dic_dynamic(dic: dict) -> str:
    """
    Drop-in replacement for role.get_optimized_from_dic().
    Apply optimizations in the order of `sorted_directions` and stop on first FAIL.
    This matches the behavior you called “the first version”.
    """
    opts = dic.get('optimization', {})
    directions = [d.value if hasattr(d, 'value') else d for d in dic.get('sorted_directions', [])]

    out = dic.get('decompiler_output', '')
    for key in directions:
        opt = opts.get(key)
        if not opt:
            # If this direction has no recorded optimization, skip gracefully.
            continue
        status = opt.get('status', '')
        if status.startswith('FAIL'):
            # Stop at the first failed step; return last successful output.
            return out
        out = opt.get('output', out)
    return out

role_mod.get_optimized_from_dic = _get_optimized_from_dic_dynamic

def load_functions(filepath):
    funcs = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                funcs.append(json.loads(line))
    return funcs

def main():

    functions = load_functions(INPUT_FILE)

    for func in functions:
        name    = func.get("Function Name")
        address = func.get("Address")
        source  = func.get("Source Code")

        print(f"Processing {name} @ {address} ...")

        model = RoleModel(decompile_code=source, src_code=None)
        res = model.work(end_at="DONE")

        result_entry = {
            "Function Name": name,
            "Address": address,
            "Source Code": res.get("output"),
        }

        # Append intermediate results
        with open(OUTPUT_FILE, 'a', encoding='utf-8') as out:
            json.dump(result_entry, out, ensure_ascii=False)
            out.write('\n')

    print(f"All done. Intermediate results were logged to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
