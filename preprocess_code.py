import os
import re
import pandas as pd
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────────
load_dotenv()
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
GHIDRA_OUTPUT_DIR = os.getenv("GHIDRA_OUTPUT_DIR")
PREPROCESS_OUTPUT_DIR = os.getenv("PREPROCESS_OUTPUT_DIR")

input_file_path = os.path.join(GHIDRA_OUTPUT_DIR, f"{SAMPLE_HASH}.txt")
os.makedirs(PREPROCESS_OUTPUT_DIR, exist_ok=True)
cleaned_file_path = os.path.join(PREPROCESS_OUTPUT_DIR, f"{SAMPLE_HASH}.txt")
json_output_path = os.path.join(PREPROCESS_OUTPUT_DIR, f"{SAMPLE_HASH}.json")
# ─────────────────────────────────────────────────────────────────────────────────

def is_halt_only(src: str) -> bool:
    lines = src.splitlines()
    body_started = False
    body_lines = []
    for line in lines:
        if not body_started:
            if "{" in line:
                body_started = True
            continue
        if "}" in line:
            break
        stripped = line.strip()
        if stripped:
            body_lines.append(stripped)
    return (len(body_lines) == 1 and body_lines[0] == "halt_baddata();")

def extract_function_name(source: str) -> str:
    first_line = source.strip().split('\n', 1)[0]
    m = re.search(r'\b([A-Za-z_]\w*)\s*\(', first_line)
    return m.group(1) if m else ''

def clean_blank_lines(source: str) -> str:
    return re.sub(r'\n[ \t]*\n+', '\n', source).strip()

def is_self_trivial_wrapper(func_name: str, source: str) -> bool:

    m = re.search(r'\{([\s\S]*?)\}', source)
    if not m:
        return False
    lines = [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]

    # 1) just call functions
    call_only    = re.compile(rf'^{re.escape(func_name)}\s*\(.*\)\s*;\s*$')
    # 2) just return functions 
    return_call  = re.compile(rf'^return\s+{re.escape(func_name)}\s*\(.*\)\s*;\s*$')

    # call_only or return_call with one line
    if len(lines) == 1 and (call_only.match(lines[0]) or return_call.match(lines[0])):
        return True

    #  call_only + return; or return_call + (optional) return; with two line
    if len(lines) == 2:
        if call_only.match(lines[0]) and lines[1] == 'return;':
            return True
        if return_call.match(lines[0]) and lines[1] == 'return;':
            return True

    return False

def apply_filters(row):
    fname = row["Function Name"]
    src   = row["Source Code"]

    # 1) Skip external functions
    if "<EXTERNAL>" in fname:
        return False
    # 2) Skip halt-only functions
    if is_halt_only(src):
        return False
    # 3) Skip trivial self-wrappers
    if is_self_trivial_wrapper(fname, src):
        return False
    return True

with open(input_file_path, 'r', encoding='utf-8') as file:
    content = file.read()


content = re.sub(r'/\*.*?\*/','', content, flags=re.DOTALL)
content = re.sub(r'\n+', '\n', content)
content = re.sub(r'Parameter:.*\n', '', content)
content = re.sub(r'Called by:.*\n', '', content)

with open(cleaned_file_path, 'w', encoding='utf-8') as file:
    file.write(content)
print(f"Preprocessing complete. File saved to: {cleaned_file_path}")

function_names, addresses, source_codes = [], [], []

with open(cleaned_file_path, 'r', encoding='utf-8') as file:
    lines = file.readlines()

current_function_name = None
current_address = None
current_source_code = []
capturing_code = False

for line in lines:
    if "Function Found:" in line:
        if current_function_name:
            source_codes.append("\n".join(current_source_code).strip())
            current_source_code = []

        current_function_name = line.split(":", 1)[1].strip()
        function_names.append(current_function_name)

    elif "Address:" in line:
        current_address = line.split(":", 1)[1].strip()
        addresses.append(current_address)

    elif "Decompiled C Code:" in line:
        capturing_code = True

    elif capturing_code:
        current_source_code.append(line.strip())

if current_function_name:
    source_codes.append("\n".join(current_source_code).strip())


df = pd.DataFrame({
    "Function Name": function_names,
    "Address": addresses,
    "Source Code": source_codes
})

df = df[df.apply(apply_filters, axis=1)].reset_index(drop=True)
df.to_json(json_output_path, orient="records", lines=True, force_ascii=False)

print(f"Extracted function data saved to JSON: {json_output_path}")