import os
import subprocess
from dotenv import load_dotenv

load_dotenv()

GHIDRA_HEADLESS_PATH = os.getenv("GHIDRA_HEADLESS_PATH")
GHIDRA_SCRIPT = os.getenv("GHIDRA_SCRIPT")
SAMPLE_EXE_PATH = os.getenv("SAMPLE_EXE_PATH")
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
GHIDRA_OUTPUT_DIR = os.getenv("GHIDRA_OUTPUT_DIR")

def run_ghidra_analysis():
    if not all([GHIDRA_HEADLESS_PATH, GHIDRA_SCRIPT, SAMPLE_EXE_PATH, SAMPLE_HASH, GHIDRA_OUTPUT_DIR]):
        raise ValueError("Missing one or more Ghidra configuration values in .env")

    os.makedirs(GHIDRA_OUTPUT_DIR, exist_ok=True)

    ghidra_cmd = [
        GHIDRA_HEADLESS_PATH,     
        ".",
        "tmp_ghidra_project" ,     
        "-import", os.path.abspath(SAMPLE_EXE_PATH),
        "-postScript", os.path.basename(GHIDRA_SCRIPT),        
        "-deleteProject",
        "-overwrite"
    ]

    print("[*] Running Ghidra analysis...")
    result = subprocess.call(ghidra_cmd)

    if result == 0:
        print("Analysis completed")
    else:
        print(f"Analysis failed with exit code {result}")

if __name__ == "__main__":
    run_ghidra_analysis()