import os
import subprocess
from dotenv import load_dotenv

load_dotenv() 

def run_command(cmd):
    print(f"\n[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] Command failed with exit code {result.returncode}")
        exit(result.returncode)

def main():
    openai_api_key = os.getenv("OPENAI_API_KEY")
    hybrid_api_key = os.getenv("HYBRID_API_KEY")
    sample_path = os.getenv("SAMPLE_EXE_PATH")
    sample_hash = os.getenv("SAMPLE_HASH")
    environment_id = os.getenv("ENVIRONMENT_ID")

    ha_output_dir = os.getenv("HA_OUTPUT_DIR")
    ghidra_output_dir = os.getenv("GHIDRA_OUTPUT_DIR")
    preprocess_output_dir = os.getenv("PREPROCESS_OUTPUT_DIR")
    filtering_output_dir = os.getenv("FILTERING_OUTPUT_DIR")
    comment_output_dir = os.getenv("COMMENT_OUTPUT_DIR")
    result_output_dir = os.getenv("RESULT_OUTPUT_DIR")
    procedure_output_dir = os.getenv("PROCEDURE_OUTPUT_DIR")
    report_output_dir = os.getenv("REPORT_OUTPUT_DIR")

    if not all([openai_api_key, hybrid_api_key, sample_path, sample_hash,
                environment_id,filtering_output_dir,
                ha_output_dir, ghidra_output_dir, preprocess_output_dir,
                comment_output_dir, result_output_dir,
                procedure_output_dir, report_output_dir]):
        raise EnvironmentError("Missing required environment variables in .env")

    os.environ["OPENAI_API_KEY"] = openai_api_key
    os.environ["HYBRID_API_KEY"] = hybrid_api_key
    os.environ["SAMPLE_EXE_PATH"] = sample_path
    os.environ["SAMPLE_HASH"] = sample_hash

    # Step 1: Crawl hybrid analysis
    run_command(f"python3 crawl.py")

    # Step 2: Run Ghidra
    run_command(f"python3 decompile.py")

    # Step 2-1: Preprocess Decompiled Code
    run_command(f"python3 preprocess_code.py")

    # Step 2-2: Generating embbedding file
    run_command(f"python3 generate_embedding.py")

    # Step 2-3: Filtering Benign function
    run_command(f"python3 filtering.py")

    # Step 2-4: DeGPT functuin
    run_command(f"python3 degpt_function.py")

    # Step 2-5: Remove the comments made by DeGPT 
    run_command(f"python3 remove_comment.py")

    # Step 2-6: Filtering benign functions using llm
    run_command(f"python3 llm_filter.py")

    # Step 3: Generate Comments
    run_command("python3 generate_comment.py")

    # Step 4: Mapping
    run_command("python3 mapping.py")

    # Step 5: Graph-based procedure generation
    run_command("python3 generate_ttp.py")

    # Step 6: Report generation
    run_command("python3 generate_report.py")

if __name__ == "__main__":
    main()
