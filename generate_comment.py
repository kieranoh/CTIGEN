import logging
import os
import json
import time
import argparse
from dotenv import load_dotenv
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import OllamaLLM

load_dotenv()

SAMPLE_HASH = os.getenv("SAMPLE_HASH")
FILTERING_OUTPUT_DIR = os.getenv("FILTERING_OUTPUT_DIR")


##########################################################################################
# Config from .env or defaults
##########################################################################################
MODEL_NAME = os.getenv("MODEL_NAME")
PROMPT_FILE = os.getenv("PROMPT_FILE")
INPUT_FILE = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}.json")
COMMENT_OUTPUT_DIR = os.getenv("COMMENT_OUTPUT_DIR")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
##########################################################################################

if not all([INPUT_FILE, OPENAI_API_KEY]):
    raise EnvironmentError("❌ Required environment variables missing: INPUT_JSON, OPENAI_API_KEY")

os.environ["PYDANTIC_COMPAT_V1"] = "1"
os.environ["PYDANTIC_V2"] = "True"
os.environ["OLLAMA_CUDA"] = "1"

def load_prompt():
    with open(PROMPT_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def build_prompt_for_function(code, function_name):
    intro = load_prompt()
    prompt = f"{intro}\nHere is code from the function {function_name}:\n\n\n{code}\n\n"
    return prompt

class LangChainAgent:
    def __init__(self, model_name=MODEL_NAME):
        self.model_name = model_name
        if model_name.startswith("gpt-"):
            self.model = ChatOpenAI(model=model_name, temperature=0,  top_p=1.0, openai_api_key=OPENAI_API_KEY)
        elif model_name == "llama3":
            self.model = OllamaLLM(model="llama3.3:70b")
        elif model_name == "gemini":
            self.model = ChatGoogleGenerativeAI(model="gemini-1.5-flash", temperature=0, max_output_tokens=4000)
        elif model_name == "claude":
            self.model = ChatAnthropic(model="claude-3-haiku-20240307", temperature=0, max_tokens=50)
        elif model_name == "deepseek":
            self.model = OllamaLLM(model="deepseek-r1:7b")
        else:
            raise ValueError("Unsupported model name")

def send_request(prompt, model_name):
    agent = LangChainAgent(model_name)
    retries = 5
    wait_time = 5
    for attempt in range(retries):
        try:
            response = agent.model.invoke(prompt)
            return str(response.content)
        except Exception as e:
            if "429" in str(e) or "rate_limit_error" in str(e):
                time.sleep(wait_time)
                wait_time *= 2
            else:
                logging.error(f"Error: {e}")
                return None
    return None

def generate_comment(task):
    part_code, part_name = task
    prompt = build_prompt_for_function(part_code, part_name)
    response = send_request(prompt=prompt, model_name=MODEL_NAME)
    return {
        "Function Name": part_name,
        "Source Code": part_code,
        "Comment": response if isinstance(response, str) else "Failed to generate comment"
    }

def split_function(function_name, source_code, token_limit=12000):
    tokens = source_code.split()
    split_functions = []
    current_chunk = []
    current_token_count = 0
    for token in tokens:
        if current_token_count + len(token) > token_limit:
            part_name = f"{function_name}_{len(split_functions) + 1}"
            split_functions.append((part_name, " ".join(current_chunk)))
            current_chunk = []
            current_token_count = 0
        current_chunk.append(token)
        current_token_count += len(token)
    if current_chunk:
        part_name = f"{function_name}_{len(split_functions) + 1}"
        split_functions.append((part_name, " ".join(current_chunk)))
    return split_functions

def process_function(func):
    try:
        function_name = func["Function Name"]
        source_code = func.get("Source Code", func.get("Opcode"))
        if not source_code:
            return []
        split_funcs = split_function(function_name, source_code)
        tasks = [(code, name) for name, code in split_funcs]
        results = [generate_comment(task) for task in tasks]
        return results
    except Exception as e:
        logging.error(f"Error: {e}")
        return []

def get_output_filename(input_path):
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    return f"{base_name}_comments.json"

def process_json(input_file, output_file):
    with open(input_file, 'r',encoding='utf-8') as f:
        functions = [json.loads(line.strip()) for line in f if line.strip()]
    output_data = []
    with Pool(cpu_count()) as pool:
        for result in tqdm(pool.imap_unordered(process_function, functions), total=len(functions), desc="Generating Comments"):
            output_data.extend(result)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding="utf-8") as f:
        json.dump(output_data, f, indent=4, ensure_ascii=False)
    print(f"Comments saved to {output_file}")


if __name__ == "__main__":
    output_file = os.path.join(COMMENT_OUTPUT_DIR, get_output_filename(INPUT_FILE))
    process_json(INPUT_FILE, output_file)