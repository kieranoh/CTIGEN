import json
import os
from dotenv import load_dotenv
import re
import numpy as np
from tqdm import tqdm
import time
from sklearn.metrics.pairwise import cosine_similarity
from collections import defaultdict
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from faiss import IndexFlatL2
from multiprocessing import Pool, cpu_count
import tiktoken
import faiss

load_dotenv()

# ───────────── Setup ─────────────
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")
embedding_model = OpenAIEmbeddings(model="text-embedding-ada-002")
llm = ChatOpenAI(model_name="gpt-4o-mini", temperature=0)
model_name = "gpt-4o-mini"
encoding = tiktoken.tiktoken.get_encoding("cl100k_base")

# ───────────── File Path ─────────────
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
COMMENT_OUTPUT_DIR = os.getenv("COMMENT_OUTPUT_DIR")
HA_OUTPUT_DIR = os.getenv("HA_OUTPUT_DIR")
RESULT_OUTPUT_DIR = os.getenv("RESULT_OUTPUT_DIR")

function_file_path = os.path.join(COMMENT_OUTPUT_DIR, f"{SAMPLE_HASH}_comments.json")
indicator_file_path = os.path.join(HA_OUTPUT_DIR, f"{SAMPLE_HASH}.json")
output_path = os.path.join(RESULT_OUTPUT_DIR, f"{SAMPLE_HASH}_result.json")
# ───────────── Load Data ─────────────
with open(function_file_path, "r",encoding='utf-8') as f:
    function_data = json.load(f)
with open(indicator_file_path, "r",encoding='utf-8') as f:
    indicator_data = json.load(f)

# ───────────── Indicator Vector indexing ─────────────
indicator_texts = []
indicator_ids = []

exclude_prefixes = [
    "Imports Suspicious APIs",
    "Contains export function",
    "Calls an API typically used to load libraries",
    "Contains ability to load modules",
    "Section contains high entropy",
    "Uses 32 bit executable PE",
    "Runs shell commands"
]

for sig in indicator_data.get("signatures", []):
    attack_id = (sig.get("attck_id") or "").strip()
    name = (sig.get("name") or "").strip()
    desc = (sig.get("description") or "").strip()
    if any(name.startswith(prefix) for prefix in exclude_prefixes):
        continue

    if attack_id and name and desc:
        indicator_texts.append(f"{name}: {desc}")
        indicator_ids.append(attack_id)

indicator_embeddings = np.array([embedding_model.embed_query(text) for text in tqdm(indicator_texts, desc="Embedding indicators")])
index = IndexFlatL2(indicator_embeddings.shape[1])
index.add(indicator_embeddings)

# ───────────── LLM Validation ─────────────
def split_into_sentences(text):
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+', text) if s.strip()]

def build_prompt(sentence, indicator):
    return f"""
[Function Sentence]
{sentence}

[Indicator Description]
{indicator}

[Task]
Does the sentence describe the behavior in the indicator? Focus on API calls and intent.
Answer with YES or NO and briefly explain.
"""

def process_function(args):
    function = args
    fname = function["Function Name"]
    comment = function.get("Comment", "").strip()
    if not comment:
        return None

    results = []
    sentences = split_into_sentences(comment)
    sentence_embeddings = [embedding_model.embed_query(s) for s in sentences]

    for i, sent_emb in enumerate(sentence_embeddings):
        D, I = index.search(np.array([sent_emb]), k=10)
        for j in I[0]:
            indicator = indicator_texts[j]
            attack_id = indicator_ids[j]

            sim = cosine_similarity([sent_emb], [indicator_embeddings[j]])[0][0]
            if sim < 0.75:
                continue

            prompt = build_prompt(sentences[i], indicator)
            response = llm.invoke(prompt).content.strip().lower()
            if response.startswith("yes"):
                results.append({
                    "ATT&CK ID": attack_id,
                    "Indicator": indicator,
                    "Comment": comment,
                    "Matched Sentence": sentences[i],
                    "Similarity": round(sim, 6)
                })
                break  

    return fname, results[:30] if results else None

if __name__ == "__main__":
    start = time.time()
    thresholded_results = {}
    os.makedirs(RESULT_OUTPUT_DIR, exist_ok=True)

    with Pool(cpu_count()) as pool:
        all_results = list(tqdm(pool.imap(process_function, function_data), total=len(function_data), desc="LLM+FAISS Matching"))

    for result in all_results:
        if result:
            fname, matched = result
            if matched:
                thresholded_results[fname] = matched

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(thresholded_results, f, indent=4)

    print(f"\nSaved to {output_path}")
    print(f"Execution Time: {time.time() - start:.2f}초")

