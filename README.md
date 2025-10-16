# CTIGEN

crawl.py 
- 동적 분석 실행 코드
- .env에서 ENVIRONMENT_ID 로 분석 돌릴 환경 지정

run_extract.py
- asm decompile 코드
- dump_instructions.py 랑 같은 위치에 있어야됨

fun_preprocess.py 
- ["FUN_", "Catch@", "Unwind@", "Catch_All@", "thunk_FUN_"] 로 시작하는 함수 제거

o_extract_embadding_palmtree.py
- palmtree 임베딩 생성
- --batch_size 로 조절가능 기본 32
```
python o_extract_embadding_palmtree.py --repo_dir ./model/path --model_path model/path/transformer.ep19 --vocab_path model/path/vocab --inp_dir path/to/asm_decompile_result --out_jsonl path/to/embedding_result.jsonl 
```

anomb_s.py
- ingest -> embedding 결과 db로 만들기 (비나인) <p>
input : o_extract_embadding_palmtree.py 결과
- detect -> threshold 구하기
- filter_target -> 필터링 하기
- output -> benign 이라고 판단 된거
```python
python anomb_s.py ingest --inp_dir ./path/to/embedding_result_dir --db ./path/to/data.db
#ex)  python ingest --inp_dir ./Dikedataset/embedding --db ./Dikedataset/db/benign.db

python anomb_s.py detect --db ./path/to/data.db --out_csv ./path/to/result.csv --k 10 --percentile 95 --use_gpu --gpu_id 0
# --percentile 로 단일 threshold 혹은 --p_range 일정범위 threshold 구할 수 있음
#ex)--p_range : 55:65:0.1
#gpu 설정도 argument로 받음

python anomb_s.py filter_targets --db ./path/to/data.db --out_csv ./path/to/result.csv --k 10 --percentile 95 --use_gpu --gpu_id 0
# --percentile 로 detect로 threshold 구하지않고 돌리면서 구할수 있음
# --threshold 로 detect로 threshold로 구해둔 threshold를 인풋으로 주고 사용할 수 있음
# --export_all 하면 benign이라 판단한거 아니라 판단한거 다 보임
# ex) "decision": "drop" or "decision": "keep 이런식으로 둘다 나옴
#gpu 설정도 argument로 받음

```

filtering.py
- anomb_s.py 결과를 기준으로 preprocess 결과랑 겹치는거 제거
```
python filtering.py anomb_result.jsonl preprocessed_file.json remove_benign.json 
```

degpt_function.py
- 함수 degpt진행
- https://github.com/PeiweiHu/DeGPT 에있는 requirement 충족해야됨
- 파일 구조 chat.py랑 같은 위치에 있어야됨

```
DeGPT
├── cinspector
├── DeGPT
│   ├── degpt
│   │   ├── chat.py
│   │   ├── config.ini
│   │   ├── degpt_function.py
│   │   ├── mssc.py
│   │   ├── prompt.json
│   │   ├── prompt.py
│   │   ├── __pycache__
│   │   ├── role.py
│   │   ├── test.json
│   │   └── util.py
├── README.md
```

remove_comment.py
- degpt 가 만든 주석 제거


---------------- 

 # CTIGen

This repository provides a fully automated pipeline for generating structured malware analysis reports using static + dynamic analysis and LLMs.

## Setup

### Prepare `.env`
All API keys and configurations must be set in the .env file before execution.
```bash
cd /Data/.env
# Fill in API keys, file paths, hash value, etc.
```

### Install Requirements
```bash
pip install -r requirements.txt
```
### Initialize Neo4j Graph (Required for TTP Generation)

Before generating TTPs, you must first build the MITRE ATT&CK knowledge graph in Neo4j.

#### 1.1 Load MITRE ATT&CK Ontolocy (https://ontolocy.readthedocs.io/en/stable/ontolocy_parsers/MitreAttackParser/)

```python
from langchain_community.graphs import Neo4jGraph
from neontology import init_neontology
from ontolocy.tools import MitreAttackParser

graph = Neo4jGraph(
    url="bolt://localhost:7687",
    username="neo4j",
    password="your_password"
)

init_neontology(graph)
parser = MitreAttackParser()
parser.parse_file("/path/to/enterprise-attack.json")
```

#### 1.2 Extract and Store Procedure Examples

```bash
python initialize_procedures.py
```

This script:
- Retrieves `procedure examples` for each Technique
- Extracts entities, relationships, and claims using an LLM
- Stores the result into the Neo4j graph database

---

### Run the Pipeline
```bash
python run.py
```

## Pipeline Stages

| Step | Script | Description |
|------|--------|-------------|
| 1 | `crawl.py` | Download Hybrid Analysis JSON by hash |
| 2 | `decompile.py` | Run Ghidra headless analysis |
| 3 | `preprocess_code.py` | Preprocess decompiled code |
| 4 | `generate_comment.py` | Generate function-level comments using LLM |
| 5 | `mapping.py` | Match behaviors to ATT&CK using FAISS + LLM verification |
| 6 | `generate_ttp.py` | Generate TTP procedures using GraphRAG over Neo4j |
| 7 | `generate_ttp.py` | Build structured markdown report |

## Output
Markdown report saved to:
```
/reports/{hash}_report.md
```

## Notes
- All API keys and configurations must be set in the `.env` file before execution.
- Python 3.8+
- Ghidra installed and accessible via `GHIDRA_HEADLESS_PATH`
- OpenAI API key
- Hybrid Analysis API key (https://www.hybrid-analysis.com)
- Neo4j running locally or remotely for TTP generation
- The `Report/` directory contains both human-written reports and CTIGen-generated reports.

---
