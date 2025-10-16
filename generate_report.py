import os
from dotenv import load_dotenv
import json
import re
import textwrap
from datetime import datetime
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.schema import SystemMessage, HumanMessage
from time import time
from tqdm import tqdm

load_dotenv()

os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

llm_gpt4o = ChatOpenAI(model_name="gpt-4o", temperature=0.7)
llm_gpt4omini = ChatOpenAI(model_name="gpt-4o-mini", temperature=0.0)

SAMPLE_HASH = os.getenv("SAMPLE_HASH")
HA_OUTPUT_DIR = os.getenv("HA_OUTPUT_DIR")
GHIDRA_OUTPUT_DIR = os.getenv("GHIDRA_OUTPUT_DIR")
COMMENT_OUTPUT_DIR = os.getenv("COMMENT_OUTPUT_DIR")
RESULT_OUTPUT_DIR = os.getenv("RESULT_OUTPUT_DIR")
PROCEDURE_OUTPUT_DIR = os.getenv("PROCEDURE_OUTPUT_DIR")
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR")
MITRE_PATH = os.getenv("MITRE_PATH")

os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

json_data_path = os.path.join(HA_OUTPUT_DIR, f"{SAMPLE_HASH}.json")
ttp_file = os.path.join(PROCEDURE_OUTPUT_DIR, f"{SAMPLE_HASH}_result.json")
comments_json_path = os.path.join(COMMENT_OUTPUT_DIR, f"{SAMPLE_HASH}_comments.json")
indicator_json_path = os.path.join(RESULT_OUTPUT_DIR, f"{SAMPLE_HASH}_result.json")
mitre_techniques_file = MITRE_PATH
markdown_output_dir = REPORT_OUTPUT_DIR

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)

def load_mitre_techniques(mitre_techniques_file):
    techniques_data = load_json(mitre_techniques_file)
    return {entry["technique"]: entry["tactic"] for entry in techniques_data}

def extract_file_details(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or len(data) == 0:
        return {}

    file_info = data[0]
    size_kib = round(file_info.get('size', 0) / 1024, 2)
    
    imphash = file_info.get("imphash")
    if not imphash or imphash.lower() == "null":
        for entry in data[1:]: 
            imphash = entry.get("imphash")
            if imphash and imphash.lower() != "null":
                break 
    
    return {
        "Size": f"{size_kib}KiB ({file_info.get('size', 'N/A')} bytes)",
        "Type": file_info.get("type", "N/A"),
        "MD5": file_info.get("md5", "N/A"),
        "SHA256": file_info.get("sha256", "N/A"),
        "SHA1": file_info.get("sha1", "N/A"),
        "IMPHASH": imphash if imphash else "N/A" 
    }

def generate_behavior_description(function_name, indicator_text):
    prompt = [
        SystemMessage(content="You are a malware analysis expert. Generate a detailed behavior analysis based on the provided function and indicators."),
        HumanMessage(content=f"Analyze the following function based on its behavior indicators:\n\nFunction Name: {function_name}\n\nIndicators:\n{indicator_text}\n\n Provide a brief, single-paragraph summary of its behavior.")
    ]
    try:
        response = llm_gpt4omini.invoke(prompt)
        return f"**Behavior Analysis:**\n\n{response.content}\n"
    except Exception as e:
        print(f"LLM API call failed: {e}")
        return "**Behavior Analysis:**\n\nAnalysis unavailable due to API error.\n"

def query_malware_family(data):
    if not isinstance(data, list) or len(data) == 0:
        return "Unknown"

    signature_texts = []
    for entry in data:
        if "signatures" in entry and isinstance(entry["signatures"], list):
            for signature in entry["signatures"]:
                name = signature.get("name", "Unknown Signature")
                description = signature.get("description", "No description available")
                signature_texts.append(f"{name}: {description}")

    signature_info = "\n".join(signature_texts) if signature_texts else "No signature data available."

    prompt_template = PromptTemplate(
        input_variables=["signatures"],
        template=(
            "You are a cybersecurity expert specializing in malware classification. Based on the following indicators, identify the most likely malware family this sample belongs to:\n{signatures}\nProvide only the name of the malware family."
        )
    )

    chain = LLMChain(llm=llm_gpt4o, prompt=prompt_template)
    return chain.run(signatures=signature_info)

def get_malware_family_description(malware_family):
    prompt = f"You are a cybersecurity expert. Provide a brief, high-level summary of the malware family '{malware_family}'. Keep it concise (maximum 150 words)."
    response = llm_gpt4omini.invoke(prompt)
    return response.content if response else "No description available."

def get_mitigation_recommendation(malware_family):
    prompt = f"""You are a threat intelligence analyst. Based on the malware family "{malware_family}", provide recommended mitigation strategies.
Keep the suggestions concise and actionable. Use a bullet-point list format and limit to 5 items."""
    try:
        response = llm_gpt4o.invoke([HumanMessage(content=prompt)])
        return response.content.strip()
    except Exception as e:
        return f"[Error] Failed to generate mitigation: {e}"

def load_ttps(ttp_file, mitre_techniques):
    ttps_data = load_json(ttp_file)
    ttp_sections = []

    idx = 1
    for function_name, entries in ttps_data.items():
        for entry in entries:
            technique = entry.get("technique_name", "Unknown Technique")
            tactic = mitre_techniques.get(technique, "Unknown Tactic")
            procedure_steps = entry.get("generated_procedure", {}).get("procedure", [])

            procedure_description = " ".join([step["description"] for step in procedure_steps])

            section = f"{idx}. **Tactic:** {tactic}  \n   **Technique:** {technique}  \n   **Procedure:** {procedure_description}\n"
            ttp_sections.append(section)
            idx += 1

    return "\n".join(ttp_sections)

def extract_iocs(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or len(data) == 0:
        return {}

    ioc_data = {
        "Domains": set(),
        "Hosts": set(),
        "IPv4": set(),
        "Emails": set(),
        "Registry Keys": set(),
        "Extracted Files": set(),
        "URLs": set(), 
    }

    for entry in data:
        if "domains" in entry and isinstance(entry["domains"], list):
            ioc_data["Domains"].update(entry["domains"])
        if "hosts" in entry and isinstance(entry["hosts"], list):
            ioc_data["Hosts"].update(entry["hosts"])

    ioc_patterns = {
        "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "Emails": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Registry Keys": r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"]+",
        "Extracted Files": r"\b[\w-]+\.(?:exe|dll|sys|tmp|dat|log|bat|cmd|vbs|ps1)\b",
        "URLs": r"https?://[^\s\"\'<>]+|http://[^\s\"\'<>]*\.onion[^\s\"\'<>]*",
    }

    json_string = json.dumps(data, ensure_ascii=False)

    for ioc_type, pattern in ioc_patterns.items():
        matches = re.findall(pattern, json_string)

        if ioc_type == "Emails":
            matches = [email for email in matches if not email.endswith((".DLL", ".dll"))]

        ioc_data[ioc_type].update(matches)

    return {key: sorted(list(values)) for key, values in ioc_data.items()}


def generate_markdown_report(malware_family, malware_description, file_details, function_analysis, ttps, iocs, output_path, mitigations):
    markdown_content = f"# Threat Overview\n\n"
    markdown_content += f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
    
    markdown_content += f"## Malware Family: {malware_family}\n\n"
    markdown_content += f"**Description:** {malware_description}\n\n"

    # General File Information
    markdown_content += "## General File Information\n\n"
    for key, value in file_details.items():
        markdown_content += f"- **{key}:** {value}\n"

    # Technical Analysis
    markdown_content += "\n## Technical Analysis\n\n"
    markdown_content += function_analysis

    markdown_content += "\n## Recommended Mitigations\n\n"
    markdown_content += mitigations + "\n"

    # Tactics, Techniques, and Procedures (TTPs)
    markdown_content += "\n## Tactics, Techniques, and Procedures (TTPs)\n\n"
    markdown_content += ttps

    # Indicators of Compromise (IoC)
    markdown_content += "\n## Indicators of Compromise (IoC)\n\n"
    for key, values in iocs.items():
        markdown_content += f"### {key}\n"
        markdown_content += "\n".join([f"- {v}" for v in values]) if values else "- None detected\n"
        markdown_content += "\n"

    # Save Markdown report
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"Markdown report successfully generated: {output_path}")

def get_markdown_output_path(hash_value, output_dir):
    return os.path.join(output_dir, f"{hash_value}_report.md")

if __name__ == "__main__":
    start_time = time()
    # Load data
    data = load_json(json_data_path)
    comments_data = load_json(comments_json_path)
    comment_lookup = {entry["Function Name"]: entry["Source Code"] for entry in comments_data}
    mitre_techniques = load_mitre_techniques(mitre_techniques_file)
    indicator_data = load_json(indicator_json_path)

    # Extract file details and IoCs
    file_details = extract_file_details(data)

    iocs = extract_iocs(data)

    malware_family = query_malware_family(data)
    malware_description = get_malware_family_description(malware_family)
    ttps = load_ttps(ttp_file, mitre_techniques)

    function_analysis_sections = []
    indicator_function_names = set(indicator_data.keys())
    gpt4o_mini_calls = 0
    
    for function_name, indicators in tqdm(indicator_data.items(), desc="Building Function Descriptions"):
        indicator_texts = "\n".join(ind.get("Indicator", "") for ind in indicators if "Indicator" in ind)
        source_code = comment_lookup.get(function_name, "// Decompiled source code not available.")
        behavior_description = generate_behavior_description(function_name, indicator_texts)

        section = f"### Function: {function_name}\n\n"
        section += "```c\n" + textwrap.indent(textwrap.fill(source_code, width=80), "    ") + "\n```\n\n"
        section += behavior_description + "\n---\n"
        function_analysis_sections.append(section)

        function_analysis = "\n".join(function_analysis_sections)
    # Generate report filename
    markdown_output_file = get_markdown_output_path(SAMPLE_HASH, markdown_output_dir)

    mitigations = get_mitigation_recommendation(malware_family)

    # Generate markdown report
    generate_markdown_report(malware_family, malware_description, file_details, function_analysis, ttps, iocs, markdown_output_file, mitigations)

    end_time = time()
    elapsed = end_time - start_time

    gpt4o_calls = 1 
    gpt4o_mini_calls += 1 

    gpt4o_input_tokens = gpt4o_calls * 600
    gpt4o_output_tokens = gpt4o_calls * 300
    gpt4omini_input_tokens = gpt4o_mini_calls * 700
    gpt4omini_output_tokens = gpt4o_mini_calls * 500

    total_cost = (
        (gpt4o_input_tokens / 1000) * 0.00025 + (gpt4o_output_tokens / 1000) * 0.001 +
        (gpt4omini_input_tokens / 1000) * 0.000015 + (gpt4omini_output_tokens / 1000) * 0.00006
    )

    print("\n📊 Execution Summary")
    print(f"⏱️ Total execution time: {elapsed:.2f} seconds")
    print(f"🔁 gpt-4o calls: {gpt4o_calls}, gpt-4o-mini calls: {gpt4o_mini_calls}")
    print(f"💰 Estimated total cost: ${total_cost:.6f}")