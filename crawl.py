import requests
import json
import requests
import os
import time
from dotenv import load_dotenv


load_dotenv()

def hybridapi2(input_file, output_filename, hashvalue, environment_id = 160):
    
    apikey = os.getenv("HYBRID_API_KEY")
    url = 'https://hybrid-analysis.com/api/v2/submit/file'
    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': apikey
    }

    os.makedirs(output_dir,exist_ok=True)
    
    filename = os.path.basename(input_file)
    with open(input_file , 'rb') as f:
        
        resp = requests.post(url, 
                            headers=headers, 
                            data = {'environment_id' : environment_id}, 
                            files= {'file' : (filename,f)}
                            )
    
    try:
        resp.raise_for_status() 
        response_json = resp.json()

        output_filename = os.path.join(output_dir, f"{hashvalue}_submit.json")

        with open(output_filename, "w", encoding="utf-8") as json_file:
            json.dump(response_json, json_file, indent=2, separators=(",", ":"))

        print(f"Saved to {output_filename}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
  
def get_result(output_filename,hashvalue) :

    output_filename = os.path.join(output_dir, f"{hashvalue}_submit.json")

    apikey = os.getenv("HYBRID_API_KEY")
    url = 'https://hybrid-analysis.com/api/v2/report/'
    headers = {
        'accept': 'application/json',
        'user-agent': 'Falcon Sandbox',
        'api-key': apikey
    }
    with open(output_filename, 'r', encoding='utf-8') as file:
        data = json.load(file)

    job_id = data["job_id"]
    url = f'https://hybrid-analysis.com/api/v2/report/{job_id}/summary'

    try:
        resp = requests.get(url, 
                            headers=headers, 
                            )
        result_filename = os.path.join(output_dir, f"{hashvalue}.json")
        resp.raise_for_status() 
        response_json = resp.json()
        result_filename = os.path.join(output_dir, f"{hashvalue}.json")
        with open(result_filename, "w", encoding="utf-8") as json_file:
            json.dump(response_json, json_file, indent=2, separators=(",", ":"))

        print(f"Get the result! Saved to {result_filename}")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def check_progress(output_filename,hashvalue,interval = 30,timeout = 600):
    output_filename = os.path.join(output_dir, f"{hashvalue}.json")
    start = time.time()
    while True:
        with open(output_filename, 'r', encoding='utf-8') as file:
            data = json.load(file)
        result = data["state"]
        if(result == "SUCCESS" ):
            print("success!")
            return
        elif(result == "ERROR" ):
            print("Error! Wrong Environment id")
            return  
        else:
            print("waiting for analyze...")
            get_result(output_filename,hvalue)

            elapsed = time.time() - start 
            if elapsed >= timeout:
                raise TimeoutError(f"Time out...")
            time.sleep(interval)


SAMPLE_EXE_PATH = os.getenv("SAMPLE_EXE_PATH")
output_dir = os.getenv("HA_OUTPUT_DIR")
hvalue = os.getenv("SAMPLE_HASH")
environment_id = os.getenv("ENVIRONMENT_ID")

hybridapi2(SAMPLE_EXE_PATH, output_dir,hvalue)
get_result(output_dir,hvalue)
check_progress(output_dir,hvalue)