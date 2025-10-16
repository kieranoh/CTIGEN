import pandas as pd
import os
import json

# 파일 로드
input_csv = "/data_add/yejin/behaviormapping/gt_mapping/function-report/Malware Report Generation - Report-function copy.csv"
df = pd.read_csv(input_csv)

# 열 이름 확인 (혹시 모를 대비)
print("Columns:", df.columns.tolist())

function_col = df.columns[0]  # 첫 번째 열: Function 이름
report_col = df.columns[2]    # 세 번째 열: Report 문장

# Malware 이름은 첫 번째 열 이름에서 추출
malware_name = df.columns[0].strip()  # 'Abbadon RAT'


# 샘플별로 데이터 나누기
output_dir = "/data_add/yejin/behaviormapping/gt_mapping/function-report"
os.makedirs(output_dir, exist_ok=True)

# 결과 저장용 딕셔너리
sample_dict = {}

# Function 별로 그룹핑하여 Report 문장 수집
for function_name, group in df.groupby(function_col):
    reports = group[report_col].dropna().tolist()
    if reports:  # 리포트 문장이 있는 경우에만 추가
        sample_dict[function_name] = reports

# JSON으로 저장
output_path = os.path.join(output_dir, f"{malware_name}.json")
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(sample_dict, f, indent=4, ensure_ascii=False)

print(f"Saved: {output_path}")
