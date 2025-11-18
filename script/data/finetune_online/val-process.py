import json
import re

# 你可以自行修改这些路径
input_path = "./raw/val.jsonl"      # 原始 jsonl 文件路径
normal_path = "./raw/normal.txt"        # 输出正常样本
attack_path = "./raw/attack.txt"        # 输出攻击样本

def extract_url(text):
    """从提示文本中提取URL"""
    # 匹配 "请判断以下URL是否为攻击：" 后面的内容，直到遇到换行或结束
    match = re.search(r'请判断以下URL是否为攻击：(.+?)(?:只需输出检测结果|$)', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()

def split_jsonl_by_label(input_file, normal_file, attack_file):
    with open(input_file, "r", encoding="utf-8") as fin, \
         open(normal_file, "w", encoding="utf-8") as fnorm, \
         open(attack_file, "w", encoding="utf-8") as fattk:
        
        for line in fin:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                input_text = data.get("input", "").strip()
                output = data.get("output", "").strip()
                
                # 提取纯URL
                url = extract_url(input_text)
                
                # 判断是正常(0)还是攻击(1)
                if output.startswith("0"):
                    fnorm.write(url + "\n")
                elif output.startswith("1"):
                    fattk.write(url + "\n")
            except json.JSONDecodeError:
                print("跳过格式错误的行：", line)

if __name__ == "__main__":
    split_jsonl_by_label(input_path, normal_path, attack_path)
    print("处理完成！已生成 normal.txt 与 attack.txt，仅包含URL")