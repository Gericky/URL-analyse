"""准备LoRA微调数据集"""
import json
import os
from typing import List, Dict

def load_urls(filepath: str) -> List[str]:
    """加载URL列表"""
    with open(filepath, 'r', encoding='utf-8') as f:
        urls = []
        for line in f:
            line = line.strip()
            if line:
                url = line.split('\t')[0] if '\t' in line else line
                urls.append(url)
        return urls

def create_training_data(normal_urls: List[str], attack_urls: List[str]) -> List[Dict]:
    """创建训练数据(指令微调格式)"""
    data = []
    
    # 正常URL样本
    for url in normal_urls:
        data.append({
            "instruction": "分析以下URL是否存在安全威胁,如果是正常请求返回'normal',如果是攻击返回攻击类型。",
            "input": url,
            "output": "normal"
        })
    
    # 攻击URL样本
    for url in attack_urls:
        # 简单的攻击类型识别
        attack_type = detect_attack_type(url)
        data.append({
            "instruction": "分析以下URL是否存在安全威胁,如果是正常请求返回'normal',如果是攻击返回攻击类型。",
            "input": url,
            "output": attack_type
        })
    
    return data

def detect_attack_type(url: str) -> str:
    """简单的攻击类型检测"""
    url_lower = url.lower()
    
    if any(k in url_lower for k in ['select', 'union', 'or 1=1', '--', 'drop']):
        return "sql_injection"
    elif any(k in url_lower for k in ['<script>', 'alert(', 'onerror=']):
        return "xss"
    elif any(k in url_lower for k in ['../', '..\\', '/etc/passwd']):
        return "path_traversal"
    elif any(k in url_lower for k in ['|', ';', '&&', 'system(', 'exec(']):
        return "command_injection"
    else:
        return "attack"

def main():
    # 加载数据
    normal_urls = load_urls('data/processed/CCF-BDCI2022/total/all_normal.txt')
    attack_urls = load_urls('data/processed/CCF-BDCI2022/total/all_attacks.txt')
    
    print(f"正常URL: {len(normal_urls)} 条")
    print(f"攻击URL: {len(attack_urls)} 条")
    
    # 创建训练数据
    training_data = create_training_data(normal_urls[:5000], attack_urls[:5000])
    
    # 划分训练集和验证集
    split_idx = int(len(training_data) * 0.9)
    train_data = training_data[:split_idx]
    val_data = training_data[split_idx:]
    
    # 保存为JSONL格式
    os.makedirs('data/finetune', exist_ok=True)
    
    with open('data/finetune/train.jsonl', 'w', encoding='utf-8') as f:
        for item in train_data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    with open('data/finetune/val.jsonl', 'w', encoding='utf-8') as f:
        for item in val_data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    print(f"\n✅ 数据准备完成!")
    print(f"训练集: {len(train_data)} 条")
    print(f"验证集: {len(val_data)} 条")

if __name__ == "__main__":
    main()