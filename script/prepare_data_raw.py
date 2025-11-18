"""
在线检测数据准备脚本 (LoRA-online)
生成指令格式: {"instruction": "...", "input": "...", "output": "..."}
"""
import os
import sys
import json
import random
import re
from collections import defaultdict, Counter
from typing import List, Tuple, Dict

# 添加项目路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ========== 统一标签体系 ==========
STANDARD_LABELS = {
    'Benign': '0|Benign',
    'SQLi': '1|SQLi',
    'XSS': '1|XSS',
    'LFI': '1|LFI',           # Local File Inclusion / Path Traversal
    'RCE': '1|RCE',           # Remote Code Execution
    'CMDi': '1|CMDi',         # Command Injection
}

# ========== 数据源映射配置 ==========
DATA_SOURCE_CONFIG = {
    'CCF-BDCI2022': {
        'base_dir': '../data/processed/CCF-BDCI2022/total',
        'files': {
            'all_normal.txt': 'Benign',
            'sql_injection.txt': 'SQLi',
            'xss.txt': 'XSS',
            'path_traversal.txt': 'LFI',
            'remote_code_execution.txt': 'RCE',
            'command_execution.txt': 'CMDi'
        }
    },
    'WAF-github': {
        'base_dir': '../data/processed/WAF-github/total',
        'files': {
            'sqli_urls.txt': 'SQLi',
            'xss_urls.txt': 'XSS'
        }
    }
}

# ========== 目标样本数配置 ==========
TARGET_SAMPLES_PER_CLASS = {
    'Benign': 10000,
    'SQLi': 10000,
    'XSS': 8000,
    'LFI': 5000,
    'RCE': 5000,
    'CMDi': 5000,
}


def validate_url(url: str) -> bool:
    """
    URL 有效性检查
    
    检查项:
    1. 非空
    2. 包含基本URL特征 (/, ?, &)
    3. 长度合理 (3-2048)
    4. 可编码为UTF-8
    """
    # 1. 非空检查
    if not url or url.isspace():
        return False
    
    # 2. 去除首尾空白
    url = url.strip()
    
    # 3. 基本结构检查
    if not any(char in url for char in ['/', '?', '&', '=']):
        return False
    
    # 4. 长度检查
    if len(url) < 3 or len(url) > 2048:
        return False
    
    # 5. 编码检查
    try:
        url.encode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False
    
    return True


def load_urls_from_file(filepath: str, label: str, source_name: str) -> List[Dict]:
    """
    从文件加载URL并标注标签
    
    Returns:
        List[Dict]: [{'url': str, 'label': str, 'standard_label': str, 'source': str}, ...]
    """
    samples = []
    error_count = 0
    
    if not os.path.exists(filepath):
        print(f"  ⚠️  文件不存在: {filepath}")
        return samples
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # 跳过空行
            if not line:
                continue
            
            # 提取URL（处理 URL\t参数 格式）
            url = line.split('\t')[0] if '\t' in line else line
            
            # URL验证
            if not validate_url(url):
                error_count += 1
                continue
            
            # 获取标准标签
            standard_label = STANDARD_LABELS.get(label)
            if not standard_label:
                print(f"  ❌ 无法映射标签: {label} (文件: {filepath}, 行: {line_num})")
                error_count += 1
                continue
            
            samples.append({
                'url': url,
                'label': label,
                'standard_label': standard_label,
                'source': source_name,
                'file': os.path.basename(filepath)
            })
    
    if error_count > 0:
        print(f"  ⚠️  跳过 {error_count} 条无效样本")
    
    return samples


def deduplicate_samples(samples: List[Dict]) -> List[Dict]:
    """
    去重（保留第一次出现的样本）
    """
    seen_urls = set()
    unique_samples = []
    
    for sample in samples:
        url = sample['url']
        if url not in seen_urls:
            seen_urls.add(url)
            unique_samples.append(sample)
    
    duplicate_count = len(samples) - len(unique_samples)
    if duplicate_count > 0:
        print(f"  🔄 去重: 移除 {duplicate_count} 条重复样本")
    
    return unique_samples


def balance_samples(samples_by_label: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
    """
    数据平衡处理
    
    策略:
    - 样本不足: 重复采样（过采样）
    - 样本过多: 随机下采样
    """
    balanced = {}
    
    for label, samples in samples_by_label.items():
        target_count = TARGET_SAMPLES_PER_CLASS.get(label, 5000)
        current_count = len(samples)
        
        if current_count == 0:
            print(f"  ⚠️  {label}: 无样本，跳过")
            continue
        
        if current_count < target_count:
            # 过采样
            sampled = random.choices(samples, k=target_count)
            print(f"  📈 {label:15s}: {current_count:6d} -> {len(sampled):6d} (过采样)")
        elif current_count > target_count:
            # 下采样
            sampled = random.sample(samples, k=target_count)
            print(f"  📉 {label:15s}: {current_count:6d} -> {len(sampled):6d} (下采样)")
        else:
            sampled = samples
            print(f"  ✅ {label:15s}: {current_count:6d} (无需平衡)")
        
        balanced[label] = sampled
    
    return balanced


def create_training_sample(sample_dict: Dict, sample_id: int) -> Dict:
    """
    创建训练样本（指令格式）
    
    格式:
    {
        "instruction": "判断以下URL是否存在安全威胁",
        "input": "请判断以下URL是否为攻击：/path?x=1\n只需输出检测结果。",
        "output": "1|SQLi"
    }
    """
    url = sample_dict['url']
    standard_label = sample_dict['standard_label']
    
    return {
        'instruction': '判断以下URL是否存在安全威胁',
        'input': f'请判断以下URL是否为攻击：{url}\n只需输出检测结果。',
        'output': standard_label
    }


def save_error_log(errors: List[str], output_dir: str):
    """保存错误日志"""
    if not errors:
        return
    
    log_path = os.path.join(output_dir, 'error.log')
    with open(log_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(errors))
    print(f"\n  📄 错误日志: {log_path} ({len(errors)} 条)")


def main():
    print("=" * 70)
    print("🔧 在线检测数据准备 (LoRA-online)")
    print("=" * 70)
    
    # ========== 加载所有数据源 ==========
    print("\n📂 加载数据源...")
    
    all_samples = []
    load_errors = []
    
    for source_name, config in DATA_SOURCE_CONFIG.items():
        print(f"\n  📦 {source_name}:")
        base_dir = config['base_dir']
        
        for filename, label in config['files'].items():
            filepath = os.path.join(base_dir, filename)
            samples = load_urls_from_file(filepath, label, source_name)
            
            if samples:
                all_samples.extend(samples)
                print(f"    ✅ {filename:30s} → {len(samples):6d} 条 ({label})")
            else:
                load_errors.append(f"加载失败: {filepath}")
    
    print(f"\n📊 原始样本总数: {len(all_samples)} 条")
    
    # ========== 去重 ==========
    print("\n🔄 数据去重...")
    all_samples = deduplicate_samples(all_samples)
    print(f"  去重后总数: {len(all_samples)} 条")
    
    # ========== 按标签分组 ==========
    print("\n📊 按标签分组统计...")
    samples_by_label = defaultdict(list)
    for sample in all_samples:
        samples_by_label[sample['label']].append(sample)
    
    for label, samples in sorted(samples_by_label.items()):
        print(f"  {label:15s}: {len(samples):6d} 条")
    
    # ========== 数据平衡 ==========
    print("\n⚖️  数据平衡处理...")
    balanced_samples = balance_samples(samples_by_label)
    
    # ========== 合并并打乱 ==========
    print("\n🔀 合并并打乱数据...")
    final_samples = []
    for label, samples in balanced_samples.items():
        final_samples.extend(samples)
    
    random.shuffle(final_samples)
    print(f"  最终样本数: {len(final_samples)} 条")
    
    # ========== 生成训练样本 ==========
    print("\n🔄 生成训练样本...")
    training_data = [
        create_training_sample(sample, i)
        for i, sample in enumerate(final_samples)
    ]
    
    # ========== 打印样本预览 ==========
    print("\n📝 样本格式预览:")
    for i, sample in enumerate(training_data[:3], 1):
        print(f"\n  样本 {i}:")
        print(f"    instruction: {sample['instruction']}")
        print(f"    input: {sample['input'][:100]}...")
        print(f"    output: {sample['output']}")
    
    # ========== 划分训练集/验证集 ==========
    print("\n✂️  划分数据集...")
    split_ratio = 0.9
    split_idx = int(len(training_data) * split_ratio)
    
    train_data = training_data[:split_idx]
    val_data = training_data[split_idx:]
    
    print(f"  训练集: {len(train_data):6d} 条 ({split_ratio*100:.0f}%)")
    print(f"  验证集: {len(val_data):6d} 条 ({(1-split_ratio)*100:.0f}%)")
    
    # ========== 保存数据 ==========
    print("\n💾 保存数据...")
    output_dir = './data/finetune_online/raw'
    os.makedirs(output_dir, exist_ok=True)
    
    # 保存训练集
    train_path = os.path.join(output_dir, 'train.jsonl')
    with open(train_path, 'w', encoding='utf-8') as f:
        for sample in train_data:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    print(f"  ✅ {train_path}")
    
    # 保存验证集
    val_path = os.path.join(output_dir, 'val.jsonl')
    with open(val_path, 'w', encoding='utf-8') as f:
        for sample in val_data:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    print(f"  ✅ {val_path}")
    
    # 保存样本预览（按标签分类）
    print("\n📋 生成样本预览...")
    preview_samples = {}
    for label in STANDARD_LABELS.keys():
        matching_samples = [s for s in train_data if s['output'].endswith(label)]
        if matching_samples:
            preview_samples[label] = matching_samples[:5]  # 每个标签保存5个样本
    
    preview_path = os.path.join(output_dir, 'sample_preview.json')
    with open(preview_path, 'w', encoding='utf-8') as f:
        json.dump(preview_samples, f, ensure_ascii=False, indent=2)
    print(f"  ✅ {preview_path}")
    
    # 保存数据统计
    label_distribution = defaultdict(int)
    for sample in training_data:
        output_label = sample['output']  # 如 "1|SQLi"
        label_distribution[output_label] += 1
    
    stats = {
        'total_samples': len(final_samples),
        'train_samples': len(train_data),
        'val_samples': len(val_data),
        'distribution': dict(label_distribution),
        'sources': list(DATA_SOURCE_CONFIG.keys())
    }
    stats_path = os.path.join(output_dir, 'data_stats.json')
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"  ✅ {stats_path}")
    
    # 保存错误日志
    save_error_log(load_errors, output_dir)
    
    # ========== 完成 ==========
    print("\n" + "=" * 70)
    print("✅ 数据准备完成!")
    print("=" * 70)
    
    print("\n📊 数据分布:")
    for output_label, count in sorted(label_distribution.items()):
        percentage = count / len(training_data) * 100
        print(f"  {output_label:15s}: {count:6d} 条 ({percentage:5.1f}%)")
    
    print("\n💡 下一步:")
    print(f"  1. 查看样本预览: {preview_path}")
    print(f"  2. 检查数据统计: {stats_path}")
    print("  3. 运行训练脚本: python script/train_lora_online.py")
    print("=" * 70)


if __name__ == "__main__":
    main()