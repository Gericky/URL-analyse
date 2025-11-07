"""
准备在线检测微调数据集
将 messages 格式转换为指令格式: instruction + input → output
"""

import json
import os

# ========================
# 配置
# ========================

DATA_DIR = "d:/code/URL-analyse/script/data/finetune_online"
TRAIN_PATH = os.path.join(DATA_DIR, "train.jsonl")
VAL_PATH = os.path.join(DATA_DIR, "val.jsonl")

# ========================
# 转换函数
# ========================

def convert_messages_to_instruction(input_file, output_file):
    """
    将 messages 格式转换为指令格式
    
    输入: {"messages": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
    输出: {"instruction": "...", "input": "...", "output": "..."}
    """
    
    print(f"📂 读取文件: {input_file}")
    
    converted_data = []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                item = json.loads(line)
                messages = item.get("messages", [])
                
                # 提取 user 和 assistant 内容
                user_content = ""
                assistant_content = ""
                
                for msg in messages:
                    if msg["role"] == "user":
                        user_content = msg["content"]
                    elif msg["role"] == "assistant":
                        assistant_content = msg["content"]
                
                # 从 user 内容中提取 URL
                # 假设格式类似 "检测URL: http://xxx" 或直接是URL
                url = user_content.strip()
                if ":" in user_content and "http" in user_content.lower():
                    # 提取 http 开头的部分
                    parts = user_content.split()
                    for part in parts:
                        if part.startswith("http"):
                            url = part
                            break
                
                # 构建指令格式
                instruction_item = {
                    "instruction": "判断以下URL是否存在安全威胁",
                    "input": url,
                    "output": assistant_content.strip()
                }
                
                converted_data.append(instruction_item)
                
            except Exception as e:
                print(f"⚠️ 第 {line_num} 行转换失败: {e}")
                continue
    
    # 写入新文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for item in converted_data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    
    print(f"✅ 转换完成: {len(converted_data)} 条数据")
    print(f"💾 保存到: {output_file}")
    
    # 打印示例
    if converted_data:
        print(f"\n📝 转换后的数据示例 (前3条):")
        for i, item in enumerate(converted_data[:3], 1):
            print(f"\n样本 {i}:")
            print(f"  instruction: {item['instruction']}")
            print(f"  input: {item['input'][:80]}...")
            print(f"  output: {item['output']}")

# ========================
# 主函数
# ========================

def main():
    """转换训练集和验证集"""
    
    print("=" * 70)
    print("🔄 开始转换数据集格式")
    print("=" * 70)
    
    # 转换训练集
    print("\n【训练集】")
    convert_messages_to_instruction(TRAIN_PATH, TRAIN_PATH)
    
    # 转换验证集
    print("\n" + "=" * 70)
    print("【验证集】")
    convert_messages_to_instruction(VAL_PATH, VAL_PATH)
    
    print("\n" + "=" * 70)
    print("✅ 所有数据集转换完成!")
    print("=" * 70)
    
    # 验证数据格式
    print("\n🔍 验证数据格式...")
    with open(TRAIN_PATH, 'r', encoding='utf-8') as f:
        sample = json.loads(f.readline())
        required_keys = ["instruction", "input", "output"]
        
        if all(k in sample for k in required_keys):
            print("✅ 数据格式正确!")
            print(f"   包含字段: {list(sample.keys())}")
        else:
            missing = [k for k in required_keys if k not in sample]
            print(f"⚠️ 警告: 缺少字段 {missing}")

if __name__ == "__main__":
    main()