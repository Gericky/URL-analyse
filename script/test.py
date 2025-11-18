"""
模型评估脚本 - 验证 LoRA 微调效果
"""
import torch
print(torch.__version__)  # 应类似 2.6.0.dev...
print(torch.cuda.is_available())
import os
import json
import torch
from tqdm import tqdm
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

# ========================
# 配置
# ========================

BASE_MODEL = "d:/code/URL-analyse/Qwen3-0.6B"
# LORA_PATH = "d:/code/URL-analyse/script/output/lora_online"
# TEST_DATA = "d:/code/URL-analyse/script/data/finetune_online/test/val.jsonl"
LORA_PATH = "d:/code/URL-analyse/script/output/lora_online_v2"
TEST_DATA = "d:/code/URL-analyse/script/data/finetune_online/raw/test/val.jsonl"
# ========================
# 加载模型
# ========================

print("🚀 加载模型...")

# 从本地加载 tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL,  # 从 base model 加载
    trust_remote_code=True,
    local_files_only=True
)

# 从本地加载 base model
base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    device_map="auto",
    trust_remote_code=True,
    torch_dtype=torch.bfloat16,
    local_files_only=True
)

# 加载 LoRA 权重
model = PeftModel.from_pretrained(
    base_model, 
    LORA_PATH,
    local_files_only=True
)
model.eval()

print("✅ 模型加载完成")

# ========================
# 推理函数
# ========================

PROMPT_TEMPLATE = """<|im_start|>system
你是一个URL安全检测系统,专门识别恶意URL。请判断给定URL是否存在威胁。
输出格式要求: 
- 如果URL安全,输出: 0|benign
- 如果URL存在威胁,输出: 1|威胁类型 (如 phishing, malware, defacement 等)
<|im_end|>
<|im_start|>user
{instruction}
输入URL: {input}<|im_end|>
<|im_start|>assistant
"""

def predict(url, instruction="判断以下URL是否存在安全威胁"):
    """对单个URL进行预测"""
    
    prompt = PROMPT_TEMPLATE.format(
        instruction=instruction,
        input=url
    )
    
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=50,
            do_sample=False,
            # temperature=1.0,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id
            # enable_thinking=False
        )
    
    result = tokenizer.decode(outputs[0], skip_special_tokens=False)
    
    # 提取 assistant 的输出
    if "<|im_start|>assistant" in result:
        prediction = result.split("<|im_start|>assistant")[-1]
        if "<|im_end|>" in prediction:
            prediction = prediction.split("<|im_end|>")[0]
        prediction = prediction.strip()
    else:
        prediction = "ERROR"
    
    return prediction

# ========================
# 批量评估
# ========================
from sklearn.metrics import classification_report

def evaluate_on_test_set(test_file, batch_size=1):
    """在测试集上评估模型（二分类+多类别F1统计）"""

    print(f"\n📂 加载测试数据: {test_file}")
    if not os.path.exists(test_file):
        print(f"❌ 测试文件不存在: {test_file}")
        return None, None

    dataset = load_dataset("json", data_files={"test": test_file})
    test_data = dataset["test"]
    total_samples = len(test_data)
    print(f"✅ 测试样本数: {total_samples}")

    results = []
    total, correct_binary, correct_full = 0, 0, 0
    y_true, y_pred = [], []

    print(f"\n🔍 开始评估 (batch_size={batch_size})...")

    with tqdm(total=total_samples, desc="评估进度") as pbar:
        for i in range(0, total_samples, batch_size):
            end_idx = min(i + batch_size, total_samples)
            batch_items = [test_data[j] for j in range(i, end_idx)]

            for item in batch_items:
                url = item["input"]
                ground_truth = item["output"]
                instruction = item.get("instruction", "判断以下URL是否存在安全威胁")

                prediction = predict(url, instruction)

                # === 记录原始输出 ===
                gt_binary = ground_truth.split("|")[0]
                gt_full = ground_truth.strip()
                pred_binary = prediction.split("|")[0].strip()
                pred_full = prediction.strip()

                # 记录二分类正确性
                if gt_binary == pred_binary:
                    correct_binary += 1

                # 记录完全匹配（包含攻击类型）
                if gt_full == pred_full:
                    correct_full += 1

                y_true.append(gt_full)
                y_pred.append(pred_full)

                results.append({
                    "url": url,
                    "ground_truth": ground_truth,
                    "prediction": prediction,
                    "binary_correct": (gt_binary == pred_binary),
                    "full_correct": (gt_full == pred_full)
                })
                total += 1

            pbar.update(len(batch_items))

    # ======= 指标统计 =======
    acc_binary = correct_binary / total if total else 0
    acc_full = correct_full / total if total else 0

    print("\n" + "=" * 70)
    print("📊 评估结果")
    print("=" * 70)
    print(f"总体准确率（仅看0/1）: {acc_binary:.2%}")
    print(f"完整匹配准确率（含攻击类型）: {acc_full:.2%}")

    # ======= 分类报告（F1/Precision/Recall） =======
    print("\n详细分类报告（按完整标签）:")
    print(classification_report(y_true, y_pred, digits=3, zero_division=0))

    # ======= 错误案例展示 =======
    print("\n" + "=" * 70)
    print("❌ 错误预测案例（前10个）")
    print("=" * 70)
    wrongs = [r for r in results if not r["binary_correct"] or not r["full_correct"]]
    for i, case in enumerate(wrongs[:10], 1):
        print(f"\n{i}. URL: {case['url'][:80]}")
        print(f"   真值: {case['ground_truth']}")
        print(f"   预测: {case['prediction']}")

    # ======= 保存输出 =======
    output_dir = "d:/code/URL-analyse/script/output"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "evaluation_results_detailed.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"\n💾 模型输出已保存到: {output_file}")
    return acc_full, results

# ========================
# 交互式测试
# ========================

def interactive_test():
    """交互式测试模式"""

    print("\n" + "=" * 70)
    print("🎯 交互式测试模式")
    print("=" * 70)
    print("输入 URL 进行检测,输入 'quit' 退出")

    while True:
        url = input("\n请输入URL: ").strip()

        if url.lower() in ['quit', 'exit', 'q']:
            print("👋 退出测试")
            break

        if not url:
            continue

        prediction = predict(url)
        print(f"🔍 检测结果: {prediction}")

# ========================
# 主函数
# ========================

def main():
    evaluate_on_test_set(TEST_DATA)

if __name__ == "__main__":
    main()