#以0代表正常URL，以1代表异常URL
import os
import torch
import json
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
from time import perf_counter

# === 配置 ===
MODEL_PATH = "./Qwen3-0.6B"  # 本地模型路径
DATA_DIR = "./data"          # 数据文件目录

# === 初始化模型和 tokenizer ===
print("🚀 正在从本地加载 Qwen3-0.6B 模型...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)
print(f"✅ 模型已加载到设备: {model.device}\n")

# === 解析模型回答：得到模型预测(0/1)和理由 ===
def analyze_response(response: str):
    """
    从模型的 response 中抽取：
      - predicted: 模型判定 "0"(正常)/"1"(异常)
      - reason: 仅保留理由文本（去掉开头的"0/1"等），如果模型没给理由则为空字符串
    解析逻辑尽量鲁棒：优先匹配开头的明确回答，否则根据关键词判断。
    """
    text = response.strip()
    # 优先匹配开头明确的 "0" / "1" 或 "回答: 0/1"
    m = re.match(r'^\s*(回答[:：]\s*)?(0|1)\s*[\u3000\s,，\.。.:\-：]*([\s\S]*)', text)
    if m:
        pred = m.group(2)  # "0" 或 "1"
        reason = m.group(3).strip()
        # 如果理由中仍然含有「0/1」开头，再去掉
        reason = re.sub(r'^(0|1)[\s，。:：,-]*', '', reason).strip()
        return pred, reason

    # 若无明确开头，用关键字判断（去掉空格和中文标点便于匹配）
    compact = re.sub(r'[\s，。、""]', '', text)
    if re.search(r'(不是攻击|非攻击|安全|正常)', compact):
        pred = '0'
    elif re.search(r'(是攻击|属于攻击|恶意|异常|SQL注入|XSS|命令注入|攻击)', compact):
        pred = '1'
    else:
        # 默认保守判断为正常
        pred = '0'

    # 清理理由：去掉首部的"0/1"等，再尽量保留后续文字
    reason = re.sub(r'^(回答[:：]\s*)?(0|1)[\s，。:：,-]*', '', text).strip()
    return pred, reason

# === 主检测函数：返回模型预测、理由、用时等信息 ===
def query_model_for_url(url: str) -> dict:
    messages = [
    {
        "role": "system",
        "content": (
            "你是一个专业的Web安全检测系统，负责分析URL请求并识别潜在的安全威胁。"
            "你的任务是判断给定的URL是否包含恶意攻击特征，并给出明确的分类结果。"
            "判定规则："
            "- 输出 0：表示正常URL，即安全的、合法的Web请求"
            "- 输出 1：表示异常URL，即包含攻击特征的恶意请求"
            "攻击特征包括但不限于："
            "• SQL注入：包含 `'`、`--`、`#`、`union`、`select` 等SQL语句"
            "• XSS跨站脚本：包含 `<script>`、`</script>`、`javascript:`、`onerror=` 等"
            "• 命令注入：包含 `|`、`;`、`&&`、shell命令等"
            "• 路径遍历：包含 `../`、`..\\`、`/etc/passwd` 等"
            "• 文件包含：包含 `<?php`、`include`、远程文件路径等"
            "• 其他恶意特征：编码绕过、异常字符、敏感路径访问等"
            "正常请求特征："
            "• 仅包含常规路径和静态资源访问"
            "• 参数值为正常的业务数据，无注入符号"
            "• 符合标准的HTTP请求格式"
            "请基于OWASP Top 10安全标准进行判断，保持高灵敏度但避免误报。"
        )
    },
    {
        "role": "user",
        "content": (
            "请分析以下URL请求，判断其是否为恶意攻击：\n"
            f"URL: {url}\n\n"
            "请按以下格式回答：\n"
            "首先输出分类结果（0或1）：\n"
            "- 0 表示正常URL\n"
            "- 1 表示异常URL\n"
            "然后说明判断理由，包括：\n"
            "- 如果是异常URL（1），请指出具体的攻击类型（如SQL注入、XSS、命令执行、路径遍历等）和恶意特征\n"
            "- 如果是正常URL（0），请说明为何判定为安全请求\n\n"
            "请直接以数字0或1开头回答。"
        )
    }
]

    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
    inputs = tokenizer([text], return_tensors="pt").to(model.device)

    start_time = perf_counter()
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=128,
            do_sample=False,
            temperature=0.0,
            pad_token_id=tokenizer.eos_token_id
        )
    end_time = perf_counter()

    raw_response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()
    predicted, reason = analyze_response(raw_response)
    elapsed = round(end_time - start_time, 3)

    return {
        "url": url,
        "predicted": predicted,             # 模型判定（"0"/"1"）
        "reason": reason,                   # 仅理由（不包含"0/1"）
        "elapsed_time_sec": elapsed,
        "raw_response": raw_response        # 保留原始完整回复以供调试
    }

# === 批量处理文件 ===
def process_file(filename, label):
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        print(f"⚠️ 跳过不存在的文件: {filepath}")
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    print(f"\n📂 开始处理文件: {filename}，共 {len(lines)} 条")
    file_start = perf_counter()
    results = []
    for i, url in enumerate(lines, 1):
        print(f"[{label}] 第 {i}/{len(lines)}: {url}")
        res = query_model_for_url(url)
        # 把真实标签写进去（0为正常，1为攻击）
        res["true_label"] = "1" if label == "attack" else "0"
        results.append(res)
        print(f"  模型判定: {res['predicted']} | 真实标签: {res['true_label']} | 用时: {res['elapsed_time_sec']}s")
        print(f"  理由（简要）: {res['reason']}\n")
    file_elapsed = perf_counter() - file_start
    print(f"⏱️ 文件 {filename} 总用时: {file_elapsed:.2f} 秒\n")
    return results

if __name__ == "__main__":
    total_start = perf_counter()

    # good_results = process_file("good-500.txt", "normal")
    good_results = process_file("good_fromE.txt", "normal")
    bad_results = process_file("bad-500.txt", "attack")

    all_results = good_results + bad_results

    total_elapsed = perf_counter() - total_start
    print(f"🎯 全部检测完成，总用时 {total_elapsed:.2f} 秒")
    
# ========== 详细的混淆矩阵统计 ==========
    # TP (True Positive): 真实是攻击,预测也是攻击 ✅
    tp = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "1")
    
    # TN (True Negative): 真实是正常,预测也是正常 ✅
    tn = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "0")
    
    # FP (False Positive): 真实是正常,预测是攻击 ❌ (误报)
    fp = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "1")
    
    # FN (False Negative): 真实是攻击,预测是正常 ❌ (漏报)
    fn = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "0")
    
    total = len(all_results)
    
    # 准确率 (Accuracy): 所有预测正确的比例
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0
    
    # 召回率 (Recall): 在所有真实攻击中,成功识别的比例
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    
    # 精确率 (Precision): 在所有预测为攻击的样本中,真正是攻击的比例
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
    
    # F1分数: 精确率和召回率的调和平均数
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    # 打印混淆矩阵
    print("=" * 50)
    print("📊 混淆矩阵 (Confusion Matrix)")
    print("=" * 50)
    print(f"{'':12} | 预测:正常(0) | 预测:攻击(1)")
    print("-" * 50)
    print(f"真实:正常(0) |    TN={tn:3d}     |    FP={fp:3d}     (误报)")
    print(f"真实:攻击(1) |    FN={fn:3d}     |    TP={tp:3d}     ")
    print("-" * 50)
    print(f"            |   (漏报)     |   (正确识别)")
    print("=" * 50)
    print()
    
    # 打印评估指标
    print("📈 评估指标")
    print("=" * 50)
    print(f"✅ 准确率 (Accuracy):  {accuracy:.2f}%  = {tp+tn}/{total}")
    print(f"   含义: 所有预测正确的比例")
    print()
    print(f"🎯 召回率 (Recall):    {recall:.2f}%  = {tp}/{tp+fn}")
    print(f"   含义: 在所有真实攻击中,成功识别出的比例")
    print(f"   (也叫真正率,越高越好,表示不漏掉攻击)")
    print()
    print(f"🔍 精确率 (Precision): {precision:.2f}%  = {tp}/{tp+fp}")
    print(f"   含义: 在预测为攻击的样本中,真正是攻击的比例")
    print(f"   (越高越好,表示不误报正常URL)")
    print()
    print(f"⚖️  F1分数 (F1-Score):  {f1:.2f}%")
    print(f"   含义: 精确率和召回率的调和平均,综合评价指标")
    print("=" * 50)
    print()
    
    # 保存结果
    out_all = "./output/slm_results_1000_all.json"
    out_good = "./output/slm_results_500_good.json"
    out_bad = "./output/slm_results_500_bad.json"

    with open(out_all, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    with open(out_good, "w", encoding="utf-8") as f:
        json.dump(good_results, f, ensure_ascii=False, indent=2)
    with open(out_bad, "w", encoding="utf-8") as f:
        json.dump(bad_results, f, ensure_ascii=False, indent=2)

    print(f"\n📁 结果已保存：{out_all}, {out_good}, {out_bad}")