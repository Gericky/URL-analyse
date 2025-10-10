
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

# === 解析模型回答：得到模型预测(是/否)和仅理由 ===
def analyze_response(response: str):
    """
    从模型的 response 中抽取：
      - predicted: 模型判定 "是"/"否"
      - reason: 仅保留理由文本（去掉开头的“是/否”等），如果模型没给理由则为空字符串
    解析逻辑尽量鲁棒：优先匹配开头的明确回答，否则根据关键词判断。
    """
    text = response.strip()
    # 优先匹配开头明确的 "回答: 是 ..." / "是。..." / "否，..."
    m = re.match(r'^\s*(回答[:：]\s*)?(是|否)\s*[\u3000\s,，\.。.:\-：]*([\s\S]*)', text)
    if m:
        pred = '是' if m.group(2) == '是' else '否'
        reason = m.group(3).strip()
        # 如果理由中仍然含有「是/否」开头，再去掉
        reason = re.sub(r'^(是|否)[\s，。:：,-]*', '', reason).strip()
        return pred, reason

    # 若无明确开头，用关键字判断（去掉空格和中文标点便于匹配）
    compact = re.sub(r'[\s，。、“”]', '', text)
    if re.search(r'(不是攻击|非攻击|安全|正常|否)', compact):
        pred = '否'
    elif re.search(r'(是攻击|属于攻击|恶意|SQL注入|XSS|命令注入|攻击)', compact):
        pred = '是'
    else:
        # 默认保守判断为否
        pred = '否'

    # 清理理由：去掉首部的“是/否”等，再尽量保留后续文字
    reason = re.sub(r'^(回答[:：]\s*)?(是|否)[\s，。:：,-]*', '', text).strip()
    return pred, reason

# === 主检测函数：返回模型预测、理由、用时等信息 ===
def query_model_for_url(url: str) -> dict:
    messages = [
    {
        "role": "system",
        "content": (
            "你是一名经验丰富的网络安全专家，专门负责Web安全检测与威胁识别。"
            "你的任务是**严格判断**给定的URL是否包含攻击意图。"
            "请注意：只要URL中存在典型攻击特征就应当判定为恶意攻击请求（如 `../`、`<?php`、`</script>`、`<script>`、`/etc/passwd`、shell命令、注入符号 `'`、`--`、`#`、`;`、`|` 等），"
            "即使该请求尚未执行或结果未知，也应视为恶意攻击请求。"
            "没有出现恶意特征的请求应判定为正常访问。不能过度判定为攻击。"
            "你需要区分三类情况："
            "（1）正常访问：仅路径或静态资源，无参数或可疑字符。"
            "（2）可疑访问：带参数但未出现攻击特征。"
            "（3）攻击访问：包含注入、跨站、远程执行、命令执行、文件包含或目录遍历等迹象。"
            "请基于安全威胁检测标准（OWASP Top 10）作出判断。"
        )
    },
    {
        "role": "user",
        "content": (
            "请判断以下Web请求是否为恶意攻击行为，恶意攻击行为请回答“是”，正常访问请回答“否”：\n"
             f"请求: {url}\n"
            "请仅回答：是或者否，并说明理由。"
            "理由中请指出攻击类型（如SQL注入、XSS、命令执行、路径遍历等），"
            "若无攻击迹象，请说明该URL为何为正常访问。"
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
        "predicted": predicted,             # 模型判定（"是"/"否"）
        "reason": reason,                   # 仅理由（不包含“是/否”）
        "elapsed_time_sec": elapsed,
        "raw_response": raw_response        # 保留原始完整回复以供调试（可删）
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
        # 把真实标签写进去
        res["true_label"] = label  # "attack" 或 "normal"
        # is_attack 字段根据 true_label 决定（按你要求：label为attack即认为它是attack）
        res["is_attack"] = "是" if label == "attack" else "否"
        results.append(res)
        print(f"  模型判定: {res['predicted']} | 真实标签 is_attack: {res['is_attack']} | 用时: {res['elapsed_time_sec']}s")
        print(f"  理由（简要）: {res['reason']}\n")
    file_elapsed = perf_counter() - file_start
    print(f"⏱️ 文件 {filename} 总用时: {file_elapsed:.2f} 秒\n")
    return results

if __name__ == "__main__":
    total_start = perf_counter()

    good_results = process_file("good-10.txt", "normal")
    bad_results = process_file("bad-10.txt", "attack")

    all_results = good_results + bad_results

    total_elapsed = perf_counter() - total_start
    print(f"🎯 全部检测完成，总用时 {total_elapsed:.2f} 秒")
    # 保存结果
    out_all = "./output/slm_results_100_all.json"
    out_good = "./output/slm_results_100_good.json"
    out_bad = "./output/slm_results_100_bad.json"

    with open(out_all, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    with open(out_good, "w", encoding="utf-8") as f:
        json.dump(good_results, f, ensure_ascii=False, indent=2)
    with open(out_bad, "w", encoding="utf-8") as f:
        json.dump(bad_results, f, ensure_ascii=False, indent=2)

    print(f"\n📁 结果已保存：{out_all}, {out_good}, {out_bad}")
