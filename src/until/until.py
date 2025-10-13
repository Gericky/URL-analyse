import os
from time import perf_counter

def process_file(filename, label, query_func, data_dir):
    """
    批量处理文件
    
    Args:
        filename: 文件名
        label: 标签 ("normal"/"attack")
        query_func: 查询模型的函数
        data_dir: 数据目录路径
    
    Returns:
        list: 处理结果列表
    """
    filepath = os.path.join(data_dir, filename)
    if not os.path.exists(filepath):
        print(f"⚠️ 跳过不存在的文件: {filepath}")
        return []
    
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    
    print(f"\n📂 开始处理文件: {filename},共 {len(lines)} 条")
    file_start = perf_counter()
    results = []
    
    for i, url in enumerate(lines, 1):
        print(f"[{label}] 第 {i}/{len(lines)}: {url}")
        res = query_func(url)
        # 把真实标签写进去(0为正常,1为攻击)
        res["true_label"] = "1" if label == "attack" else "0"
        results.append(res)
        print(f"  模型判定: {res['predicted']} | 真实标签: {res['true_label']} | 用时: {res['elapsed_time_sec']}s")
        print(f"  理由(简要): {res['reason']}\n")
    
    file_elapsed = perf_counter() - file_start
    print(f"⏱️ 文件 {filename} 总用时: {file_elapsed:.2f} 秒\n")
    return results