import json
import os

def analyze_results(all_results, good_results, bad_results, output_config):
    """
    分析结果并保存
    
    Args:
        all_results: 所有结果列表
        good_results: 正常URL结果列表
        bad_results: 攻击URL结果列表
        output_config: 输出配置字典
    """
    # ========== 混淆矩阵统计 ==========
    tp = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "1")
    tn = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "0")
    fp = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "1")
    fn = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "0")
    
    total = len(all_results)
    
    # 评估指标
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
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
    output_dir = output_config['dir']
    os.makedirs(output_dir, exist_ok=True)
    
    out_all = os.path.join(output_dir, output_config['all_results'])
    out_good = os.path.join(output_dir, output_config['good_results'])
    out_bad = os.path.join(output_dir, output_config['bad_results'])
    
    with open(out_all, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    with open(out_good, "w", encoding="utf-8") as f:
        json.dump(good_results, f, ensure_ascii=False, indent=2)
    with open(out_bad, "w", encoding="utf-8") as f:
        json.dump(bad_results, f, ensure_ascii=False, indent=2)
    
    print(f"\n📁 结果已保存:{out_all}, {out_good}, {out_bad}")