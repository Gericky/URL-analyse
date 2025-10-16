"""
结果统计分析模块 - 负责第一阶段和第二阶段检测结果的统计和评估
"""
import json
import os
from typing import List, Dict
from time import perf_counter
class ResultStatistics:
    """结果统计分析器"""
    
    def __init__(self, all_results: List[Dict], output_config: Dict):
        """
        初始化统计分析器
        
        Args:
            all_results: 所有检测结果列表
            output_config: 输出配置字典
        """
        self.all_results = all_results
        self.output_config = output_config
        self.output_dir = output_config['dir']
        
        # 分类结果
        self.normal_results = [r for r in all_results if r['predicted'] == "0"]
        self.anomalous_results = [r for r in all_results if r['predicted'] == "1"]
        
        # 按真实标签分类
        self.true_normal_results = [r for r in all_results if r['true_label'] == "0"]
        self.true_attack_results = [r for r in all_results if r['true_label'] == "1"]
        
        # 混淆矩阵
        self.tp = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "1")
        self.tn = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "0")
        self.fp = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "1")
        self.fn = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "0")
        
        # 检测方法统计
        self.rule_normal_count = sum(1 for r in all_results if r.get('detection_method') == 'rule_normal')
        self.rule_anomalous_count = sum(1 for r in all_results if r.get('detection_method') == 'rule_anomalous')
        self.model_count = sum(1 for r in all_results if r.get('detection_method') == 'model')
        
        # 按检测方法分类结果
        self.rule_results = [r for r in all_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]
        self.model_results = [r for r in all_results if r.get('detection_method') == 'model']
        
        # 数据集 + 检测方法交叉统计
        # 正常数据集 (true_label == "0")
        self.normal_by_rule = [r for r in self.true_normal_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]
        self.normal_by_model = [r for r in self.true_normal_results if r.get('detection_method') == 'model']
        
        # 攻击数据集 (true_label == "1")
        self.attack_by_rule = [r for r in self.true_attack_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]
        self.attack_by_model = [r for r in self.true_attack_results if r.get('detection_method') == 'model']
        
        # 错误分析
        self.fp_results = [r for r in all_results if r['true_label'] == "0" and r['predicted'] == "1"]
        self.fn_results = [r for r in all_results if r['true_label'] == "1" and r['predicted'] == "0"]
        # ✨ 新增：时长统计
        self.rule_normal_time = sum(r.get('elapsed_time_sec', 0) for r in all_results if r.get('detection_method') == 'rule_normal')
        self.rule_anomalous_time = sum(r.get('elapsed_time_sec', 0) for r in all_results if r.get('detection_method') == 'rule_anomalous')
        self.model_time = sum(r.get('elapsed_time_sec', 0) for r in all_results if r.get('detection_method') == 'model')
        
        self.total_rule_time = self.rule_normal_time + self.rule_anomalous_time
        self.total_model_time = self.model_time
    
    def print_stage1_basic_statistics(self, elapsed_time: float):
        """
        打印第一阶段基础统计
        
        Args:
            elapsed_time: 第一阶段用时（秒）
        """
        total = len(self.all_results)
        if total == 0:
            print(f"\n{'='*60}")
            print(f"⚠️  警告：没有检测结果")
            print(f"{'='*60}\n")
            return
        
        # 计算实际检测总耗时（规则 + 模型）
        actual_detection_time = self.total_rule_time + self.total_model_time
        overhead_time = elapsed_time - actual_detection_time
        
        print(f"\n{'='*60}")
        print(f"📊 第一阶段基础统计")
        print(f"{'='*60}")
        print(f"⏱️  总运行时间: {elapsed_time:.2f} 秒")
        print(f"   ├─ 实际检测耗时: {actual_detection_time:.4f} 秒 ({actual_detection_time/elapsed_time*100:.1f}%)")
        print(f"   │  ├─ 规则检测: {self.total_rule_time:.4f} 秒")
        print(f"   │  └─ 模型检测: {self.total_model_time:.4f} 秒")
        print(f"   └─ 其他开销: {overhead_time:.4f} 秒 ({overhead_time/elapsed_time*100:.1f}%)")
        print(f"      (文件I/O、数据处理等)")
        print()
        print(f"📊 总URL数: {total}")
        print(f"   平均每URL总耗时: {elapsed_time/total*1000:.2f} 毫秒")
        print(f"   平均每URL检测耗时: {actual_detection_time/total*1000:.2f} 毫秒")
        print()
        print(f"📂 输入数据集:")
        print(f"   正常URL数据集: {len(self.true_normal_results)} 条")
        print(f"   攻击URL数据集: {len(self.true_attack_results)} 条")
        print()
        print(f"🎯 检测结果:")
        print(f"   判定为正常: {len(self.normal_results)} 条")
        print(f"   判定为异常: {len(self.anomalous_results)} 条")
        print(f"{'='*60}")
    
    def calculate_metrics(self) -> Dict:
        """
        计算评估指标
        
        Returns:
            dict: 包含各项评估指标的字典
        """
        total = len(self.all_results)
        
        metrics = {
            'total': total,
            'tp': self.tp,
            'tn': self.tn,
            'fp': self.fp,
            'fn': self.fn,
            'accuracy': 0.0,
            'recall': 0.0,
            'precision': 0.0,
            'f1_score': 0.0,
            'fpr': 0.0,
            'fnr': 0.0
        }
        
        # 准确率
        if total > 0:
            metrics['accuracy'] = (self.tp + self.tn) / total * 100
        
        # 召回率
        if (self.tp + self.fn) > 0:
            metrics['recall'] = self.tp / (self.tp + self.fn) * 100
        
        # 精确率
        if (self.tp + self.fp) > 0:
            metrics['precision'] = self.tp / (self.tp + self.fp) * 100
        
        # F1分数
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * metrics['precision'] * metrics['recall'] / (metrics['precision'] + metrics['recall'])
        
        # 误报率
        if (self.fp + self.tn) > 0:
            metrics['fpr'] = self.fp / (self.fp + self.tn) * 100
        
        # 漏报率
        if (self.fn + self.tp) > 0:
            metrics['fnr'] = self.fn / (self.fn + self.tp) * 100
        
        return metrics
    
    def print_confusion_matrix(self):
        """打印混淆矩阵"""
        print("\n" + "=" * 60)
        print("📊 混淆矩阵 (Confusion Matrix)")
        print("=" * 60)
        print(f"{'':15} | 预测:正常(0) | 预测:攻击(1) | 合计")
        print("-" * 60)
        print(f"真实:正常(0)  |    TN={self.tn:3d}     |    FP={self.fp:3d}     | {self.tn+self.fp:3d}")
        print(f"真实:攻击(1)  |    FN={self.fn:3d}     |    TP={self.tp:3d}     | {self.fn+self.tp:3d}")
        print("-" * 60)
        print(f"合计          |      {self.tn+self.fn:3d}      |      {self.fp+self.tp:3d}      | {len(self.all_results):3d}")
        print("=" * 60)
        print("\n说明:")
        print("  TP (True Positive):  正确识别为攻击")
        print("  TN (True Negative):  正确识别为正常")
        print("  FP (False Positive): 误报 - 正常URL被判定为攻击")
        print("  FN (False Negative): 漏报 - 攻击URL被判定为正常")
    
    def print_metrics(self):
        """打印评估指标"""
        metrics = self.calculate_metrics()
        
        print("\n" + "=" * 60)
        print("📈 评估指标 (Evaluation Metrics)")
        print("=" * 60)
        print(f"✅ 准确率 (Accuracy):   {metrics['accuracy']:.2f}%")
        print(f"   = (TP + TN) / Total = ({self.tp} + {self.tn}) / {metrics['total']}")
        print(f"   含义: 所有预测正确的比例")
        print()
        print(f"🎯 召回率 (Recall):     {metrics['recall']:.2f}%")
        print(f"   = TP / (TP + FN) = {self.tp} / ({self.tp} + {self.fn})")
        print(f"   含义: 在所有真实攻击中,成功识别出的比例")
        print(f"   (也叫真正率 TPR,越高越好,表示不漏掉攻击)")
        print()
        print(f"🔍 精确率 (Precision):  {metrics['precision']:.2f}%")
        print(f"   = TP / (TP + FP) = {self.tp} / ({self.tp} + {self.fp})")
        print(f"   含义: 在预测为攻击的样本中,真正是攻击的比例")
        print(f"   (越高越好,表示不误报正常URL)")
        print()
        print(f"⚖️  F1分数 (F1-Score):   {metrics['f1_score']:.2f}%")
        print(f"   = 2 × (Precision × Recall) / (Precision + Recall)")
        print(f"   含义: 精确率和召回率的调和平均,综合评价指标")
        print()
        print(f"⚠️  误报率 (FPR):       {metrics['fpr']:.2f}%")
        print(f"   = FP / (FP + TN) = {self.fp} / ({self.fp} + {self.tn})")
        print(f"   含义: 正常URL被误判为攻击的比例 (越低越好)")
        print()
        print(f"❌ 漏报率 (FNR):       {metrics['fnr']:.2f}%")
        print(f"   = FN / (FN + TP) = {self.fn} / ({self.fn} + {self.tp})")
        print(f"   含义: 攻击URL被漏判为正常的比例 (越低越好)")
        print("=" * 60)
    
    def print_detection_method_statistics(self):
        """打印检测方法统计（包含时长信息）"""
        total = len(self.all_results)
        
        if total == 0:
            print("\n" + "=" * 60)
            print("🔧 检测方法统计")
            print("=" * 60)
            print("⚠️  没有检测结果可供统计")
            print("=" * 60)
            return
        
        print("\n" + "=" * 60)
        print("🔧 检测方法统计（数量 + 时长）")
        print("=" * 60)
        
        # 规则检测统计
        total_rule_count = self.rule_normal_count + self.rule_anomalous_count
        print(f"\n🔍 规则引擎检测:")
        print(f"   ├─ 总匹配数: {total_rule_count} 条 ({total_rule_count/total*100:.1f}%)")
        print(f"   ├─ 总耗时: {self.total_rule_time:.4f} 秒")
        
        if total_rule_count > 0:
            avg_rule_time = self.total_rule_time / total_rule_count
            print(f"   ├─ 平均耗时: {avg_rule_time*1000:.4f} 毫秒/条")
            print(f"   │")
            print(f"   ├─ 判定为正常: {self.rule_normal_count} 条")
            if self.rule_normal_count > 0:
                print(f"   │  ├─ 耗时: {self.rule_normal_time:.4f} 秒")
                print(f"   │  └─ 平均: {self.rule_normal_time/self.rule_normal_count*1000:.4f} 毫秒/条")
            print(f"   │")
            print(f"   └─ 判定为异常: {self.rule_anomalous_count} 条")
            if self.rule_anomalous_count > 0:
                print(f"      ├─ 耗时: {self.rule_anomalous_time:.4f} 秒")
                print(f"      └─ 平均: {self.rule_anomalous_time/self.rule_anomalous_count*1000:.4f} 毫秒/条")
        
        # 模型检测统计
        print(f"\n🤖 模型推理检测:")
        print(f"   ├─ 检测数量: {self.model_count} 条 ({self.model_count/total*100:.1f}%)")
        print(f"   ├─ 总耗时: {self.total_model_time:.4f} 秒")
        if self.model_count > 0:
            avg_model_time = self.total_model_time / self.model_count
            print(f"   └─ 平均耗时: {avg_model_time*1000:.4f} 毫秒/条")
        
        # 效率对比
        if total_rule_count > 0 and self.model_count > 0:
            avg_rule_time = self.total_rule_time / total_rule_count
            avg_model_time = self.total_model_time / self.model_count
            speedup = avg_model_time / avg_rule_time
            print(f"\n⚡ 效率对比:")
            print(f"   └─ 规则比模型快 {speedup:.2f}x")
        
        # 整体统计
        print(f"\n📊 整体命中率:")
        print(f"   ├─ 规则命中率: {total_rule_count/total*100:.1f}%")
        print(f"   └─ 模型调用率: {self.model_count/total*100:.1f}%")
        
        print("=" * 60)
    
    def print_dataset_method_statistics(self):
        """打印数据集 × 检测方法交叉统计"""
        print("\n" + "=" * 60)
        print("📂 数据集 × 检测方法交叉统计")
        print("=" * 60)
        
        # 正常数据集统计
        total_normal = len(self.true_normal_results)
        normal_rule_count = len(self.normal_by_rule)
        normal_model_count = len(self.normal_by_model)
        
        # 正常数据集的正确识别数
        normal_correct_by_rule = sum(1 for r in self.normal_by_rule if r['predicted'] == "0")
        normal_correct_by_model = sum(1 for r in self.normal_by_model if r['predicted'] == "0")
        
        print(f"\n🟢 正常URL数据集 (共 {total_normal} 条):")
        print(f"   ├─ 规则引擎处理: {normal_rule_count:3d} 条 ({normal_rule_count/total_normal*100:.1f}%)")
        if normal_rule_count > 0:
            print(f"   │  ├─ 正确识别: {normal_correct_by_rule} 条")
            print(f"   │  ├─ 误报(判为攻击): {normal_rule_count - normal_correct_by_rule} 条")
            print(f"   │  └─ 准确率: {normal_correct_by_rule/normal_rule_count*100:.2f}%")
        print(f"   └─ 模型推理处理: {normal_model_count:3d} 条 ({normal_model_count/total_normal*100:.1f}%)")
        if normal_model_count > 0:
            print(f"      ├─ 正确识别: {normal_correct_by_model} 条")
            print(f"      ├─ 误报(判为攻击): {normal_model_count - normal_correct_by_model} 条")
            print(f"      └─ 准确率: {normal_correct_by_model/normal_model_count*100:.2f}%")
        
        # 攻击数据集统计
        total_attack = len(self.true_attack_results)
        attack_rule_count = len(self.attack_by_rule)
        attack_model_count = len(self.attack_by_model)
        
        # 攻击数据集的正确识别数
        attack_correct_by_rule = sum(1 for r in self.attack_by_rule if r['predicted'] == "1")
        attack_correct_by_model = sum(1 for r in self.attack_by_model if r['predicted'] == "1")
        
        print(f"\n🔴 攻击URL数据集 (共 {total_attack} 条):")
        print(f"   ├─ 规则引擎处理: {attack_rule_count:3d} 条 ({attack_rule_count/total_attack*100:.1f}%)")
        if attack_rule_count > 0:
            print(f"   │  ├─ 正确识别: {attack_correct_by_rule} 条")
            print(f"   │  ├─ 漏报(判为正常): {attack_rule_count - attack_correct_by_rule} 条")
            print(f"   │  └─ 准确率: {attack_correct_by_rule/attack_rule_count*100:.2f}%")
        print(f"   └─ 模型推理处理: {attack_model_count:3d} 条 ({attack_model_count/total_attack*100:.1f}%)")
        if attack_model_count > 0:
            print(f"      ├─ 正确识别: {attack_correct_by_model} 条")
            print(f"      ├─ 漏报(判为正常): {attack_model_count - attack_correct_by_model} 条")
            print(f"      └─ 准确率: {attack_correct_by_model/attack_model_count*100:.2f}%")
        
        print("=" * 60)
    
    def print_method_performance_comparison(self):
        """打印检测方法性能对比"""
        print("\n" + "=" * 60)
        print("⚔️  检测方法性能对比")
        print("=" * 60)
        
        # 规则引擎性能
        rule_total = len(self.rule_results)
        if rule_total > 0:
            rule_tp = sum(1 for r in self.rule_results if r['true_label'] == "1" and r['predicted'] == "1")
            rule_tn = sum(1 for r in self.rule_results if r['true_label'] == "0" and r['predicted'] == "0")
            rule_fp = sum(1 for r in self.rule_results if r['true_label'] == "0" and r['predicted'] == "1")
            rule_fn = sum(1 for r in self.rule_results if r['true_label'] == "1" and r['predicted'] == "0")
            
            rule_accuracy = (rule_tp + rule_tn) / rule_total * 100
            rule_fpr = rule_fp / (rule_fp + rule_tn) * 100 if (rule_fp + rule_tn) > 0 else 0
            rule_fnr = rule_fn / (rule_fn + rule_tp) * 100 if (rule_fn + rule_tp) > 0 else 0
            
            print(f"\n📏 规则引擎 (处理 {rule_total} 条):")
            print(f"   ├─ 准确率: {rule_accuracy:.2f}%")
            print(f"   ├─ 误报率: {rule_fpr:.2f}% ({rule_fp}/{rule_fp+rule_tn} 正常URL被误判)")
            print(f"   ├─ 漏报率: {rule_fnr:.2f}% ({rule_fn}/{rule_fn+rule_tp} 攻击URL被漏判)")
            print(f"   └─ 混淆矩阵: TP={rule_tp}, TN={rule_tn}, FP={rule_fp}, FN={rule_fn}")
        else:
            print(f"\n📏 规则引擎: 未处理任何URL")
        
        # 模型推理性能
        model_total = len(self.model_results)
        if model_total > 0:
            model_tp = sum(1 for r in self.model_results if r['true_label'] == "1" and r['predicted'] == "1")
            model_tn = sum(1 for r in self.model_results if r['true_label'] == "0" and r['predicted'] == "0")
            model_fp = sum(1 for r in self.model_results if r['true_label'] == "0" and r['predicted'] == "1")
            model_fn = sum(1 for r in self.model_results if r['true_label'] == "1" and r['predicted'] == "0")
            
            model_accuracy = (model_tp + model_tn) / model_total * 100
            model_fpr = model_fp / (model_fp + model_tn) * 100 if (model_fp + model_tn) > 0 else 0
            model_fnr = model_fn / (model_fn + model_tp) * 100 if (model_fn + model_tp) > 0 else 0
            
            print(f"\n🤖 模型推理 (处理 {model_total} 条):")
            print(f"   ├─ 准确率: {model_accuracy:.2f}%")
            print(f"   ├─ 误报率: {model_fpr:.2f}% ({model_fp}/{model_fp+model_tn} 正常URL被误判)")
            print(f"   ├─ 漏报率: {model_fnr:.2f}% ({model_fn}/{model_fn+model_tp} 攻击URL被漏判)")
            print(f"   └─ 混淆矩阵: TP={model_tp}, TN={model_tn}, FP={model_fp}, FN={model_fn}")
        else:
            print(f"\n🤖 模型推理: 未处理任何URL")
        
        print("=" * 60)
    
    def print_error_analysis(self, max_display: int = 3):
        """
        打印错误分析（终端只显示前几个示例）
        
        Args:
            max_display: 终端显示的最大示例数量（默认3个）
        """
        print("\n" + "=" * 60)
        print("🔍 错误分析")
        print("=" * 60)
        
        # 误报分析 (FP)
        print(f"\n⚠️  误报 (False Positive) - 共 {len(self.fp_results)} 条:")
        if len(self.fp_results) > 0:
            fp_by_rule = [r for r in self.fp_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]
            fp_by_model = [r for r in self.fp_results if r.get('detection_method') == 'model']
            
            print(f"   ├─ 规则引擎误报: {len(fp_by_rule)} 条 ({len(fp_by_rule)/len(self.fp_results)*100:.1f}%)")
            print(f"   └─ 模型推理误报: {len(fp_by_model)} 条 ({len(fp_by_model)/len(self.fp_results)*100:.1f}%)")
            
            # 只显示前几个示例
            display_count = min(max_display, len(self.fp_results))
            print(f"\n   示例（显示前 {display_count} 条，完整列表见: stage1_false_positives.json）:")
            for i, result in enumerate(self.fp_results[:display_count], 1):
                url_display = result['url'][:70] + "..." if len(result['url']) > 70 else result['url']
                print(f"   {i}. {url_display}")
                print(f"      检测方法: {result.get('detection_method', 'unknown')}")
                if result.get('detection_method') in ['rule_normal', 'rule_anomalous']:
                    matched_rules = result.get('matched_rules', [])
                    if matched_rules:
                        rule_names = [r.get('rule_name', 'unknown') for r in matched_rules]
                        print(f"      匹配规则: {', '.join(rule_names)}")
        else:
            print(f"   ✅ 无误报!")
        
        # 漏报分析 (FN)
        print(f"\n❌ 漏报 (False Negative) - 共 {len(self.fn_results)} 条:")
        if len(self.fn_results) > 0:
            fn_by_rule = [r for r in self.fn_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]
            fn_by_model = [r for r in self.fn_results if r.get('detection_method') == 'model']
            
            print(f"   ├─ 规则引擎漏报: {len(fn_by_rule)} 条 ({len(fn_by_rule)/len(self.fn_results)*100:.1f}%)")
            print(f"   └─ 模型推理漏报: {len(fn_by_model)} 条 ({len(fn_by_model)/len(self.fn_results)*100:.1f}%)")
            
            # 只显示前几个示例
            display_count = min(max_display, len(self.fn_results))
            print(f"\n   示例（显示前 {display_count} 条，完整列表见: stage1_false_negatives.json）:")
            for i, result in enumerate(self.fn_results[:display_count], 1):
                url_display = result['url'][:70] + "..." if len(result['url']) > 70 else result['url']
                print(f"   {i}. {url_display}")
                print(f"      检测方法: {result.get('detection_method', 'unknown')}")
                if result.get('detection_method') in ['rule_normal', 'rule_anomalous']:
                    matched_rules = result.get('matched_rules', [])
                    if matched_rules:
                        rule_names = [r.get('rule_name', 'unknown') for r in matched_rules]
                        print(f"      匹配规则: {', '.join(rule_names)}")
        else:
            print(f"   ✅ 无漏报!")
        
        print("=" * 60)
    
    def print_attack_type_distribution(self):
        """打印攻击类型分布"""
        if not self.anomalous_results:
            return
        
        attack_types = {}
        for result in self.anomalous_results:
            attack_type = result.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        print("\n" + "=" * 60)
        print("🎯 异常URL攻击类型分布")
        print("=" * 60)
        total_anomalous = len(self.anomalous_results)
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            percentage = count / total_anomalous * 100
            print(f"  {attack_type:20s}: {count:3d} 条 ({percentage:.1f}%)")
        print("=" * 60)
    
    def save_results(self):
        """保存结果到文件"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 保存第一阶段所有结果
        stage1_all_file = os.path.join(
            self.output_dir, 
            self.output_config.get('stage1_all', 'stage1_realtime_all.json')
        )
        with open(stage1_all_file, 'w', encoding='utf-8') as f:
            json.dump(self.all_results, f, ensure_ascii=False, indent=2)
        
        # 保存评估指标
        metrics = self.calculate_metrics()
        
        # ✨ 新增：时长统计信息
        total_rule_count = self.rule_normal_count + self.rule_anomalous_count
        
        # 扩展指标：添加时长统计
        extended_metrics = {
            **metrics,
            'timing_statistics': {  # ✨ 新增部分
                'rule_engine': {
                    'total_count': total_rule_count,
                    'total_time_sec': round(self.total_rule_time, 6),
                    'avg_time_sec': round(self.total_rule_time / total_rule_count, 6) if total_rule_count > 0 else 0,
                    'avg_time_ms': round(self.total_rule_time / total_rule_count * 1000, 4) if total_rule_count > 0 else 0,
                    'normal_rules': {
                        'count': self.rule_normal_count,
                        'total_time_sec': round(self.rule_normal_time, 6),
                        'avg_time_ms': round(self.rule_normal_time / self.rule_normal_count * 1000, 4) if self.rule_normal_count > 0 else 0
                    },
                    'anomalous_rules': {
                        'count': self.rule_anomalous_count,
                        'total_time_sec': round(self.rule_anomalous_time, 6),
                        'avg_time_ms': round(self.rule_anomalous_time / self.rule_anomalous_count * 1000, 4) if self.rule_anomalous_count > 0 else 0
                    }
                },
                'model_inference': {
                    'total_count': self.model_count,
                    'total_time_sec': round(self.total_model_time, 6),
                    'avg_time_sec': round(self.total_model_time / self.model_count, 6) if self.model_count > 0 else 0,
                    'avg_time_ms': round(self.total_model_time / self.model_count * 1000, 4) if self.model_count > 0 else 0
                },
                'speedup': round(
                    (self.total_model_time / self.model_count) / (self.total_rule_time / total_rule_count),
                    2
                ) if (total_rule_count > 0 and self.model_count > 0) else 0
            },
            'dataset_statistics': {
                'normal_dataset': {
                    'total': len(self.true_normal_results),
                    'by_rule': len(self.normal_by_rule),
                    'by_model': len(self.normal_by_model),
                    'correct_by_rule': sum(1 for r in self.normal_by_rule if r['predicted'] == "0"),
                    'correct_by_model': sum(1 for r in self.normal_by_model if r['predicted'] == "0")
                },
                'attack_dataset': {
                    'total': len(self.true_attack_results),
                    'by_rule': len(self.attack_by_rule),
                    'by_model': len(self.attack_by_model),
                    'correct_by_rule': sum(1 for r in self.attack_by_rule if r['predicted'] == "1"),
                    'correct_by_model': sum(1 for r in self.attack_by_model if r['predicted'] == "1")
                }
            },
            'method_performance': {
                'rule_engine': self._calculate_method_metrics(self.rule_results),
                'model_inference': self._calculate_method_metrics(self.model_results)
            }
        }
        
        metrics_file = os.path.join(self.output_dir, 'stage1_metrics.json')
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(extended_metrics, f, ensure_ascii=False, indent=2)
        
        # ✨ 修改：分别保存误报和漏报到两个独立的 JSON 文件（全部保存）
        # 保存误报案例（False Positives）
        fp_file = os.path.join(self.output_dir, 'stage1_false_positives.json')
        fp_data = {
            'total_count': len(self.fp_results),
            'by_rule': len([r for r in self.fp_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]),
            'by_model': len([r for r in self.fp_results if r.get('detection_method') == 'model']),
            'cases': self.fp_results  # 保存全部误报案例
        }
        with open(fp_file, 'w', encoding='utf-8') as f:
            json.dump(fp_data, f, ensure_ascii=False, indent=2)
        
        # 保存漏报案例（False Negatives）
        fn_file = os.path.join(self.output_dir, 'stage1_false_negatives.json')
        fn_data = {
            'total_count': len(self.fn_results),
            'by_rule': len([r for r in self.fn_results if r.get('detection_method') in ['rule_normal', 'rule_anomalous']]),
            'by_model': len([r for r in self.fn_results if r.get('detection_method') == 'model']),
            'cases': self.fn_results  # 保存全部漏报案例
        }
        with open(fn_file, 'w', encoding='utf-8') as f:
            json.dump(fn_data, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 第一阶段结果已保存: {stage1_all_file}")
        print(f"💾 评估指标已保存: {metrics_file}")
        print(f"💾 误报案例已保存: {fp_file} (共 {len(self.fp_results)} 条)")
        print(f"💾 漏报案例已保存: {fn_file} (共 {len(self.fn_results)} 条)")
    
    def _calculate_method_metrics(self, results: List[Dict]) -> Dict:
        """计算特定方法的指标"""
        if not results:
            return {
                'total': 0,
                'accuracy': 0.0,
                'fpr': 0.0,
                'fnr': 0.0
            }
        
        tp = sum(1 for r in results if r['true_label'] == "1" and r['predicted'] == "1")
        tn = sum(1 for r in results if r['true_label'] == "0" and r['predicted'] == "0")
        fp = sum(1 for r in results if r['true_label'] == "0" and r['predicted'] == "1")
        fn = sum(1 for r in results if r['true_label'] == "1" and r['predicted'] == "0")
        
        total = len(results)
        accuracy = (tp + tn) / total * 100 if total > 0 else 0
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) * 100 if (fn + tp) > 0 else 0
        
        return {
            'total': total,
            'tp': tp,
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'accuracy': round(accuracy, 2),
            'fpr': round(fpr, 2),
            'fnr': round(fnr, 2)
        }
    
    def generate_full_report(self, stage1_elapsed: float):
        """
        生成完整统计报告
        
        Args:
            stage1_elapsed: 第一阶段用时（秒）
        """
        if len(self.all_results) == 0:
            print(f"\n{'='*60}")
            print(f"⚠️  警告：没有检测结果")
            print(f"{'='*60}")
            print(f"请检查:")
            print(f"  1. 数据文件是否存在")
            print(f"  2. 数据文件是否为空")
            print(f"  3. 文件路径配置是否正确")
            print(f"{'='*60}\n")
            return
        
        # 1. 基础统计
        self.print_stage1_basic_statistics(stage1_elapsed)
        
        # 2. 混淆矩阵
        self.print_confusion_matrix()
        
        # 3. 整体评估指标
        self.print_metrics()
        
        # 4. 检测方法统计
        self.print_detection_method_statistics()
        
        # 5. 数据集 × 检测方法交叉统计
        self.print_dataset_method_statistics()
        
        # 6. 检测方法性能对比
        self.print_method_performance_comparison()
        
        # 7. ✨ 修改：错误分析（终端只显示前3个示例）
        self.print_error_analysis(max_display=3)
        
        # 8. 攻击类型分布
        self.print_attack_type_distribution()
        
        # 9. 保存结果（包括全部误报和漏报）
        self.save_results()


def analyze_results(all_results: List[Dict], output_config: Dict, stage1_elapsed: float):
    """
    分析第一阶段结果的便捷函数
    
    Args:
        all_results: 所有检测结果列表
        output_config: 输出配置字典
        stage1_elapsed: 第一阶段用时（秒）
    """
    analyzer = ResultStatistics(all_results, output_config)
    analyzer.generate_full_report(stage1_elapsed)


def print_stage2_statistics(elapsed_time: float, output_file: str, deep_results: List[Dict]):
    """
    打印第二阶段深度分析统计
    
    Args:
        elapsed_time: 第二阶段用时（秒）
        output_file: 输出文件路径
        deep_results: 深度分析结果列表
    """
    if len(deep_results) == 0:
        print(f"\n{'='*60}")
        print(f"⚠️  第二阶段：没有需要深度分析的URL")
        print(f"{'='*60}\n")
        return
    
    print(f"\n{'='*60}")
    print(f"📊 第二阶段统计")
    print(f"{'='*60}")
    print(f"⏱️  总用时: {elapsed_time:.2f} 秒")
    print(f"📈 平均每URL用时: {elapsed_time/len(deep_results):.2f} 秒")
    print(f"📊 深度分析URL数: {len(deep_results)}")
    print(f"💾 深度分析报告已保存: {output_file}")
    print(f"{'='*60}")


def print_two_stage_summary(stage1_elapsed: float, stage2_elapsed: float):
    """
    打印两阶段检测总结
    
    Args:
        stage1_elapsed: 第一阶段用时（秒）
        stage2_elapsed: 第二阶段用时（秒）
    """
    total_elapsed = stage1_elapsed + stage2_elapsed
    print(f"\n{'='*60}")
    print(f"🎯 两阶段检测完成")
    print(f"{'='*60}")
    print(f"⏱️  第一阶段用时: {stage1_elapsed:.2f} 秒")
    print(f"⏱️  第二阶段用时: {stage2_elapsed:.2f} 秒")
    print(f"⏱️  总用时: {total_elapsed:.2f} 秒")
    print(f"{'='*60}\n")