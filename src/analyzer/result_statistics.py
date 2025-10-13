"""
结果统计分析模块 - 负责第一阶段和第二阶段检测结果的统计和评估
"""
import json
import os
from typing import List, Dict

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
        
        # 混淆矩阵
        self.tp = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "1")
        self.tn = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "0")
        self.fp = sum(1 for r in all_results if r['true_label'] == "0" and r['predicted'] == "1")
        self.fn = sum(1 for r in all_results if r['true_label'] == "1" and r['predicted'] == "0")
        
        # 检测方法统计
        self.rule_normal_count = sum(1 for r in all_results if r.get('detection_method') == 'rule_normal')
        self.rule_anomalous_count = sum(1 for r in all_results if r.get('detection_method') == 'rule_anomalous')
        self.model_count = sum(1 for r in all_results if r.get('detection_method') == 'model')
    
    def print_stage1_basic_statistics(self, elapsed_time: float):
        """
        打印第一阶段基础统计
        
        Args:
            elapsed_time: 第一阶段用时（秒）
        """
        print(f"\n{'='*60}")
        print(f"📊 第一阶段基础统计")
        print(f"{'='*60}")
        print(f"⏱️  总用时: {elapsed_time:.2f} 秒")
        print(f"📊 总URL数: {len(self.all_results)}")
        print(f"✅ 判定为正常: {len(self.normal_results)} 个")
        print(f"⚠️  判定为异常: {len(self.anomalous_results)} 个")
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
            'fpr': 0.0,  # 误报率
            'fnr': 0.0   # 漏报率
        }
        
        # 准确率
        if total > 0:
            metrics['accuracy'] = (self.tp + self.tn) / total * 100
        
        # 召回率 (真正率)
        if (self.tp + self.fn) > 0:
            metrics['recall'] = self.tp / (self.tp + self.fn) * 100
        
        # 精确率
        if (self.tp + self.fp) > 0:
            metrics['precision'] = self.tp / (self.tp + self.fp) * 100
        
        # F1分数
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = 2 * metrics['precision'] * metrics['recall'] / (metrics['precision'] + metrics['recall'])
        
        # 误报率 (False Positive Rate)
        if (self.fp + self.tn) > 0:
            metrics['fpr'] = self.fp / (self.fp + self.tn) * 100
        
        # 漏报率 (False Negative Rate)
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
        """打印检测方法统计"""
        total = len(self.all_results)
        
        print("\n" + "=" * 60)
        print("🔧 检测方法统计")
        print("=" * 60)
        print(f"📌 规则判定为正常:    {self.rule_normal_count:3d} 个 ({self.rule_normal_count/total*100:.1f}%)")
        print(f"📌 规则判定为异常:    {self.rule_anomalous_count:3d} 个 ({self.rule_anomalous_count/total*100:.1f}%)")
        print(f"📌 模型推理判定:      {self.model_count:3d} 个 ({self.model_count/total*100:.1f}%)")
        print("-" * 60)
        print(f"📊 规则命中率:        {(self.rule_normal_count + self.rule_anomalous_count)/total*100:.1f}%")
        print(f"📊 模型调用率:        {self.model_count/total*100:.1f}%")
        print("=" * 60)
    
    def print_attack_type_distribution(self):
        """打印攻击类型分布"""
        attack_types = {}
        for result in self.anomalous_results:
            attack_type = result.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        if not attack_types:
            return
        
        print("\n" + "=" * 60)
        print("🔍 异常URL攻击类型分布")
        print("=" * 60)
        total_anomalous = len(self.anomalous_results)
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            percentage = count / total_anomalous * 100
            print(f"  {attack_type:20s}: {count:3d} 个 ({percentage:.1f}%)")
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
        metrics_file = os.path.join(self.output_dir, 'stage1_metrics.json')
        metrics = self.calculate_metrics()
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 第一阶段结果已保存: {stage1_all_file}")
        print(f"💾 评估指标已保存: {metrics_file}")
    
    def generate_full_report(self, stage1_elapsed: float):
        """
        生成完整统计报告（包含第一阶段基础统计）
        
        Args:
            stage1_elapsed: 第一阶段用时（秒）
        """
        # 打印第一阶段基础统计
        self.print_stage1_basic_statistics(stage1_elapsed)
        
        # 打印详细评估
        self.print_confusion_matrix()
        self.print_metrics()
        self.print_detection_method_statistics()
        self.print_attack_type_distribution()
        
        # 保存结果
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