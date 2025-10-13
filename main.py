from time import perf_counter
from src.until.config_loader import load_config
from src.models.qwen_model import QwenModel
from src.analyzer.response_analyse import ResponseAnalyzer
from src.analyzer.hybrid_detector import HybridDetector
from src.rules.rule_loader import load_rule_engine
from src.until.until import process_file
from src.analyzer.offline_analysis import analyze_results

def main():
    """主函数"""
    # 加载配置
    config = load_config("./config.yaml")
    
    # 初始化组件
    model = QwenModel(
        model_path=config['model']['path'],
        dtype=config['model']['dtype']
    )
    parser = ResponseAnalyzer()
    rule_engine = load_rule_engine(config.get('rules', {}))
    
    # 初始化混合检测器
    detector = HybridDetector(model, parser, rule_engine, config)
    
    # 开始处理
    total_start = perf_counter()
    
    normal_count, anomalous_count = rule_engine.get_rules_count()
    print(f"\n{'='*60}")
    print(f"🚀 开始URL安全检测")
    print(f"{'='*60}")
    print(f"📋 规则引擎状态: {'启用' if rule_engine.enabled else '禁用'}")
    print(f"📊 正常规则数: {normal_count} 条")
    print(f"📊 异常规则数: {anomalous_count} 条")
    print(f"⚙️  检测策略: 异常规则 > 正常规则 > 模型判断")
    print(f"{'='*60}\n")
    
    # 处理正常URL
    good_results = process_file(
        filename=config['data']['normal_file'],
        label="normal",
        query_func=detector.detect,
        data_dir=config['data']['dir']
    )
    
    # 处理攻击URL
    bad_results = process_file(
        filename=config['data']['attack_file'],
        label="attack",
        query_func=detector.detect,
        data_dir=config['data']['dir']
    )
    
    # 合并结果
    all_results = good_results + bad_results
    
    # 统计检测方法
    rule_only = sum(1 for r in all_results if r.get('detection_method') == 'rule_only')
    model_only = sum(1 for r in all_results if r.get('detection_method') == 'model_only')
    
    total_elapsed = perf_counter() - total_start
    print(f"🎯 全部检测完成,总用时 {total_elapsed:.2f} 秒")
    print(f"📊 检测方法统计:")
    print(f"   - 规则直接判定: {rule_only} 个")
    print(f"   - 模型推理判定: {model_only} 个")
    print(f"   - 规则命中率: {rule_only/len(all_results)*100:.2f}%\n")
    
    # 分析并保存结果
    analyze_results(all_results, good_results, bad_results, config['output'])

if __name__ == "__main__":
    main()