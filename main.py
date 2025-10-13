import json
import os
import argparse
from time import perf_counter
from src.until.config_loader import load_config
from src.models.qwen_model import QwenModel
from src.analyzer.response_analyse import ResponseAnalyzer
from src.analyzer.hybrid_detector import HybridDetector
from src.analyzer.deep_analyzer import DeepAnalyzer
from src.rules.rule_loader import load_rule_engine
from src.until.until import process_file
from src.analyzer.offline_analysis import analyze_results


def main():
    """主函数：两阶段检测流程"""
    
    # ========== 解析命令行参数 ==========
    parser = argparse.ArgumentParser(
        description="URL安全检测系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  1. 完整检测（包含深度分析）:
     python main.py
  
  2. 仅第一阶段检测（跳过深度分析）:
     python main.py --skip-deep-analysis
  
  3. 使用自定义配置:
     python main.py --config custom_config.yaml
        """
    )
    
    parser.add_argument(
        '--skip-deep-analysis',
        action='store_true',
        help='跳过第二阶段深度分析（仅执行快速检测）'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='./config.yaml',
        help='配置文件路径 (默认: ./config.yaml)'
    )
    
    args = parser.parse_args()
    
    # ========== 初始化 ==========
    config = load_config(args.config)
    model = QwenModel(
        model_path=config['model']['path'],
        dtype=config['model']['dtype']
    )
    parser_analyzer = ResponseAnalyzer()
    rule_engine = load_rule_engine(config.get('rules', {}))
    
    # ========== 第一阶段：实时监测（快速判定） ==========
    print(f"\n{'='*60}")
    print(f"⚡ 第一阶段：实时监测 - 快速判定")
    print(f"{'='*60}\n")
    
    detector = HybridDetector(model, parser_analyzer, rule_engine, config)
    stage1_start = perf_counter()
    
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
    
    all_stage1_results = good_results + bad_results
    stage1_elapsed = perf_counter() - stage1_start
    
    # 统计第一阶段结果
    anomalous_results = [r for r in all_stage1_results if r['predicted'] == "1"]
    normal_results = [r for r in all_stage1_results if r['predicted'] == "0"]
    
    print(f"\n{'='*60}")
    print(f"📊 第一阶段统计")
    print(f"{'='*60}")
    print(f"⏱️  总用时: {stage1_elapsed:.2f} 秒")
    print(f"✅ 正常URL: {len(normal_results)} 个")
    print(f"⚠️  异常URL: {len(anomalous_results)} 个")
    print(f"{'='*60}\n")
    
    # 保存第一阶段结果
    output_dir = config['output']['dir']
    os.makedirs(output_dir, exist_ok=True)
    
    stage1_all_file = os.path.join(output_dir, config['output']['stage1_all'])
    with open(stage1_all_file, 'w', encoding='utf-8') as f:
        json.dump(all_stage1_results, f, ensure_ascii=False, indent=2)
    
    # 保存异常URL列表（用于第二阶段）
    stage1_anomalous_file = os.path.join(output_dir, config['output']['stage1_anomalous'])
    with open(stage1_anomalous_file, 'w', encoding='utf-8') as f:
        for item in anomalous_results:
            f.write(f"{item['url']}\n")
    
    print(f"💾 第一阶段结果已保存: {stage1_all_file}")
    print(f"💾 异常URL列表已保存: {stage1_anomalous_file}\n")
    
    # ========== 第二阶段：离线深度分析（可选） ==========
    if args.skip_deep_analysis:
        print(f"\n{'='*60}")
        print(f"⏭️  跳过第二阶段深度分析")
        print(f"{'='*60}")
        print(f"💡 提示: 如需深度分析，请运行以下命令:")
        print(f"   python deep_analysis.py --input {stage1_all_file}")
        print(f"{'='*60}\n")
    else:
        if len(anomalous_results) == 0:
            print("✅ 未检测到异常URL，跳过第二阶段分析")
        else:
            deep_analyzer = DeepAnalyzer(model, parser_analyzer, config)
            stage2_start = perf_counter()
            
            deep_results = deep_analyzer.batch_analyze(anomalous_results)
            
            stage2_elapsed = perf_counter() - stage2_start
            
            # 保存第二阶段结果
            stage2_file = os.path.join(output_dir, config['output']['stage2_deep_analysis'])
            with open(stage2_file, 'w', encoding='utf-8') as f:
                json.dump(deep_results, f, ensure_ascii=False, indent=2)
            
            print(f"\n{'='*60}")
            print(f"📊 第二阶段统计")
            print(f"{'='*60}")
            print(f"⏱️  总用时: {stage2_elapsed:.2f} 秒")
            print(f"📄 深度分析报告已保存: {stage2_file}")
            print(f"{'='*60}\n")
            
            # ========== 总结 ==========
            total_elapsed = stage1_elapsed + stage2_elapsed
            print(f"{'='*60}")
            print(f"🎯 两阶段检测完成")
            print(f"{'='*60}")
            print(f"⏱️  第一阶段用时: {stage1_elapsed:.2f} 秒")
            print(f"⏱️  第二阶段用时: {stage2_elapsed:.2f} 秒")
            print(f"⏱️  总用时: {total_elapsed:.2f} 秒")
            print(f"{'='*60}\n")
    
    # ========== 评估指标 ==========
    analyze_results(all_stage1_results, good_results, bad_results, config['output'])


if __name__ == "__main__":
    main()