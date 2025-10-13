"""
独立的深度分析脚本
用法: python deep_analysis.py [--input INPUT_FILE] [--output OUTPUT_FILE]
"""

import json
import os
import argparse
from time import perf_counter
from src.until.config_loader import load_config
from src.models.qwen_model import QwenModel
from src.analyzer.response_analyse import ResponseAnalyzer
from src.analyzer.deep_analyzer import DeepAnalyzer
from src.analyzer.result_statistics import print_stage2_statistics  # ✨ 导入统计函数


def load_anomalous_urls(input_file: str):
    """
    从第一阶段结果文件或URL列表文件加载异常URL
    
    Args:
        input_file: 输入文件路径 (.json 或 .txt)
        
    Returns:
        list: 异常URL结果列表
    """
    if not os.path.exists(input_file):
        print(f"❌ 文件不存在: {input_file}")
        return []
    
    # 根据文件扩展名判断文件类型
    _, ext = os.path.splitext(input_file)
    
    if ext == '.json':
        # 从JSON文件加载
        with open(input_file, 'r', encoding='utf-8') as f:
            all_results = json.load(f)
        
        # 筛选出异常URL
        anomalous_results = [r for r in all_results if r.get('predicted') == "1"]
        print(f"📊 从 {input_file} 加载了 {len(anomalous_results)} 个异常URL")
        return anomalous_results
    
    elif ext == '.txt':
        # 从TXT文件加载URL列表
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        # 构造基本结果结构
        anomalous_results = [
            {
                "url": url,
                "predicted": "1",
                "attack_type": "unknown",
                "detection_method": "manual"
            }
            for url in urls
        ]
        print(f"📊 从 {input_file} 加载了 {len(urls)} 个URL")
        return anomalous_results
    
    else:
        print(f"❌ 不支持的文件格式: {ext} (仅支持 .json 或 .txt)")
        return []


def main():
    """主函数：独立深度分析流程"""
    
    # ========== 解析命令行参数 ==========
    parser = argparse.ArgumentParser(
        description="URL安全检测 - 深度分析模块",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  1. 使用默认配置:
     python deep_analysis.py
  
  2. 指定输入文件:
     python deep_analysis.py --input output/stage1_realtime_all.json
  
  3. 指定输入和输出文件:
     python deep_analysis.py --input output/stage1_anomalous.txt --output output/custom_analysis.json
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        type=str,
        default=None,
        help='输入文件路径 (支持 .json 或 .txt 格式)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default=None,
        help='输出文件路径 (默认: output/stage2_deep_analysis.json)'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        default='./config.yaml',
        help='配置文件路径 (默认: ./config.yaml)'
    )
    
    args = parser.parse_args()
    
    # ========== 加载配置 ==========
    config = load_config(args.config)
    
    # 确定输入文件
    if args.input:
        input_file = args.input
    else:
        # 默认使用配置文件中的第一阶段输出
        input_file = os.path.join(
            config['output']['dir'],
            config['output']['stage1_all']
        )
    
    # 确定输出文件
    if args.output:
        output_file = args.output
    else:
        output_file = os.path.join(
            config['output']['dir'],
            config['output']['stage2_deep_analysis']
        )
    
    # ========== 初始化模型 ==========
    print(f"\n{'='*60}")
    print(f"🔬 URL安全检测 - 深度分析模块")
    print(f"{'='*60}")
    print(f"📂 输入文件: {input_file}")
    print(f"📄 输出文件: {output_file}")
    print(f"{'='*60}\n")
    
    model = QwenModel(
        model_path=config['model']['path'],
        dtype=config['model']['dtype']
    )
    parser_analyzer = ResponseAnalyzer()
    
    # ========== 加载异常URL ==========
    anomalous_results = load_anomalous_urls(input_file)
    
    if len(anomalous_results) == 0:
        print("✅ 未找到异常URL，退出深度分析")
        return
    
    # ========== 执行深度分析 ==========
    deep_analyzer = DeepAnalyzer(model, parser_analyzer, config)
    stage2_start = perf_counter()
    
    deep_results = deep_analyzer.batch_analyze(anomalous_results)
    
    stage2_elapsed = perf_counter() - stage2_start
    
    # ========== 保存结果 ==========
    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(deep_results, f, ensure_ascii=False, indent=2)
    
    # ========== 使用统一的统计函数 ==========
    print_stage2_statistics(stage2_elapsed, output_file, deep_results)
    
    # ========== 攻击类型统计 ==========
    attack_type_count = {}
    for result in deep_results:
        attack_type = result.get('attack_type', 'unknown')
        attack_type_count[attack_type] = attack_type_count.get(attack_type, 0) + 1
    
    print(f"\n📊 攻击类型分布:")
    print(f"{'='*60}")
    for attack_type, count in sorted(attack_type_count.items(), key=lambda x: x[1], reverse=True):
        percentage = count / len(deep_results) * 100
        print(f"  {attack_type:20s}: {count:3d} 个 ({percentage:.1f}%)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()