from time import perf_counter
from src.until.config_loader import load_config
from src.models.qwen_model import QwenModel
from src.analyzer.response_analyse import ResponseAnalyzer
from src.rules.rule_loader import load_rule_engine
from src.until.until import process_file
from src.analyzer.offline_analysis import analyze_results

def main():
    """主函数"""
    # 加载配置
    config = load_config("./config.yaml")
    
    # 初始化模型和解析器
    model = QwenModel(
        model_path=config['model']['path'],
        dtype=config['model']['dtype']
    )
    parser = ResponseAnalyzer()
    
    # 初始化规则引擎
    rule_engine = load_rule_engine(config.get('rules', {}))
    
    # 创建查询函数(带配置参数、响应解析和规则检测)
    def query_func(url):
        # 1. 规则引擎检测
        rule_prediction, matched_rules = rule_engine.detect(url)
        rule_summary = rule_engine.get_detection_summary(matched_rules)
        
        # 2. 模型推理
        result = model.query(
            url,
            max_new_tokens=config['model']['max_new_tokens'],
            temperature=config['model']['temperature']
        )
        
        # 3. 解析模型响应
        model_prediction, model_reason = parser.parse_url_detection_response(result['raw_response'])
        
        # 4. 组合结果
        result['rule_prediction'] = rule_prediction
        result['rule_matched'] = matched_rules
        result['rule_summary'] = rule_summary
        result['model_prediction'] = model_prediction
        result['model_reason'] = model_reason
        
        # 5. 综合判定 (规则优先策略)
        # 如果规则检测到攻击,则判定为攻击
        result['predicted'] = rule_prediction if rule_prediction == "1" else model_prediction
        
        # 6. 综合理由
        if rule_prediction == "1":
            result['reason'] = f"[规则匹配] {rule_summary} | [模型判断] {model_reason}"
        else:
            result['reason'] = f"[规则通过] {rule_summary} | [模型判断] {model_reason}"
        
        return result
    
    # 开始处理
    total_start = perf_counter()
    
    print(f"\n{'='*60}")
    print(f"🚀 开始URL安全检测")
    print(f"{'='*60}")
    print(f"📋 规则引擎状态: {'启用' if rule_engine.enabled else '禁用'}")
    print(f"📝 已加载规则数: {rule_engine.get_rules_count()}")
    print(f"{'='*60}\n")
    
    # 处理正常URL
    good_results = process_file(
        filename=config['data']['normal_file'],
        label="normal",
        query_func=query_func,
        data_dir=config['data']['dir']
    )
    
    # 处理攻击URL
    bad_results = process_file(
        filename=config['data']['attack_file'],
        label="attack",
        query_func=query_func,
        data_dir=config['data']['dir']
    )
    
    # 合并结果
    all_results = good_results + bad_results
    
    total_elapsed = perf_counter() - total_start
    print(f"🎯 全部检测完成,总用时 {total_elapsed:.2f} 秒\n")
    
    # 分析并保存结果
    analyze_results(all_results, good_results, bad_results, config['output'])

if __name__ == "__main__":
    main()