from time import perf_counter
from src.until.config_loader import load_config
from src.models.qwen_model import QwenModel
from src.analyzer.response_analyse import ResponseAnalyzer
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
    
    # 创建查询函数(带配置参数和响应解析)
    def query_func(url):
        result = model.query(
            url,
            max_new_tokens=config['model']['max_new_tokens'],
            temperature=config['model']['temperature']
        )
        # 解析响应
        predicted, reason = parser.parse_url_detection_response(result['raw_response'])
        result['predicted'] = predicted
        result['reason'] = reason
        return result
    
    # 开始处理
    total_start = perf_counter()
    
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