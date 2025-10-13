"""
第二阶段：离线深度分析
"""

class DeepAnalyzer:
    """深度分析器：对异常URL进行详细分析"""
    
    def __init__(self, model, parser, config):
        self.model = model
        self.parser = parser
        self.config = config
    
    def analyze(self, url: str, attack_type: str) -> dict:
        """
        对异常URL进行深度分析
        
        Args:
            url: 待分析的URL
            attack_type: 第一阶段判定的攻击类型
            
        Returns:
            dict: 详细分析报告
        """
        result = self.model.deep_analyze(
            url,
            attack_type,
            max_new_tokens=self.config['model']['deep_analysis']['max_new_tokens'],
            temperature=self.config['model']['deep_analysis']['temperature']
        )
        
        # 解析深度分析响应
        analysis_report = self.parser.parse_deep_analysis_response(
            result['raw_response']
        )
        
        result['analysis_report'] = analysis_report
        result['attack_type'] = attack_type
        
        return result
    
    def batch_analyze(self, anomalous_results: list) -> list:
        """
        批量深度分析
        
        Args:
            anomalous_results: 第一阶段判定为异常的结果列表
            
        Returns:
            list: 深度分析结果列表
        """
        print(f"\n{'='*60}")
        print(f"🔬 第二阶段：离线深度分析")
        print(f"{'='*60}")
        print(f"📊 待分析异常URL数量: {len(anomalous_results)}")
        print(f"{'='*60}\n")
        
        deep_results = []
        for i, item in enumerate(anomalous_results, 1):
            print(f"🔍 [{i}/{len(anomalous_results)}] 深度分析: {item['url']}")
            
            result = self.analyze(item['url'], item['attack_type'])
            result['stage1_result'] = item  # 保留第一阶段结果
            deep_results.append(result)
            
            print(f"   ✅ 分析完成，用时: {result['elapsed_time_sec']}s\n")
        
        return deep_results