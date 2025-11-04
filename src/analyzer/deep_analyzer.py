"""第二阶段深度分析器"""
from typing import List, Dict
from time import perf_counter

from src.rag.rag_engine import RAGEngine


class DeepAnalyzer:
    """深度分析器 - 对异常URL进行详细分析"""
    
    def __init__(self, model, parser, config):
        """
        初始化深度分析器
        
        Args:
            model: 语言模型实例
            parser: 响应解析器实例
            config: 配置字典
        """
        self.model = model
        self.parser = parser
        self.config = config
        
        # ✨ 初始化RAG引擎
        self.use_rag = config.get('model', {}).get('deep_analysis', {}).get('use_rag', False)
        if self.use_rag and config.get('rag', {}).get('enabled', False):
            self.rag_engine = RAGEngine(config.get('rag', {'enabled': False}))
            self.rag_top_k = config.get('rag', {}).get('deep_analysis', {}).get('top_k', 5)
        else:
            self.rag_engine = None
            self.rag_top_k = 0
    
    def analyze(self, url: str, stage1_result: dict = None) -> dict:
        """
        对单个URL进行深度分析
        
        Args:
            url: 待分析的URL
            stage1_result: 第一阶段检测结果（包含规则匹配等信息）
            
        Returns:
            dict: 深度分析结果
        """
        print(f"\n🔍 深度分析: {url[:80]}...")
        
        # 获取攻击类型
        attack_type = stage1_result.get('attack_type', 'unknown') if stage1_result else 'unknown'
        
        # ✨ 获取相似案例（如果启用RAG）
        similar_cases = []
        if self.use_rag and self.rag_engine:
            similar_cases = self.rag_engine.retrieve_similar_cases(url, top_k=self.rag_top_k)
        
        # ✨ 调用 model.deep_analyze()，不再传递参数（从config读取）
        model_result = self.model.deep_analyze(
            url,
            attack_type,
            similar_cases=similar_cases if similar_cases else None  # RAG增强
        )
        
        # 解析响应
        report = self.parser.parse_deep_analysis_response(model_result['response'])
        
        return {
            'url': url,
            'stage1_info': stage1_result,
            'deep_analysis': report,
            'similar_cases': similar_cases,
            'raw_response': model_result['response'],
            'elapsed_time_sec': model_result['elapsed_time']
        }
    
    def batch_analyze(self, anomalous_results: List[dict]) -> List[dict]:
        """
        批量深度分析异常URL
        
        Args:
            anomalous_results: 第一阶段判定为异常的结果列表
            
        Returns:
            深度分析结果列表
        """
        deep_results = []
        total = len(anomalous_results)
        
        for i, result in enumerate(anomalous_results, 1):
            print(f"\n[{i}/{total}] ", end='')
            analysis = self.analyze(result['url'], result)
            deep_results.append(analysis)
        
        return deep_results