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
        self.model_config = config.get('model', {})
        
        # ✨ 初始化RAG引擎（用于第二阶段）
        self.use_rag = self.model_config.get('deep_analysis', {}).get('use_rag', False)
        if self.use_rag and config.get('rag', {}).get('enabled', False):
            self.rag_engine = RAGEngine(config['rag'])
            print(f"✅ 第二阶段RAG已启用")
        else:
            self.rag_engine = None
            print(f"⚠️  第二阶段RAG未启用")
        
        # 获取模型信息
        model_info = self.model.get_model_info('deep_analysis')
        self.using_lora = model_info['using_lora']
        
        print(f"\n📋 深度分析器初始化:")
        print(f"   - 使用模型: {'LoRA微调模型' if self.using_lora else '原始模型'}")
        print(f"   - RAG增强: {'启用' if self.use_rag else '禁用'}")
    
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
        start_time = perf_counter()
        
        # 获取攻击类型
        attack_type = stage1_result.get('attack_type', 'unknown') if stage1_result else 'unknown'
        
        # ✨ RAG检索相似案例和知识
        similar_cases = []
        knowledge_context = ""
        
        if self.use_rag and self.rag_engine:
            deep_config = self.model_config.get('deep_analysis', {})
            
            # 检索相似URL案例
            rag_top_k = deep_config.get('rag_top_k', 5)
            similar_cases = self.rag_engine.retrieve_similar_cases(url, top_k=rag_top_k)
            
            # 检索相关知识
            rag_knowledge_top_k = deep_config.get('rag_knowledge_top_k', 3)
            knowledge_context = self.rag_engine.enhance_prompt_with_knowledge(
                url, top_k=rag_knowledge_top_k
            )
            
            if similar_cases:
                print(f"   📚 检索到 {len(similar_cases)} 个相似案例")
            if knowledge_context:
                print(f"   📖 检索到相关攻击知识")
        
        # ✨ 调用模型深度分析（传入RAG增强信息）
        model_result = self.model.deep_analyze(
            url,
            attack_type,
            similar_cases=similar_cases if similar_cases else None,
            knowledge_context=knowledge_context if knowledge_context else None
        )
        
        # 解析响应
        report = self.parser.parse_deep_analysis_response(model_result['response'])
        
        elapsed = perf_counter() - start_time
        
        result = {
            'url': url,
            'attack_type': attack_type,
            'stage1_info': stage1_result,
            'deep_analysis': report,
            'raw_response': model_result['response'],
            'elapsed_time_sec': elapsed
        }
        
        # ✨ 如果使用了RAG，添加相似案例和知识信息
        if similar_cases:
            result['similar_cases'] = similar_cases[:5]  # 只保留前5个
        if knowledge_context:
            result['used_knowledge'] = True
        
        return result
    
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
        
        print(f"\n{'='*60}")
        print(f"🚀 开始批量深度分析 (共 {total} 个异常URL)")
        print(f"{'='*60}")
        
        for i, result in enumerate(anomalous_results, 1):
            print(f"\n[{i}/{total}] ", end='')
            analysis = self.analyze(result['url'], result)
            deep_results.append(analysis)
        
        print(f"\n{'='*60}")
        print(f"✅ 深度分析完成")
        print(f"{'='*60}\n")
        
        return deep_results