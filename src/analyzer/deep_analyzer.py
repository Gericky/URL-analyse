"""第二阶段深度分析器"""
from typing import List, Dict
from time import perf_counter

# ✨ 新增导入
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
        
        # 构建基础提示词
        base_prompt = self._build_analysis_prompt(url, stage1_result)
        
        # ✨ 使用RAG增强提示词（如果启用）
        if self.use_rag and self.rag_engine:
            enhanced_prompt = self.rag_engine.enhance_prompt(
                url, 
                base_prompt, 
                top_k=self.rag_top_k
            )
        else:
            enhanced_prompt = base_prompt
        
        # 调用模型
        start_time = perf_counter()
        response = self.model.generate(
            enhanced_prompt,
            max_new_tokens=self.config['model']['deep_analysis']['max_new_tokens'],
            temperature=self.config['model']['deep_analysis']['temperature']
        )
        elapsed = perf_counter() - start_time
        
        # 解析响应
        report = self.parser.parse_deep_analysis_response(response)
        
        # ✨ 获取相似案例（如果启用RAG）
        similar_cases = []
        if self.use_rag and self.rag_engine:
            similar_cases = self.rag_engine.retrieve_similar_cases(url, top_k=self.rag_top_k)
        
        return {
            'url': url,
            'stage1_info': stage1_result,
            'deep_analysis': report,
            'similar_cases': similar_cases,
            'raw_response': response,
            'elapsed_time_sec': elapsed
        }
    
    def _build_analysis_prompt(self, url: str, stage1_result: dict = None) -> str:
        """构建分析提示词"""
        prompt = f"""# URL安全深度分析

## 目标URL
{url}

## 初步检测信息
"""
        if stage1_result:
            prompt += f"- 第一阶段判定: {'异常' if stage1_result.get('predicted') == '1' else '正常'}\n"
            if stage1_result.get('attack_type'):
                prompt += f"- 可能的攻击类型: {stage1_result.get('attack_type')}\n"
            if stage1_result.get('rule_matched'):
                rules = stage1_result['rule_matched']
                prompt += f"- 触发规则: {', '.join([r.get('rule_name', '') for r in rules])}\n"
        
        prompt += """
## 分析要求
请按照以下结构进行详细分析:

## 攻击类型
[明确指出具体的攻击类型，如SQL注入、XSS、路径遍历等]

## 简要概述
[一句话总结该URL的主要威胁]

## 行为描述
[描述攻击者试图执行的具体操作]

## 成因分析
[分析为什么这个URL构成威胁]

## 判定依据
[列出具体的判定证据，如特殊字符、关键字等]

## 风险评估
[评估该攻击的严重程度：低/中/高/严重]

## 防护建议
[提供具体的防护措施]
"""
        return prompt
    
    def batch_analyze(self, anomalous_results: List[dict]) -> List[dict]:
        """
        批量深度分析
        
        Args:
            anomalous_results: 第一阶段检测出的异常URL列表
            
        Returns:
            list: 深度分析结果列表
        """
        print(f"\n{'='*60}")
        print(f"📊 第二阶段：深度分析")
        print(f"{'='*60}")
        print(f"待分析URL数: {len(anomalous_results)}")
        print(f"{'='*60}\n")
        
        deep_results = []
        for i, item in enumerate(anomalous_results, 1):
            print(f"[{i}/{len(anomalous_results)}]", end=" ")
            result = self.analyze(item['url'], item)
            deep_results.append(result)
            print(f"✅ 完成，耗时: {result['elapsed_time_sec']:.2f}秒")
        
        return deep_results