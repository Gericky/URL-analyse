"""混合检测器 - 规则引擎 + LLM"""
from time import perf_counter
from typing import Dict

from src.rag.rag_engine import RAGEngine


class HybridDetector:
    """混合检测器：规则引擎 + 模型推理"""
    
    def __init__(self, model, parser, rule_engine, config):
        """
        初始化混合检测器
        
        Args:
            model: 语言模型实例
            parser: 响应解析器实例
            rule_engine: 规则引擎实例
            config: 配置字典
        """
        self.model = model
        self.parser = parser
        self.rule_engine = rule_engine
        self.config = config
        
        # ✨ 初始化RAG引擎（用于第一阶段）
        self.use_rag = config.get('model', {}).get('fast_detection', {}).get('use_rag', False)
        if self.use_rag and config.get('rag', {}).get('enabled', False):
            self.rag_engine = RAGEngine(config['rag'])
            self.rag_config = config['rag'].get('fast_detection', {})
            print(f"✅ 第一阶段RAG已启用")
        else:
            self.rag_engine = None
            print(f"⚠️  第一阶段RAG未启用")
    
    def detect(self, url: str) -> dict:
        """
        检测URL（规则优先 -> RAG相似度 -> 模型推理）
        
        Args:
            url: 待检测的URL字符串
            
        Returns:
            dict: 检测结果
        """
        start_time = perf_counter()
        
        # ========== 第一步：规则引擎检测 ==========
        rule_result = self.rule_engine.check(url)
        
        if rule_result['matched']:
            elapsed = perf_counter() - start_time
            
            if rule_result['is_normal']:
                # 规则判定为正常
                return {
                    'url': url,
                    'predicted': "0",
                    'attack_type': "none",
                    'rule_matched': rule_result['rules'],
                    'detection_method': 'rule_normal',
                    'reason': f"匹配正常规则: {rule_result['rules'][0]['rule_name']}",
                    'elapsed_time_sec': elapsed
                }
            else:
                # 规则判定为异常
                attack_type = rule_result['rules'][0].get('attack_type', 'unknown')
                return {
                    'url': url,
                    'predicted': "1",
                    'attack_type': attack_type,
                    'rule_matched': rule_result['rules'],
                    'detection_method': 'rule_anomalous',
                    'reason': f"触发异常规则: {rule_result['rules'][0]['rule_name']}",
                    'elapsed_time_sec': elapsed
                }
        
        # ========== 第二步：RAG相似度检测 ==========
        similar_cases = []
        
        if self.use_rag and self.rag_engine:
            # 检索相似案例
            top_k = self.rag_config.get('top_k', 3)
            threshold = self.rag_config.get('similarity_threshold', 0.85)
            
            similar_cases = self.rag_engine.retrieve_similar_cases(url, top_k=top_k)
            
            # 检查是否有高相似度案例
            if similar_cases:
                best_case = similar_cases[0]
                if best_case['similarity_score'] >= threshold:
                    # 高相似度，直接返回
                    elapsed = perf_counter() - start_time
                    predicted = "1" if best_case['label'] == 'attack' else "0"
                    
                    return {
                        'url': url,
                        'predicted': predicted,
                        'attack_type': 'similar_' + best_case['label'],
                        'rule_matched': [],
                        'similar_cases': similar_cases,
                        'detection_method': 'rag_similarity',
                        'confidence': best_case['similarity_score'],
                        'reason': f"与已知{best_case['label']}案例高度相似 (相似度: {best_case['similarity_score']:.2%})",
                        'elapsed_time_sec': elapsed
                    }
        
        # ========== 第三步：模型推理 ==========
        # ✨ 调用 model.fast_detect()，不再传递参数（从config读取）
        model_result = self.model.fast_detect(
            url,
            similar_cases=similar_cases if similar_cases else None  # RAG增强
        )
        
        # 解析响应
        predicted, attack_type = self.parser.parse_fast_detection_response(
            model_result['response']
        )
        elapsed = perf_counter() - start_time
        
        result = {
            'url': url,
            'predicted': predicted,
            'attack_type': attack_type,
            'rule_matched': [],
            'detection_method': 'model_with_rag' if similar_cases else 'model',
            'reason': f"模型判定: {attack_type}" if predicted == "1" else "模型判定: 正常访问",
            'elapsed_time_sec': elapsed
        }
        
        # 如果使用了RAG，添加相似案例信息
        if similar_cases:
            result['similar_cases'] = similar_cases
        
        return result