"""混合检测器 - 规则引擎 + LLM"""
from time import perf_counter
from typing import Dict, List

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
        self.model_config = config.get('model', {})
        
        # ✨ 初始化RAG引擎（用于第一阶段）
        self.use_rag = self.model_config.get('fast_detection', {}).get('use_rag', False)
        if self.use_rag and config.get('rag', {}).get('enabled', False):
            self.rag_engine = RAGEngine(config['rag'])
            print(f"✅ 第一阶段RAG已启用")
        else:
            self.rag_engine = None
            print(f"⚠️  第一阶段RAG未启用")
        
        # 获取模型信息
        model_info = self.model.get_model_info('fast_detection')
        self.using_lora = model_info['using_lora']
        
        print(f"\n📋 混合检测器初始化:")
        print(f"   - 使用模型: {'LoRA微调模型' if self.using_lora else '原始模型'}")
        print(f"   - 规则引擎: {'启用' if config.get('rules', {}).get('enabled') else '禁用'}")
        print(f"   - RAG增强: {'启用' if self.use_rag else '禁用'}")
    
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
        
        # ========== 第二步：RAG检索相似案例和知识 ==========
        similar_cases = []
        knowledge_context = ""
        
        if self.use_rag and self.rag_engine:
            fast_config = self.model_config.get('fast_detection', {})
            
            # 检索相似URL案例
            rag_top_k = fast_config.get('rag_top_k', 3)
            similar_cases = self.rag_engine.retrieve_similar_cases(url, top_k=rag_top_k)
            
            # 检索相关知识
            rag_knowledge_top_k = fast_config.get('rag_knowledge_top_k', 2)
            knowledge_context = self.rag_engine.enhance_prompt_with_knowledge(
                url, top_k=rag_knowledge_top_k
            )
            # ✨ 添加调试输出
            if self.config.get('debug', False):
                print(f"\n🔍 RAG检索结果:")
                print(f"   - 相似案例数: {len(similar_cases)}")
                print(f"   - 知识库长度: {len(knowledge_context)} 字符")
                if knowledge_context:
                    print(f"   - 知识预览: {knowledge_context[:200]}...")
            
            # 检查是否有高相似度案例（可直接返回）
            similarity_threshold = self.config.get('rag', {}).get('similarity_threshold', 0.90)
            if similar_cases:
                best_case = similar_cases[0]
                if best_case['similarity_score'] >= similarity_threshold:
                    # 高相似度，直接返回
                    elapsed = perf_counter() - start_time
                    predicted = "1" if best_case['label'] != 'normal' else "0"
                    
                    return {
                        'url': url,
                        'predicted': predicted,
                        'attack_type': best_case['label'],
                        'rule_matched': [],
                        'similar_cases': similar_cases[:3],  # 只返回前3个
                        'detection_method': 'rag_similarity',
                        'confidence': best_case['similarity_score'],
                        'reason': f"与已知{best_case['label']}案例高度相似 (相似度: {best_case['similarity_score']:.2%})",
                        'elapsed_time_sec': elapsed
                    }
        
        # ========== 第三步：模型推理（RAG增强）==========
        # 调用模型，传入RAG检索的信息
        model_result = self.model.fast_detect(
            url,
            similar_cases=similar_cases if similar_cases else None,
            knowledge_context=knowledge_context if knowledge_context else None
        )
        
        # 根据模型类型选择解析方法
        if self.using_lora:
            parsed = self.parser.parse_lora_response(model_result['response'])
            predicted = parsed['predicted']
            attack_type = parsed['attack_type']
        else:
            predicted, attack_type = self.parser.parse_fast_detection_response(
                model_result['response']
            )
        
        elapsed = perf_counter() - start_time
        
        # 确定检测方法
        if self.using_lora:
            detection_method = 'llm_lora_with_rag' if (similar_cases or knowledge_context) else 'llm_lora'
        else:
            detection_method = 'model_with_rag' if (similar_cases or knowledge_context) else 'model'
        
        result = {
            'url': url,
            'predicted': predicted,
            'attack_type': attack_type,
            'rule_matched': [],
            'detection_method': detection_method,
            'reason': f"模型判定: {attack_type}" if predicted == "1" else "模型判定: 正常访问",
            'elapsed_time_sec': elapsed
        }
        
        # 如果使用了RAG，添加相似案例和知识信息
        if similar_cases:
            result['similar_cases'] = similar_cases[:3]  # 只保留前3个
        if knowledge_context:
            result['used_knowledge'] = True
        
        return result