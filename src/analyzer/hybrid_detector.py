"""
混合检测器 - 结合规则引擎和LLM模型进行URL安全检测
"""

class HybridDetector:
    """混合检测器:规则引擎 + LLM模型"""
    
    def __init__(self, model, parser, rule_engine, config):
        """
        初始化混合检测器
        
        Args:
            model: 模型实例
            parser: 响应解析器实例
            rule_engine: 规则引擎实例
            config: 配置字典
        """
        self.model = model
        self.parser = parser
        self.rule_engine = rule_engine
        self.config = config
    
    def detect(self, url: str) -> dict:
        """
        执行混合检测
        
        Args:
            url: 待检测的URL
            
        Returns:
            dict: 检测结果字典
        """
        # 1. 规则引擎检测 (优先级最高)
        rule_prediction, matched_rules, rule_type = self.rule_engine.detect(url)
        rule_summary = self.rule_engine.get_detection_summary(
            matched_rules, rule_type, rule_prediction
        )
        
        # 2. 如果规则直接判定,则跳过模型推理
        if rule_prediction is not None:
            return {
                "url": url,
                "predicted": rule_prediction,
                "rule_prediction": rule_prediction,
                "rule_matched": matched_rules,
                "rule_summary": rule_summary,
                "rule_type": rule_type,
                "model_prediction": None,
                "model_reason": "规则直接判定,未调用模型",
                "reason": f"[规则直接判定] {rule_summary}",
                "raw_response": None,
                "elapsed_time_sec": 0,
                "detection_method": "rule_only"
            }
        
        # 3. 规则无法判定,调用模型推理
        result = self.model.query(
            url,
            max_new_tokens=self.config['model']['max_new_tokens'],
            temperature=self.config['model']['temperature']
        )
        
        # 4. 解析模型响应
        model_prediction, model_reason = self.parser.parse_url_detection_response(
            result['raw_response']
        )
        
        # 5. 组合结果
        result['rule_prediction'] = rule_prediction
        result['rule_matched'] = matched_rules
        result['rule_summary'] = rule_summary
        result['rule_type'] = rule_type
        result['model_prediction'] = model_prediction
        result['model_reason'] = model_reason
        result['predicted'] = model_prediction  # 使用模型判断
        result['reason'] = f"[规则无匹配,模型判断] {model_reason}"
        result['detection_method'] = "model_only"
        
        return result