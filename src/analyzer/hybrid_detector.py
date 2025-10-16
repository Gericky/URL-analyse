"""
第一阶段：实时监测 - 快速判定
"""
from time import perf_counter

class HybridDetector:
    """混合检测器：规则引擎 + 快速模型检测"""
    
    def __init__(self, model, parser, rule_engine, config):
        self.model = model
        self.parser = parser
        self.rule_engine = rule_engine
        self.config = config
    
    def detect(self, url: str) -> dict:
        """
        第一阶段快速检测
        
        Returns:
            dict: {
                "url": str,
                "predicted": "0"/"1",
                "attack_type": str,
                "detection_method": "rule_normal"/"rule_anomalous"/"model",
                "elapsed_time_sec": float,
                ...
            }
        """
        # 1. 规则引擎检测（计时）
        rule_start = perf_counter()
        rule_prediction, matched_rules, rule_type = self.rule_engine.detect(url)
        rule_elapsed = perf_counter() - rule_start
        
        # 2. 如果匹配到正常规则
        if rule_type == "normal":
            return {
                "url": url,
                "predicted": "0",
                "attack_type": "none",
                "detection_method": "rule_normal",
                "rule_matched": matched_rules,
                "reason": f"✅ 匹配正常规则: {matched_rules[0]['rule_name']}",
                "elapsed_time_sec": rule_elapsed
            }
        
        # 3. 如果匹配到异常规则
        if rule_type == "anomalous":
            return {
                "url": url,
                "predicted": "1",
                "attack_type": matched_rules[0]['attack_type'],
                "detection_method": "rule_anomalous",
                "rule_matched": matched_rules,
                "reason": f"⚠️ 匹配异常规则: {matched_rules[0]['rule_name']}",
                "elapsed_time_sec": rule_elapsed
            }
        
        # 4. 规则无匹配，调用模型快速检测
        result = self.model.fast_detect(
            url,
            max_new_tokens=self.config['model']['fast_detection']['max_new_tokens'],
            temperature=self.config['model']['fast_detection']['temperature']
        )
        
        # 5. 解析快速检测响应
        predicted, attack_type = self.parser.parse_fast_detection_response(
            result['raw_response']
        )
        
        result['predicted'] = predicted
        result['attack_type'] = attack_type
        result['detection_method'] = "model"
        result['rule_matched'] = []
        result['reason'] = f"🤖 模型快速判定: {'异常' if predicted == '1' else '正常'}"
        
        return result