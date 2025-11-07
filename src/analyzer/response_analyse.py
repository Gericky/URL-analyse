import re

class ResponseAnalyzer:
    """模型响应解析器"""
    
    @staticmethod
    def parse_fast_detection_response(response: str) -> tuple:
        """
        解析快速检测响应
        
        Args:
            response: "0" 或 "1|sql_injection"
            
        Returns:
            tuple: (predicted, attack_type)
        """
        response = response.strip()
        
        # 格式: "0" 或 "1|attack_type"
        if '|' in response:
            parts = response.split('|')
            predicted = parts[0].strip()
            attack_type = parts[1].strip() if len(parts) > 1 else "unknown"
        else:
            predicted = response[0] if response else "0"
            attack_type = "none" if predicted == "0" else "unknown"
        
        # 确保返回值有效
        if predicted not in ["0", "1"]:
            predicted = "0"
        
        return predicted, attack_type
    
    @staticmethod
    def parse_deep_analysis_response(response: str) -> dict:
        """
        解析深度分析响应，提取结构化报告
        
        Returns:
            dict: {
                "attack_type": str,
                "summary": str,
                "behavior": str,
                "cause": str,
                "evidence": str,
                "risk": str,
                "recommendation": str
            }
        """
        report = {
            "attack_type": "",
            "summary": "",
            "behavior": "",
            "cause": "",
            "evidence": "",
            "risk": "",
            "recommendation": ""
        }
        
        # 使用正则提取各部分
        patterns = {
            "attack_type": r'##\s*攻击类型\s*\n(.*?)(?=\n##|\Z)',
            "summary": r'##\s*简要概述\s*\n(.*?)(?=\n##|\Z)',
            "behavior": r'##\s*行为描述\s*\n(.*?)(?=\n##|\Z)',
            "cause": r'##\s*成因分析\s*\n(.*?)(?=\n##|\Z)',
            "evidence": r'##\s*判定依据\s*\n(.*?)(?=\n##|\Z)',
            "risk": r'##\s*风险评估\s*\n(.*?)(?=\n##|\Z)',
            "recommendation": r'##\s*防护建议\s*\n(.*?)(?=\n##|\Z)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, response, re.DOTALL)
            if match:
                report[key] = match.group(1).strip()
        
        return report
    
    # 保留原有方法（如果需要）
    @staticmethod
    def parse_url_detection_response(response: str) -> tuple:
        """原有的详细响应解析（向后兼容）"""
        # ... 保持原代码不变 ...
        pass
    def parse_lora_response(self, response: str) -> dict:
        """
        解析LoRA微调模型的输出（格式: 0|benign 或 1|threat_type）
        
        Args:
            response: 模型原始输出
            
        Returns:
            解析后的结果字典
        """
        response = response.strip()
        
        # 提取 assistant 后的内容（如果存在）
        if "<|im_start|>assistant" in response:
            response = response.split("<|im_start|>assistant")[-1]
            if "<|im_end|>" in response:
                response = response.split("<|im_end|>")[0]
            response = response.strip()
        
        # 解析格式: "0|benign" 或 "1|sql_injection"
        if "|" in response:
            label, threat_type = response.split("|", 1)
            label = label.strip()
            threat_type = threat_type.strip()
        else:
            # 兼容只输出数字的情况
            label = response[0] if response else "0"
            threat_type = "unknown" if label == "1" else "benign"
        
        # 统一格式
        predicted = "0" if label == "0" else "1"
        
        return {
            'predicted': predicted,
            'attack_type': threat_type,
            'confidence': 0.95  # LoRA模型的置信度通常较高
        }