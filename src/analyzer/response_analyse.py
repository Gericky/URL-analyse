import re

class ResponseAnalyzer:
    """模型响应解析器"""
    
    @staticmethod
    def parse_url_detection_response(response: str) -> tuple:
        """
        解析URL检测模型的响应
        
        Args:
            response: 模型原始响应文本
            
        Returns:
            tuple: (predicted, reason) - 预测结果和理由
        """
        text = response.strip()
        
        # 策略1: 优先匹配开头明确的 "0" / "1"
        m = re.match(r'^\s*(回答[:：]\s*)?(0|1)\s*[\u3000\s,，\.。.:\-：]*([\s\S]*)', text)
        if m:
            pred = m.group(2)
            reason = m.group(3).strip()
            reason = re.sub(r'^(0|1)[\s，。:：,-]*', '', reason).strip()
            return pred, reason
        
        # 策略2: 匹配 "- 0" 或 "- 1" 格式
        m2 = re.search(r'[-•]\s*(0|1)\s*表示', text)
        if m2:
            pred = m2.group(1)
            reason_match = re.search(r'判定?理由[:：]?\s*([\s\S]*)', text)
            reason = reason_match.group(1).strip() if reason_match else text
            return pred, reason
        
        # 策略3: 匹配包含数字的行
        m3 = re.search(r'\b(0|1)\s*表示\s*(正常|异常|攻击)', text)
        if m3:
            pred = m3.group(1)
            reason_match = re.search(r'判定?理由[:：]?\s*([\s\S]*)', text)
            reason = reason_match.group(1).strip() if reason_match else text
            return pred, reason
        
        # 策略4: 关键字判断
        compact = re.sub(r'[\s，。、""]', '', text)
        if re.search(r'(不是攻击|非攻击|安全|正常URL|判定为正常)', compact):
            pred = '0'
        elif re.search(r'(是攻击|属于攻击|恶意|异常URL|SQL注入|XSS|命令注入|路径遍历|文件包含|判定为异常)', compact):
            pred = '1'
        else:
            pred = '0'
        
        # 提取理由
        reason_match = re.search(r'判定?理由[:：]?\s*([\s\S]*)', text)
        if reason_match:
            reason = reason_match.group(1).strip()
        else:
            reason = re.sub(r'^[-•]?\s*(0|1)\s*表示[^。\n]*[。\n]?\s*', '', text).strip()
        
        return pred, reason