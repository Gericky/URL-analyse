#集中放规则匹配函数（加载 src/rules/rule_store 下的正则/关键字规则）。
import re
from typing import Dict, List, Tuple, Optional

class Rule:
    """单条规则类"""
    
    def __init__(self, rule_id: str, name: str, pattern: str, attack_type: str, 
                 severity: str = "medium", description: str = ""):
        """
        初始化规则
        
        Args:
            rule_id: 规则唯一标识
            name: 规则名称
            pattern: 正则表达式模式
            attack_type: 攻击类型 (如: sql_injection, xss, command_injection等)
            severity: 严重程度 (low/medium/high/critical)
            description: 规则描述
        """
        self.rule_id = rule_id
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.attack_type = attack_type
        self.severity = severity
        self.description = description
    
    def match(self, url: str) -> Optional[Dict]:
        """
        匹配URL
        
        Args:
            url: 待检测的URL
            
        Returns:
            匹配结果字典,如果不匹配返回None
        """
        match = self.pattern.search(url)
        if match:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.name,
                "attack_type": self.attack_type,
                "severity": self.severity,
                "matched_text": match.group(0),
                "description": self.description
            }
        return None


class RuleEngine:
    """规则引擎"""
    
    def __init__(self):
        """初始化规则引擎"""
        self.rules: List[Rule] = []
        self.enabled = True
    
    def add_rule(self, rule: Rule):
        """添加规则"""
        self.rules.append(rule)
    
    def load_rules(self, rules_config: List[Dict]):
        """
        从配置加载规则
        
        Args:
            rules_config: 规则配置列表
        """
        for config in rules_config:
            rule = Rule(
                rule_id=config.get('id', ''),
                name=config.get('name', ''),
                pattern=config.get('pattern', ''),
                attack_type=config.get('attack_type', 'unknown'),
                severity=config.get('severity', 'medium'),
                description=config.get('description', '')
            )
            self.add_rule(rule)
    
    def detect(self, url: str) -> Tuple[str, List[Dict]]:
        """
        检测URL
        
        Args:
            url: 待检测的URL
            
        Returns:
            tuple: (判定结果 "0"或"1", 匹配的规则列表)
        """
        if not self.enabled or not self.rules:
            # 如果规则引擎未启用或无规则,返回正常
            return "0", []
        
        matched_rules = []
        for rule in self.rules:
            result = rule.match(url)
            if result:
                matched_rules.append(result)
        
        # 如果有匹配的规则,判定为攻击
        prediction = "1" if matched_rules else "0"
        return prediction, matched_rules
    
    def get_detection_summary(self, matched_rules: List[Dict]) -> str:
        """
        生成检测摘要
        
        Args:
            matched_rules: 匹配的规则列表
            
        Returns:
            检测摘要字符串
        """
        if not matched_rules:
            return "规则引擎未检测到异常"
        
        attack_types = set(r['attack_type'] for r in matched_rules)
        severities = [r['severity'] for r in matched_rules]
        
        summary = f"规则引擎检测到 {len(matched_rules)} 条匹配规则: "
        summary += f"攻击类型包括 {', '.join(attack_types)}; "
        
        if 'critical' in severities:
            summary += "严重程度: 严重"
        elif 'high' in severities:
            summary += "严重程度: 高"
        elif 'medium' in severities:
            summary += "严重程度: 中"
        else:
            summary += "严重程度: 低"
        
        return summary
    
    def enable(self):
        """启用规则引擎"""
        self.enabled = True
    
    def disable(self):
        """禁用规则引擎"""
        self.enabled = False
    
    def clear_rules(self):
        """清空所有规则"""
        self.rules.clear()
    
    def get_rules_count(self) -> int:
        """获取规则数量"""
        return len(self.rules)