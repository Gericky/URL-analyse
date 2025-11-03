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
            severity: 严重程度 (low/medium/high/critical/safe)
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
    """规则引擎 - 支持正常规则和异常规则"""
    
    def __init__(self):
        """初始化规则引擎"""
        self.normal_rules: List[Rule] = []      # 正常URL规则
        self.anomalous_rules: List[Rule] = []   # 异常URL规则
        self.enabled = True
    
    def add_normal_rule(self, rule: Rule):
        """添加正常规则"""
        self.normal_rules.append(rule)
    
    def add_anomalous_rule(self, rule: Rule):
        """添加异常规则"""
        self.anomalous_rules.append(rule)
    
    def load_normal_rules(self, rules_config: List[Dict]):
        """
        加载正常规则
        
        Args:
            rules_config: 规则配置列表
        """
        for config in rules_config:
            rule = Rule(
                rule_id=config.get('id', ''),
                name=config.get('name', ''),
                pattern=config.get('pattern', ''),
                attack_type=config.get('attack_type', 'none'),
                severity=config.get('severity', 'safe'),
                description=config.get('description', '')
            )
            self.add_normal_rule(rule)
    
    def load_anomalous_rules(self, rules_config: List[Dict]):
        """
        加载异常规则
        
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
            self.add_anomalous_rule(rule)
    
    def detect(self, url: str) -> Tuple[Optional[str], List[Dict], str]:
        """
        检测URL - 优先级: 异常规则 > 正常规则 > 无匹配
        
        Args:
            url: 待检测的URL
            
        Returns:
            tuple: (
                判定结果: "0"(正常)/"1"(异常)/None(无匹配,需要模型判断),
                匹配的规则列表,
                规则类型: "normal"/"anomalous"/"none"
            )
        """
        if not self.enabled:
            return None, [], "none"
        
        # 优先检查异常规则 (严格匹配)
        for rule in self.anomalous_rules:
            result = rule.match(url)
            if result:
                return "1", [result], "anomalous"
        
        # 然后检查正常规则
        for rule in self.normal_rules:
            result = rule.match(url)
            if result:
                return "0", [result], "normal"
        
        # 无匹配,需要模型判断
        return None, [], "none"
    def check(self, url: str) -> Dict:
        """
        检查URL是否匹配规则（兼容接口）
        
        Args:
            url: 待检测的URL
            
        Returns:
            dict: {
                'matched': bool,           # 是否匹配到规则
                'is_normal': bool,         # True=正常规则, False=异常规则
                'rules': List[Dict]        # 匹配到的规则详情
            }
        """
        prediction, matched_rules, rule_type = self.detect(url)
        
        if rule_type == "none":
            # 没有匹配到任何规则
            return {
                'matched': False,
                'is_normal': None,
                'rules': []
            }
        elif rule_type == "normal":
            # 匹配到正常规则
            return {
                'matched': True,
                'is_normal': True,
                'rules': matched_rules
            }
        else:  # rule_type == "anomalous"
            # 匹配到异常规则
            return {
                'matched': True,
                'is_normal': False,
                'rules': matched_rules
            }
    def get_detection_summary(self, matched_rules: List[Dict], rule_type: str, 
                            prediction: Optional[str]) -> str:
        """
        生成检测摘要
        
        Args:
            matched_rules: 匹配的规则列表
            rule_type: 规则类型 ("normal"/"anomalous"/"none")
            prediction: 预测结果
            
        Returns:
            检测摘要字符串
        """
        if rule_type == "none":
            return "未匹配到任何规则,需要模型分析"
        
        if not matched_rules:
            return "规则引擎未检测到异常"
        
        rule = matched_rules[0]  # 只会有一条匹配规则
        
        if rule_type == "normal":
            return f"✅ 匹配正常规则 [{rule['rule_id']}]: {rule['description']}"
        elif rule_type == "anomalous":
            return f"⚠️ 匹配异常规则 [{rule['rule_id']}]: {rule['description']} (攻击类型: {rule['attack_type']}, 严重程度: {rule['severity']})"
        
        return "规则检测完成"
    
    def enable(self):
        """启用规则引擎"""
        self.enabled = True
    
    def disable(self):
        """禁用规则引擎"""
        self.enabled = False
    
    def clear_rules(self):
        """清空所有规则"""
        self.normal_rules.clear()
        self.anomalous_rules.clear()
    
    def get_rules_count(self) -> Tuple[int, int]:
        """获取规则数量"""
        return len(self.normal_rules), len(self.anomalous_rules)