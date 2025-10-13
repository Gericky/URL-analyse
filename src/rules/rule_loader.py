import yaml
import os
from .rule_engine import RuleEngine

def load_rule_engine(config: dict) -> RuleEngine:
    """
    从配置加载规则引擎
    
    Args:
        config: 规则配置字典
        
    Returns:
        RuleEngine: 初始化好的规则引擎
    """
    engine = RuleEngine()
    
    # 检查是否启用
    if not config.get('enabled', True):
        engine.disable()
        print("⚠️ 规则引擎已禁用")
        return engine
    
    # 加载规则文件
    rule_file = config.get('config_file', '')
    if not rule_file or not os.path.exists(rule_file):
        print(f"⚠️ 规则文件不存在或未配置: {rule_file}")
        print("📝 规则引擎将以空规则运行")
        return engine
    
    try:
        with open(rule_file, 'r', encoding='utf-8') as f:
            rules_config = yaml.safe_load(f)
        
        rules_list = rules_config.get('rules', [])
        engine.load_rules(rules_list)
        
        print(f"✅ 规则引擎已加载 {engine.get_rules_count()} 条规则")
        
    except Exception as e:
        print(f"❌ 加载规则文件失败: {e}")
        print("📝 规则引擎将以空规则运行")
    
    return engine