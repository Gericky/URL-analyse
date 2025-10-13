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
    
    # 加载正常规则
    normal_file = config.get('normal_rules_file', '')
    if normal_file and os.path.exists(normal_file):
        try:
            with open(normal_file, 'r', encoding='utf-8') as f:
                normal_config = yaml.safe_load(f)
            
            normal_rules = normal_config.get('rules', [])
            engine.load_normal_rules(normal_rules)
            print(f"✅ 已加载 {len(normal_rules)} 条正常规则")
            
        except Exception as e:
            print(f"❌ 加载正常规则文件失败: {e}")
    else:
        print(f"⚠️ 正常规则文件不存在: {normal_file}")
    
    # 加载异常规则
    anomalous_file = config.get('anomalous_rules_file', '')
    if anomalous_file and os.path.exists(anomalous_file):
        try:
            with open(anomalous_file, 'r', encoding='utf-8') as f:
                anomalous_config = yaml.safe_load(f)
            
            anomalous_rules = anomalous_config.get('rules', [])
            engine.load_anomalous_rules(anomalous_rules)
            print(f"✅ 已加载 {len(anomalous_rules)} 条异常规则")
            
        except Exception as e:
            print(f"❌ 加载异常规则文件失败: {e}")
    else:
        print(f"⚠️ 异常规则文件不存在: {anomalous_file}")
    
    normal_count, anomalous_count = engine.get_rules_count()
    print(f"📊 规则引擎统计: 正常规则 {normal_count} 条, 异常规则 {anomalous_count} 条")
    
    return engine