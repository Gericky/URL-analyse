#代码有误，未修正
import os
import json
from collections import defaultdict

def process_atrdf_dataset(input_path, output_dir):
    """
    处理ATRDF数据集JSON文件，提取URL和Attack_Tag
    
    Args:
        input_path: 输入JSON文件路径
        output_dir: 输出目录路径
    """
    try:
        # 读取JSON文件
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 按攻击类型分类存储
        attack_dict = defaultdict(list)
        all_attacks = []
        
        # 遍历数据
        for item in data:
            url = item.get('url', '').strip()
            attack_tag = item.get('Attack_Tag', '').strip()
            
            if not url:
                continue
            
            # 添加到对应攻击类型列表
            if attack_tag:
                # 标准化攻击类型名称（去除空格，转小写，用下划线连接）
                tag_normalized = attack_tag.lower().replace(' ', '_').replace('-', '_')
                attack_dict[tag_normalized].append(url)
                all_attacks.append(url)
        
        # 保存各攻击类型的URL
        stats = {}
        for attack_type, urls in attack_dict.items():
            # 去重
            urls_unique = list(set(urls))
            
            # 保存到文件
            output_path = os.path.join(output_dir, f"{attack_type}.txt")
            with open(output_path, 'w', encoding='utf-8') as f:
                for url in urls_unique:
                    f.write(url + '\n')
            
            stats[attack_type] = {
                'original': len(urls),
                'unique': len(urls_unique),
                'file': output_path
            }
            print(f"✅ {attack_type}: 原始{len(urls)}条 → 去重后{len(urls_unique)}条")
            print(f"   → {output_path}\n")
        
        # 保存所有攻击URL的合并文件
        if all_attacks:
            all_attacks_unique = list(set(all_attacks))
            all_attacks_path = os.path.join(output_dir, "all_attacks.txt")
            with open(all_attacks_path, 'w', encoding='utf-8') as f:
                for url in all_attacks_unique:
                    f.write(url + '\n')
            print(f"✅ 所有攻击URL合并: 原始{len(all_attacks)}条 → 去重后{len(all_attacks_unique)}条")
            print(f"   → {all_attacks_path}\n")
        
        return stats, len(all_attacks_unique)
        
    except Exception as e:
        print(f"❌ 处理文件失败: {e}")
        import traceback
        traceback.print_exc()
        return {}, 0


def main():
    """主函数: 处理ATRDF数据集"""
    
    # 定义路径
    raw_dir = os.path.join(".", "raw", "ATRDF-github")
    output_dir = os.path.join(".", "processed", "ATRDF", "total")
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n{'=' * 60}")
    print(f"📂 ATRDF 数据集处理")
    print(f"{'=' * 60}")
    print(f"📁 输入目录: {os.path.abspath(raw_dir)}")
    print(f"📁 输出目录: {os.path.abspath(output_dir)}")
    print(f"{'=' * 60}\n")
    
    # 查找所有JSON文件
    json_files = []
    for filename in os.listdir(raw_dir):
        if filename.endswith('.json'):
            json_files.append(filename)
    
    if not json_files:
        print("⚠️ 未找到JSON文件")
        return
    
    print(f"📋 找到{len(json_files)}个JSON文件:\n")
    for f in sorted(json_files):
        print(f"   - {f}")
    print()
    
    # 处理每个JSON文件
    total_stats = defaultdict(lambda: {'original': 0, 'unique': 0})
    total_attacks = 0
    
    print(f"{'=' * 60}")
    print(f"📦 开始处理:")
    print(f"{'=' * 60}\n")
    
    for json_file in sorted(json_files):
        input_path = os.path.join(raw_dir, json_file)
        
        print(f"🔍 处理文件: {json_file}")
        print(f"{'─' * 60}")
        
        stats, attack_count = process_atrdf_dataset(input_path, output_dir)
        
        # 累计统计
        for attack_type, stat in stats.items():
            total_stats[attack_type]['original'] += stat['original']
            total_stats[attack_type]['unique'] += stat['unique']
        
        total_attacks += attack_count
        
        print(f"{'─' * 60}\n")
    
    # 输出总体统计
    print(f"{'=' * 60}")
    print(f"✅ 数据处理完成!")
    print(f"{'=' * 60}")
    print(f"📂 输出目录: {os.path.abspath(output_dir)}")
    print(f"\n📊 攻击类型统计:")
    print(f"{'─' * 60}")
    
    for attack_type in sorted(total_stats.keys()):
        stat = total_stats[attack_type]
        print(f"   • {attack_type:30s}: {stat['original']:5d}条 (去重后{stat['unique']:5d}条)")
    
    print(f"{'─' * 60}")
    print(f"   🎯 总计攻击URL数量: {total_attacks}条")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()