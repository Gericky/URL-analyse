import os
import json
from glob import glob
from collections import defaultdict

def process_atrdf():
    """处理ATRDF数据集，按攻击类型提取URL"""
    
    # 定义路径
    raw_dir = 'raw/ATRDF-github/train'
    total_dir = 'processed/ATRDF/total'
    
    # 确保输出目录存在
    os.makedirs(total_dir, exist_ok=True)
    
    # 存储按攻击类型分类的URL (使用set自动去重)
    attack_urls = defaultdict(set)
    
    # 获取所有JSON文件
    json_files = glob(os.path.join(raw_dir, '*.json'))
    
    if not json_files:
        print(f"❌ 未找到JSON文件: {raw_dir}")
        return
    
    print(f"找到 {len(json_files)} 个JSON文件\n")
    
    # 处理每个文件
    total_records = 0
    skipped_records = 0
    skip_reasons = defaultdict(int)  # 统计跳过原因
    
    for json_file in json_files:
        print(f"处理文件: {os.path.basename(json_file)}")
        
        try:
            # 尝试多种编码
            content = None
            for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'gbk']:
                try:
                    with open(json_file, 'r', encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            
            if not content:
                print(f"  ⚠️  无法读取文件")
                continue
            
            # 尝试解析JSON
            data = []
            try:
                # 先尝试作为JSON数组
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    data = [parsed]  # 单个对象转为列表
                elif isinstance(parsed, list):
                    data = parsed
            except json.JSONDecodeError:
                # 如果失败，尝试按行解析(JSONL格式)
                for line_num, line in enumerate(content.strip().split('\n'), 1):
                    line = line.strip().rstrip(',')
                    if line:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            skip_reasons[f'JSON解析失败(行{line_num})'] += 1
                            continue
            
            print(f"  📦 解析到 {len(data)} 条记录")
            
            # 提取URL和攻击类型
            file_count = 0
            file_skip = 0
            
            for idx, record in enumerate(data, 1):
                try:
                    # 提取URL
                    url = None
                    if 'request' in record:
                        url = record['request'].get('url')
                    elif 'url' in record:
                        url = record['url']
                    
                    # 提取攻击类型
                    attack_tag = None
                    if 'request' in record:
                        attack_tag = record['request'].get('Attack_Tag')
                    elif 'Attack_Tag' in record:
                        attack_tag = record['Attack_Tag']
                    
                    # 调试输出（前几条）
                    if idx <= 3:
                        print(f"    记录{idx}: URL={'有' if url else '无'}, Attack_Tag={attack_tag or '无'}")
                    
                    # 验证和清理
                    if not url:
                        skip_reasons['缺少URL'] += 1
                        file_skip += 1
                        continue
                    
                    if not attack_tag:
                        skip_reasons['缺少Attack_Tag'] += 1
                        file_skip += 1
                        continue
                    
                    # 去除末尾的 HTTP/1.1
                    url = url.strip()
                    if url.endswith(' HTTP/1.1'):
                        url = url[:-9].strip()
                    
                    # 标准化攻击类型名称
                    attack_tag = attack_tag.strip().upper().replace(' ', '_')
                    
                    # 添加到对应分类
                    attack_urls[attack_tag].add(url)
                    file_count += 1
                    total_records += 1
                        
                except Exception as e:
                    skip_reasons[f'处理异常: {type(e).__name__}'] += 1
                    file_skip += 1
                    continue
            
            print(f"  ✅ 成功提取 {file_count} 条记录 (跳过 {file_skip} 条)")
            skipped_records += file_skip
            
        except Exception as e:
            print(f"  ❌ 处理失败: {str(e)}")
            continue
    
    # 保存分类结果
    print(f"\n{'='*60}")
    print(f"💾 保存分类结果:")
    print(f"{'='*60}")
    
    for attack_type, urls in sorted(attack_urls.items()):
        if urls:
            output_file = os.path.join(total_dir, f'{attack_type}.txt')
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in sorted(urls):
                    f.write(url + '\n')
            
            print(f"  📄 {attack_type:20s}: {len(urls):5d} 条 -> {attack_type}.txt")
    
    # 统计信息
    print(f"{'='*60}")
    print(f"\n处理完成!")
    print(f"{'='*60}")
    print(f"📊 统计:")
    print(f"   成功记录:  {total_records:5d} 条")
    print(f"   跳过记录:  {skipped_records:5d} 条")
    print(f"   攻击类型:  {len(attack_urls):5d} 种")
    print(f"   总URL数:   {sum(len(urls) for urls in attack_urls.values()):5d} 条 (去重后)")
    
    # 显示跳过原因
    if skip_reasons:
        print(f"\n⚠️  跳过原因统计:")
        for reason, count in sorted(skip_reasons.items(), key=lambda x: x[1], reverse=True):
            print(f"   {reason:30s}: {count:5d} 条")
    
    print(f"\n文件已保存到: {total_dir}")
    print(f"{'='*60}")

if __name__ == '__main__':
    process_atrdf()