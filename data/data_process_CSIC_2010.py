import csv
import os

def process_csic_2010():
    """处理CSIC-2010数据集,提取URL并按Label分类"""
    
    # 定义路径
    raw_file = 'raw/CSIC-2010/csic-2010.csv'
    total_dir = 'processed/CSIC-2010/total'
    
    # 确保输出目录存在
    os.makedirs(total_dir, exist_ok=True)
    
    # 用于存储URL
    normal_urls = []
    attack_urls = []
    
    print(f"正在处理文件: {raw_file}")
    
    try:
        with open(raw_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            count = 0
            skipped = 0
            
            for row in reader:
                try:
                    label = row.get('Label', '').strip()
                    url = row.get('URL', '').strip()
                    
                    # 跳过空行
                    if not label or not url:
                        skipped += 1
                        continue
                    
                    # 去掉末尾的 HTTP/1.1
                    url = url.replace(' HTTP/1.1', '').strip()
                    
                    # 根据Label分类
                    if label == 'Normal':
                        normal_urls.append(url)
                    else:  # Anomalous
                        attack_urls.append(url)
                    
                    count += 1
                    
                except Exception as row_error:
                    skipped += 1
                    continue
        
        print(f"  ✅ 成功处理 {count} 条记录" + (f" (跳过 {skipped} 条)" if skipped > 0 else ""))
        
    except Exception as e:
        print(f"  ❌ 处理失败: {str(e)}")
        return
    
    # 保存正常URL
    normal_file = os.path.join(total_dir, 'normal_urls.txt')
    with open(normal_file, 'w', encoding='utf-8') as f:
        for url in normal_urls:
            f.write(url + '\n')
    
    # 保存攻击URL
    attack_file = os.path.join(total_dir, 'attack_urls.txt')
    with open(attack_file, 'w', encoding='utf-8') as f:
        for url in attack_urls:
            f.write(url + '\n')
    
    # 打印统计信息
    print(f"\n{'='*60}")
    print(f"💾 处理完成!")
    print(f"{'='*60}")
    print(f"📊 统计:")
    print(f"   正常URL:   {len(normal_urls):5d} 条")
    print(f"   攻击URL:   {len(attack_urls):5d} 条")
    print(f"   总计:      {len(normal_urls) + len(attack_urls):5d} 条")
    print(f"\n文件已保存到:")
    print(f"  📄 {normal_file}")
    print(f"  📄 {attack_file}")
    print(f"{'='*60}")

if __name__ == '__main__':
    process_csic_2010()