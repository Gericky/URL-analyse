import csv
import os

def detect_encoding(file_path):
    """检测文件编码"""
    encodings = ['utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'latin1', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                f.read()
            return encoding
        except (UnicodeDecodeError, UnicodeError):
            continue
    
    return 'utf-8'

def clean_line(line):
    """清理行内容，移除NUL字符和其他不可见字符"""
    if line is None:
        return ""
    return ''.join(char for char in line if char.isprintable() or char in '\n\r\t')

def process_csv_files():
    # 定义路径
    raw_dir = 'raw/WAF-github'
    total_dir = 'processed/WAF-github/total'
    
    # 确保total目录存在
    os.makedirs(total_dir, exist_ok=True)
    
    # 根据文件名分类存储
    url_categories = {
        'sqli': [],           # SQL注入
        'xss': [],            # XSS攻击
        'normal': []          # 正常URL
    }
    
    # 获取raw目录下所有csv文件
    csv_files = [f for f in os.listdir(raw_dir) if f.endswith('.csv')]
    
    print(f"找到 {len(csv_files)} 个CSV文件")
    
    # 处理每个CSV文件
    for csv_file in csv_files:
        file_path = os.path.join(raw_dir, csv_file)
        print(f"\n处理文件: {csv_file}")
        
        # 根据文件名判断攻击类型
        if 'sqli' in csv_file.lower() or 'sql' in csv_file.lower():
            attack_category = 'sqli'
        elif 'xss' in csv_file.lower():
            attack_category = 'xss'
        else:
            attack_category = 'unknown'
        
        # 检测编码
        encoding = detect_encoding(file_path)
        print(f"  检测到编码: {encoding}")
        print(f"  攻击类型: {attack_category}")
        
        try:
            # 读取并清理文件内容
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                raw_content = f.read()
            
            # 移除NUL字符和不可见字符
            cleaned_content = clean_line(raw_content)
            
            # 使用清理后的内容创建临时CSV读取器
            from io import StringIO
            reader = csv.DictReader(StringIO(cleaned_content))
            
            count = 0
            skipped = 0
            for row in reader:
                try:
                    # 获取URL和标签，并清理
                    url = clean_line(row.get('Sentence', '')).strip()
                    label = clean_line(row.get('Label', '')).strip()
                    
                    # 跳过空行
                    if not url or not label:
                        skipped += 1
                        continue
                    
                    # 根据标签分类
                    if label == '0':
                        # 正常URL
                        url_categories['normal'].append(url)
                    else:
                        # 攻击URL - 根据文件名分类
                        if attack_category in url_categories:
                            url_categories[attack_category].append(url)
                        else:
                            # 未知类型也记录
                            if 'unknown' not in url_categories:
                                url_categories['unknown'] = []
                            url_categories['unknown'].append(url)
                    
                    count += 1
                    
                except Exception as row_error:
                    skipped += 1
                    continue
            
            print(f"  ✅ 成功处理 {count} 条记录" + (f" (跳过 {skipped} 条)" if skipped > 0 else ""))
            
        except Exception as e:
            print(f"  ❌ 处理失败: {str(e)}")
            continue
    
    # 保存分类结果
    print(f"\n{'='*60}")
    print(f"💾 保存分类结果:")
    print(f"{'='*60}")
    
    for category, urls in url_categories.items():
        if len(urls) > 0:
            # 文件名映射
            filename_map = {
                'normal': 'normal_urls.txt',
                'sqli': 'sqli_urls.txt',
                'xss': 'xss_urls.txt',
                'unknown': 'unknown_attack_urls.txt'
            }
            
            output_file = os.path.join(total_dir, filename_map.get(category, f'{category}_urls.txt'))
            
            with open(output_file, 'w', encoding='utf-8') as f:
                for url in urls:
                    f.write(url + '\n')
            
            print(f"  📄 {category.upper():10s}: {len(urls):5d} 条 -> {output_file}")
    
    print(f"{'='*60}")
    print(f"\n处理完成!")
    print(f"{'='*60}")
    print(f"📊 统计:")
    print(f"   正常URL:   {len(url_categories['normal']):5d} 条")
    print(f"   SQL注入:   {len(url_categories['sqli']):5d} 条")
    print(f"   XSS攻击:   {len(url_categories['xss']):5d} 条")
    if 'unknown' in url_categories:
        print(f"   未知类型:  {len(url_categories['unknown']):5d} 条")
    print(f"   总计:      {sum(len(urls) for urls in url_categories.values()):5d} 条")
    print(f"{'='*60}")

if __name__ == '__main__':
    process_csv_files()