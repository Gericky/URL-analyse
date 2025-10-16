import os
import csv
import sys

# 增加CSV字段大小限制（修复后的版本）
try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    # 在某些系统上 sys.maxsize 太大，使用一个较大但安全的值
    maxInt = int(1e9)  # 10亿字符，足够大
    csv.field_size_limit(maxInt)


def process_csv_file(input_path, output_path, label):
    """
    处理CSV格式的数据文件，提取URL列

    Args:
        input_path: 输入CSV文件路径
        output_path: 输出TXT文件路径
        label: 标签类型 (用于输出文件名)
    """
    urls = []

    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)

            # 读取表头
            header = next(reader)
            print(f"📋 表头: {header}")

            # 确认URL列索引
            try:
                url_index = header.index('url')
            except ValueError:
                print(f"❌ 未找到'url'列，使用第4列（索引3）")
                url_index = 3

            # 读取数据行
            for row_num, row in enumerate(reader, start=2):
                if len(row) <= url_index:
                    continue

                url = row[url_index].strip()
                if url:
                    urls.append(url)

        # 去重
        urls_unique = list(set(urls))

        # 保存到txt
        with open(output_path, 'w', encoding='utf-8') as f:
            for url in urls_unique:
                f.write(url + '\n')

        print(f"✅ 已处理 {label}: 原始{len(urls)}条 → 去重后{len(urls_unique)}条 → {output_path}")
        return len(urls_unique)

    except Exception as e:
        print(f"❌ 处理 {input_path} 失败: {e}")
        import traceback
        traceback.print_exc()
        return 0


def main():
    """主函数:处理CCF-BDCI-2022数据集"""

    # 定义路径
    raw_dir = os.path.join(".", "raw", "CCF-BDCI2022-github")
    train_dir = os.path.join(raw_dir, "train")
    test_dir = os.path.join(raw_dir, "test")
    output_dir = os.path.join(".", "processed", "CCF-BDCI2022")

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"📂 CCF-BDCI-2022 数据集处理")
    print(f"{'=' * 60}")
    print(f"📁 训练集目录: {os.path.abspath(train_dir)}")
    print(f"📁 测试集目录: {os.path.abspath(test_dir)}")
    print(f"📁 输出目录: {os.path.abspath(output_dir)}")
    print(f"{'=' * 60}\n")

    # 处理训练集中的各类文件
    train_files = {
        '白.csv': 'normal',
        'SQL注入.csv': 'sql_injection',
        'XSS跨站脚本.csv': 'xss',
        '命令执行.csv': 'command_execution',
        '目录遍历.csv': 'path_traversal',
        '远程代码执行.csv': 'remote_code_execution'
    }

    # 统计
    all_attack_urls = []
    all_normal_urls = []

    print(f"📦 处理训练集文件:")
    print(f"{'=' * 60}\n")

    for filename, label in train_files.items():
        input_path = os.path.join(train_dir, filename)

        print(f"🔍 检查文件: {os.path.abspath(input_path)}")

        if not os.path.exists(input_path):
            print(f"⚠️ 文件不存在，跳过处理\n")
            continue

        # 单独输出文件
        output_path = os.path.join(output_dir, f"{label}.txt")
        count = process_csv_file(input_path, output_path, label)

        # 读取URL添加到合并列表
        if count > 0:
            try:
                with open(output_path, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]

                    if label == 'normal':
                        all_normal_urls.extend(urls)
                    else:
                        all_attack_urls.extend(urls)
            except:
                pass
        print()

    # 保存合并后的文件
    print(f"{'=' * 60}")
    print(f"📊 合并处理:")
    print(f"{'=' * 60}\n")

    if all_normal_urls:
        normal_output = os.path.join(output_dir, "all_normal.txt")
        normal_unique = list(set(all_normal_urls))
        with open(normal_output, 'w', encoding='utf-8') as f:
            for url in normal_unique:
                f.write(url + '\n')
        print(f"✅ 所有正常URL已合并: {len(all_normal_urls)}条 → 去重后{len(normal_unique)}条")
        print(f"   → {normal_output}\n")

    if all_attack_urls:
        attack_output = os.path.join(output_dir, "all_attacks.txt")
        attack_unique = list(set(all_attack_urls))
        with open(attack_output, 'w', encoding='utf-8') as f:
            for url in attack_unique:
                f.write(url + '\n')
        print(f"✅ 所有攻击URL已合并: {len(all_attack_urls)}条 → 去重后{len(attack_unique)}条")
        print(f"   → {attack_output}\n")

    # 处理测试集
    print(f"{'=' * 60}")
    print(f"📦 处理测试集:")
    print(f"{'=' * 60}\n")

    test_file = os.path.join(test_dir, "test.csv")
    print(f"🔍 检查文件: {os.path.abspath(test_file)}")

    if os.path.exists(test_file):
        test_output = os.path.join(output_dir, "test_urls.txt")
        test_count = process_csv_file(test_file, test_output, "测试集")
    else:
        print(f"⚠️ 测试集文件不存在")
        test_count = 0

    # 总结
    print(f"\n{'=' * 60}")
    print(f"✅ 数据处理完成!")
    print(f"{'=' * 60}")
    print(f"📂 输出目录: {os.path.abspath(output_dir)}")
    print(f"📊 处理统计:")
    print(f"   - 正常URL: {len(all_normal_urls)}条 (去重后{len(set(all_normal_urls))}条)")
    print(f"   - 攻击URL: {len(all_attack_urls)}条 (去重后{len(set(all_attack_urls))}条)")
    print(f"   - 测试URL: {test_count}条")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()