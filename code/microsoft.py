import os

# 提取出 "shuc-pc-hunt.ksord.com" 这种格式的内容
def process_line(line):
    # 处理包含 "microsoft.com" 的行
    if '|' in line:
        after_pipe = line.split('|', 1)[1].strip()
        if not after_pipe or not (after_pipe[0].isalnum() or after_pipe[0] == '['):
            return ''
        # 如果包含路径
        if '/' in after_pipe:
            parts = after_pipe.split('/')
            # 取域名 + 第一级路径
            if len(parts) >= 2 and 'microsoft.com' in parts[0]:
                return parts[0] + '/' + parts[1] + '/'
            
    return ''

# 主处理函数
def copy_and_clean_files_unique(src_folder, dest_folder):
    abs_src = os.path.abspath(src_folder)
    abs_dest = os.path.abspath(dest_folder)
    os.makedirs(abs_dest, exist_ok=True)
    # 遍历所有无后缀文件
    for filename in os.listdir(abs_src):
        src_path = os.path.join(abs_src, filename)

        if os.path.isfile(src_path) and '.' not in filename:
            dest_path = os.path.join(abs_dest, filename)
            print(f"处理文件：{filename}")
            unique_lines = set()

            # 自动尝试多种编码打开文件
            success = False
            for encoding in ['latin1']:
                try:
                    with open(src_path, 'r', encoding=encoding, errors='strict') as src_file:
                        for line in src_file:
                            cleaned = process_line(line)
                            if cleaned:
                                unique_lines.add(cleaned)
                    success = True
                    break  # 成功则跳出编码尝试
                except UnicodeDecodeError as e:
                    print(f"尝试编码 {encoding} 失败：{e}")

            if not success:
                print(f"跳过无法解码的文件：{filename}")
                continue

            # 写入结果，使用 utf-8 编码
            with open(dest_path, 'w', encoding='utf-8') as dest_file:
                for item in sorted(unique_lines):
                    dest_file.write(item + '\n')

            print(f"写入去重后内容到：{dest_path}")
            print('-' * 40)

# 示例调用（可根据你的路径修改）
def main():
    src_folder = '../document'
    dest_folder = '../micro_output'
    copy_and_clean_files_unique(src_folder, dest_folder)

if __name__ == "__main__":
    main()