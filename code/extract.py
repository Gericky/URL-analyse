import os

def process_line(line):
    # 提取 '|' 后、首个 '/' 前的部分
    if '|' in line:
        after_pipe = line.split('|', 1)[1].strip()
        if '/' in after_pipe:
            return after_pipe.split('/', 1)[0].strip()
        else:
            return after_pipe.strip()
    return ''  # 没有 '|' 的行忽略

def copy_and_clean_files_unique(src_folder, dest_folder):
    abs_src = os.path.abspath(src_folder)
    abs_dest = os.path.abspath(dest_folder)

    os.makedirs(abs_dest, exist_ok=True)

    for filename in os.listdir(abs_src):
        src_path = os.path.join(abs_src, filename)

        if os.path.isfile(src_path) and '.' not in filename:
            dest_path = os.path.join(abs_dest, filename)

            print(f"处理文件：{filename}")
            unique_lines = set()

            with open(src_path, 'r', encoding='utf-8') as src_file:
                for line in src_file:
                    cleaned = process_line(line)
                    if cleaned:
                        unique_lines.add(cleaned)

            with open(dest_path, 'w', encoding='utf-8') as dest_file:
                for cleaned_line in sorted(unique_lines):
                    dest_file.write(cleaned_line + '\n')

            print(f"写入去重后内容到：{dest_path}")
            print('-' * 40)

# 示例调用
copy_and_clean_files_unique('../document', './output')
