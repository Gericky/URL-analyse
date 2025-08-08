import os
import re
import csv
import pyshark

# 配置 tshark 路径
TSHARK_PATH = r"D:\Wireshark\tshark.exe"

# 要处理的 pcap 文件夹
PCAP_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "document", "pcap")
OUTPUT_CSV = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "do_http_requests.csv")

# UUID 提取正则（路径中可能包含文件ID）
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

# 设置 tshark 路径
def setup_tshark_path():
    """设置 tshark 路径"""
    if os.path.exists(TSHARK_PATH):
        return TSHARK_PATH
    else:
        print(f"警告：tshark 路径不存在 {TSHARK_PATH}，将使用系统默认路径")
        return None

# 是否匹配 DO 请求的判断
def is_do_request(http_layer):
    try:
        host = http_layer.get("Host", "")
        user_agent = http_layer.get("User-Agent", "")
        return "delivery.mp.microsoft.com" in host or "Delivery-Optimization" in user_agent
    except Exception:
        return False

# 解析单个 pcap 文件
def parse_single_pcap(file_path):
    print(f"解析文件：{file_path}")
    tshark_path = setup_tshark_path()
    
    # 尝试不同的参数组合来处理有问题的文件
    capture_configs = [
        # 配置1：使用 JSON 输出，不包含原始数据
        {
            'use_json': True,
            'include_raw': False,
            'decode_as': None
        },
        # 配置2：简单配置
        {
            'use_json': False,
            'include_raw': False,
            'decode_as': None
        },
        # 配置3：最基本配置
        {}
    ]
    
    for i, config in enumerate(capture_configs):
        try:
            print(f"  尝试配置 {i+1}...")
            cap = pyshark.FileCapture(file_path, 
                                    display_filter='http.request',
                                    tshark_path=tshark_path,
                                    **config)
            
            extracted = []
            packet_count = 0
            
            for pkt in cap:
                try:
                    packet_count += 1
                    if packet_count % 1000 == 0:
                        print(f"    已处理 {packet_count} 个数据包...")
                    
                    http_layer = pkt.http

                    if not is_do_request(http_layer):
                        continue

                    method = http_layer.get("Request Method", "")
                    uri = http_layer.get("Request URI", "")
                    host = http_layer.get("Host", "")
                    user_agent = http_layer.get("User-Agent", "")
                    range_header = http_layer.get("Range", "")

                    match = UUID_REGEX.search(uri)
                    uuid = match.group(0) if match else ""

                    extracted.append({
                        "pcap_file": os.path.basename(file_path),
                        "method": method,
                        "host": host,
                        "uri": uri,
                        "uuid": uuid,
                        "range": range_header,
                        "user_agent": user_agent
                    })
                except Exception as e:
                    # 跳过有问题的数据包，继续处理下一个
                    continue
            
            print(f"  完成处理 {packet_count} 个数据包，提取到 {len(extracted)} 个匹配请求")
            
            try:
                cap.close()
            except Exception as e:
                print(f"  关闭文件时出错：{e}")
            
            return extracted
            
        except Exception as e:
            print(f"  配置 {i+1} 失败：{e}")
            try:
                cap.close()
            except:
                pass
            
            if i == len(capture_configs) - 1:
                print(f"  所有配置都失败，跳过文件 {file_path}")
                return []
            else:
                print(f"  尝试下一个配置...")
                continue

# 批量处理
def process_all_pcaps(folder):
    all_data = []
    pcap_files = [f for f in os.listdir(folder) if f.endswith(".pcap") or f.endswith(".pcapng")]
    
    print(f"找到 {len(pcap_files)} 个 PCAP 文件")
    
    for i, fname in enumerate(pcap_files, 1):
        print(f"\n[{i}/{len(pcap_files)}] 处理文件: {fname}")
        fpath = os.path.join(folder, fname)
        
        try:
            file_data = parse_single_pcap(fpath)
            all_data.extend(file_data)
            print(f"  成功处理，新增 {len(file_data)} 条记录")
        except Exception as e:
            print(f"  处理文件 {fname} 时发生错误: {e}")
            print(f"  跳过此文件，继续处理下一个...")
            continue
    
    print(f"\n总共提取到 {len(all_data)} 条 DO 请求记录")
    return all_data

# 输出到 CSV
def save_to_csv(data, filename):
    if not data:
        print("没有匹配数据")
        return
    # 确保输出目录存在
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(data[0].keys()))
        writer.writeheader()
        writer.writerows(data)
    print(f"结果已保存到 {filename}")

# 主流程
if __name__ == "__main__":
    results = process_all_pcaps(PCAP_FOLDER)
    save_to_csv(results, OUTPUT_CSV)
