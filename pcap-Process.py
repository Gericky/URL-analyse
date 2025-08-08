import subprocess
import os
import json

# 1. 设置 tshark 绝对路径
TSHARK_PATH = r"D:\Wireshark\tshark.exe"

# 2. 设置 pcap 文件夹 & 输出文件夹
PCAP_FOLDER = r"./document/pcap"
OUTPUT_FOLDER = r"./pcap_output"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# 3. 设置匹配的域名关键字（不区分大小写）
TARGET_KEYWORD = "microsoft"

# 4. 批量处理 pcap
for filename in os.listdir(PCAP_FOLDER):
    if filename.lower().endswith(".pcap"):
        pcap_path = os.path.join(PCAP_FOLDER, filename)
        output_path = os.path.join(OUTPUT_FOLDER, filename + ".json")

        cmd = [
            TSHARK_PATH,
            "-r", pcap_path,
            "-Y", "http",
            "-T", "json",
            "-e", "http.host",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "http.request.full_uri",
            "-e", "http.user_agent",
            "-e", "http.accept",
            "-e", "http.accept_language",
            "-e", "http.accept_encoding",
            "-e", "http.referer"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"[错误] 解析 {filename} 失败（JSON 格式错误）")
            continue

        filtered_data = []
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})

            host = layers.get("http.host", [""])[0] if isinstance(layers.get("http.host"), list) else layers.get("http.host")
            method = layers.get("http.request.method", [""])[0] if isinstance(layers.get("http.request.method"), list) else layers.get("http.request.method")
            uri_path = layers.get("http.request.uri", [""])[0] if isinstance(layers.get("http.request.uri"), list) else layers.get("http.request.uri")
            full_uri = layers.get("http.request.full_uri", [""])[0] if isinstance(layers.get("http.request.full_uri"), list) else layers.get("http.request.full_uri")

            headers = {}
            if layers.get("http.user_agent"):
                headers["User-Agent"] = layers["http.user_agent"][0] if isinstance(layers["http.user_agent"], list) else layers["http.user_agent"]
            if layers.get("http.accept"):
                headers["Accept"] = layers["http.accept"][0] if isinstance(layers["http.accept"], list) else layers["http.accept"]
            if layers.get("http.accept_language"):
                headers["Accept-Language"] = layers["http.accept_language"][0] if isinstance(layers["http.accept_language"], list) else layers["http.accept_language"]
            if layers.get("http.accept_encoding"):
                headers["Accept-Encoding"] = layers["http.accept_encoding"][0] if isinstance(layers["http.accept_encoding"], list) else layers["http.accept_encoding"]
            if layers.get("http.referer"):
                headers["Referer"] = layers["http.referer"][0] if isinstance(layers["http.referer"], list) else layers["http.referer"]

            # 关键字匹配（不区分大小写）
            if host and TARGET_KEYWORD.lower() in host.lower():
                filtered_data.append({
                    "host": host,
                    "method": method,
                    "url_path": uri_path,
                    "full_url": full_uri,
                    "headers": headers
                })

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(filtered_data, f, ensure_ascii=False, indent=2)

        print(f"[完成] {filename} -> {output_path}")
