import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from time import perf_counter

class QwenModel:
    def __init__(self, model_path, dtype="float16"):
        """初始化Qwen模型"""
        print(f"🚀 正在从本地加载 Qwen 模型: {model_path}...")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        
        # 设置dtype
        torch_dtype = torch.float16 if dtype == "float16" else torch.float32
        
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            dtype=torch_dtype,
            device_map="auto",
            trust_remote_code=True
        )
        print(f"✅ 模型已加载到设备: {self.model.device}\n")
    
    def query(self, url: str, max_new_tokens=128, temperature=0.0) -> dict:
        """查询模型判断URL"""
        messages = [
            {
                "role": "system",
                "content": (
                    "你是一个专业的Web安全检测系统,负责分析URL请求并识别潜在的安全威胁。"
                    "你的任务是判断给定的URL是否包含恶意攻击特征,并给出明确的分类结果。"
                    "判定规则:"
                    "- 输出 0:表示正常URL,即安全的、合法的Web请求"
                    "- 输出 1:表示异常URL,即包含攻击特征的恶意请求"
                    "攻击特征包括但不限于:"
                    "• SQL注入:包含 `'`、`--`、`#`、`union`、`select` 等SQL语句"
                    "• XSS跨站脚本:包含 `<script>`、`</script>`、`javascript:`、`onerror=` 等"
                    "• 命令注入:包含 `|`、`;`、`&&`、shell命令等"
                    "• 路径遍历:包含 `../`、`..\\`、`/etc/passwd` 等"
                    "• 文件包含:包含 `<?php`、`include`、远程文件路径等"
                    "• 其他恶意特征:编码绕过、异常字符、敏感路径访问等"
                    "正常请求特征:"
                    "• 仅包含常规路径和静态资源访问"
                    "• 参数值为正常的业务数据,无注入符号"
                    "• 符合标准的HTTP请求格式"
                    "请基于OWASP Top 10安全标准进行判断,保持高灵敏度但避免误报。"
                )
            },
            {
                "role": "user",
                "content": (
                    "请分析以下URL请求,判断其是否为恶意攻击:\n"
                    f"URL: {url}\n\n"
                    "请按以下格式回答:\n"
                    "首先输出分类结果(0或1):\n"
                    "- 0 表示正常URL\n"
                    "- 1 表示异常URL\n"
                    "然后说明判断理由,包括:\n"
                    "- 如果是异常URL(1),请指出具体的攻击类型(如SQL注入、XSS、命令执行、路径遍历等)和恶意特征\n"
                    "- 如果是正常URL(0),请说明为何判定为安全请求\n\n"
                    "请直接以数字0或1开头回答。"
                )
            }
        ]
        
        text = self.tokenizer.apply_chat_template(
            messages, 
            tokenize=False, 
            add_generation_prompt=True, 
            enable_thinking=False
        )
        inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        
        start_time = perf_counter()
        with torch.no_grad():
            # 根据temperature决定采样策略
            if temperature > 0:
                # 使用采样模式
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=True,
                    temperature=temperature,
                    top_p=0.9,
                    top_k=50,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            else:
                # 使用贪婪解码模式(确定性输出)
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id
                )
        end_time = perf_counter()
        
        raw_response = self.tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:], 
            skip_special_tokens=True
        ).strip()
        
        elapsed = round(end_time - start_time, 3)
        
        # 返回原始响应,由外部解析
        return {
            "url": url,
            "raw_response": raw_response,
            "elapsed_time_sec": elapsed
        }