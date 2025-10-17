import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from time import perf_counter

class QwenModel:
    def __init__(self, model_path, dtype="float16"):
        """初始化Qwen模型"""
        print(f"🚀 正在从本地加载 Qwen 模型: {model_path}...")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        torch_dtype = torch.float16 if dtype == "float16" else torch.float32
        
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            dtype=torch_dtype,
            device_map="auto",
            trust_remote_code=True
        )
        print(f"✅ 模型已加载到设备: {self.model.device}\n")
    
    def fast_detect(self, url: str, max_new_tokens=50, temperature=0.0) -> dict:
        """
        第一阶段：快速检测模式
        - 只输出 label (0/1) 和攻击类型
        - 不输出详细理由
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "你是一个URL安全快速检测系统。"
                    "任务：快速判断URL是否为攻击，只输出判定结果。"
                    "输出格式（严格遵守）："
                    "- 如果是正常URL，输出：0"
                    "- 如果是攻击URL，输出：1|攻击类型"
                    "攻击类型包括：sql_injection, xss, command_injection, path_traversal, file_inclusion,DDoS"
                    "示例："
                    "  正常URL → 0"
                    "  SQL注入 → 1|sql_injection"
                    "  XSS攻击 → 1|xss"
                    "不要输出任何解释，只输出判定结果。"
    #                "?d后面的内容是URL参数，请重点关注。"
                    
                    "比如/skypearl/cn/validatorAction.action?d=1497656987是正常URL，"
     #               "而/skypearl/cn/validatorAction.action?d=1497656987' OR '1'='1是SQL注入攻击。"

                )
            },
            {
                "role": "user",
                "content": f"URL: {url}\n判定结果："
            }
        ]
        
        return self._generate(messages, max_new_tokens, temperature, url)
    
    def deep_analyze(self, url: str, attack_type: str, max_new_tokens=512, temperature=0.3) -> dict:
        """
        第二阶段：深度分析模式
        - 输出详细的结构化分析报告
        """
        messages = [
            {
                "role": "system",
                "content": (
                    "你是一个Web安全专家，负责对攻击URL进行深度分析。"
                    "请按以下结构输出详细分析报告：\n"
                    "## 攻击类型\n[攻击分类]\n\n"
                    "## 简要概述\n[一句话描述攻击意图]\n\n"
                    "## 行为描述\n[详细描述URL中的恶意行为]\n\n"
                    "## 成因分析\n[分析为何会产生此类攻击]\n\n"
                    "## 判定依据\n[列出判定为攻击的关键特征]\n\n"
                    "## 风险评估\n[评估攻击的危害程度]\n\n"
                    "## 防护建议\n[给出具体的防护措施]"
                )
            },
            {
                "role": "user",
                "content": (
                    f"请对以下攻击URL进行深度分析：\n"
                    f"URL: {url}\n"
                    f"初步判定类型: {attack_type}\n\n"
                    f"请输出完整的分析报告："
                )
            }
        ]
        
        return self._generate(messages, max_new_tokens, temperature, url)
    
    def _generate(self, messages, max_new_tokens, temperature, url):
        """内部生成方法"""
        text = self.tokenizer.apply_chat_template(
            messages, 
            tokenize=False, 
            add_generation_prompt=True, 
            enable_thinking=False
        )
        inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)
        
        start_time = perf_counter()
        with torch.no_grad():
            if temperature > 0:
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
        
        return {
            "url": url,
            "raw_response": raw_response,
            "elapsed_time_sec": round(end_time - start_time, 3)
        }