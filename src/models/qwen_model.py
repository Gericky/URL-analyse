import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from time import perf_counter
import os


class QwenModel:
    def __init__(self, model_path, config, dtype="float16"):
        """
        初始化Qwen模型
        
        Args:
            model_path: 模型路径
            config: 完整配置字典
            dtype: 数据类型
        """
        print(f"🚀 正在从本地加载 Qwen 模型: {model_path}...")
        
        self.config = config
        self.tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        dtype = torch.float16 if dtype == "float16" else torch.float32
        
        self.model = AutoModelForCausalLM.from_pretrained(
            model_path,
            dtype=dtype,
            device_map="auto",
            trust_remote_code=True
        )
        print(f"✅ 模型已加载到设备: {self.model.device}\n")
        
        # ✨ 加载提示词模板
        self._load_prompts()
    
    def _load_prompts(self):
        """从配置文件指定的路径加载提示词模板"""
        # 加载快速检测提示词
        fast_prompt_path = self.config['model']['fast_detection'].get('prompt', '')
        if fast_prompt_path and os.path.exists(fast_prompt_path):
            with open(fast_prompt_path, 'r', encoding='utf-8') as f:
                self.fast_detection_prompt = f.read().strip()
            print(f"✅ 已加载快速检测提示词: {fast_prompt_path}")
        else:
            # 降级：使用默认提示词
            self.fast_detection_prompt = self._get_default_fast_prompt()
            print(f"⚠️  快速检测提示词文件未找到，使用默认提示词")
        
        # 加载深度分析提示词
        deep_prompt_path = self.config['model']['deep_analysis'].get('prompt', '')
        if deep_prompt_path and os.path.exists(deep_prompt_path):
            with open(deep_prompt_path, 'r', encoding='utf-8') as f:
                self.deep_analysis_prompt = f.read().strip()
            print(f"✅ 已加载深度分析提示词: {deep_prompt_path}")
        else:
            # 降级：使用默认提示词
            self.deep_analysis_prompt = self._get_default_deep_prompt()
            print(f"⚠️  深度分析提示词文件未找到，使用默认提示词")
    
    def _get_default_fast_prompt(self) -> str:
        """默认的快速检测提示词"""
        return """你是一个URL安全快速检测系统。
任务：快速判断URL是否为攻击，只输出判定结果。
输出格式（严格遵守）：
- 如果是正常URL，输出：0
- 如果是攻击URL，输出：1|攻击类型
攻击类型包括：sql_injection, xss, command_injection, path_traversal, file_inclusion, DDoS, malicious_file_access
不要输出任何解释，只输出判定结果。"""
    
    def _get_default_deep_prompt(self) -> str:
        """默认的深度分析提示词"""
        return """你是一名高级网络安全分析引擎，负责对可疑URL进行深度威胁分析。
请按以下格式输出：
1. 攻击类型：[具体类型]
2. 简要概述：[一句话概括]
3. 行为描述：[详细描述攻击行为]
4. 成因分析：[分析为何判定为攻击]
5. 判定依据：[列出关键特征]
6. 风险评估：[评估危害程度]
7. 防护建议：[给出防护措施]"""
    
    def fast_detect(self, url: str, similar_cases=None) -> dict:
        """
        第一阶段：快速检测模式
        - 只输出 label (0/1) 和攻击类型
        - 不输出详细理由
        - 支持RAG增强
        
        Args:
            url: 待检测URL
            similar_cases: RAG检索的相似案例列表（可选）
        """
        # ✨ 从配置读取参数
        max_new_tokens = self.config['model']['fast_detection'].get('max_new_tokens', 10)
        temperature = self.config['model']['fast_detection'].get('temperature', 0.0)
        
        # 构建用户提示词
        user_prompt = f"URL: {url}\n判定结果："
        
        # ✨ 如果有相似案例，增强提示词
        if similar_cases:
            rag_context = "\n\n参考相似案例:\n"
            for i, case in enumerate(similar_cases[:3], 1):
                label_cn = "攻击" if case['label'] == 'attack' else "正常"
                rag_context += f"{i}. {label_cn} (相似度 {case['similarity_score']:.1%}): {case['url'][:60]}...\n"
            user_prompt = rag_context + "\n" + user_prompt
        
        messages = [
            {
                "role": "system",
                "content": self.fast_detection_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            }
        ]
        
        return self._generate(messages, max_new_tokens, temperature, url)
    
    def deep_analyze(self, url: str, attack_type: str, similar_cases=None) -> dict:
        """
        第二阶段：深度分析模式
        - 输出详细的安全分析报告
        - 支持RAG增强
        
        Args:
            url: 待分析URL
            attack_type: 第一阶段识别的攻击类型
            similar_cases: RAG检索的相似案例列表（可选）
        """
        # ✨ 从配置读取参数
        max_new_tokens = self.config['model']['deep_analysis'].get('max_new_tokens', 512)
        temperature = self.config['model']['deep_analysis'].get('temperature', 0.3)
        
        # 构建用户提示词
        user_prompt = f"""请对以下URL进行深度安全分析：

URL: {url}
初步判定: {attack_type}"""
        
        # ✨ 如果有相似案例，增强提示词
        if similar_cases:
            rag_context = "\n\n### 参考相似案例:\n"
            for i, case in enumerate(similar_cases[:5], 1):
                label_cn = "攻击" if case['label'] == 'attack' else "正常"
                rag_context += f"\n**案例{i}** (相似度: {case['similarity_score']:.2%})\n"
                rag_context += f"- URL: `{case['url'][:80]}{'...' if len(case['url']) > 80 else ''}`\n"
                rag_context += f"- 类型: {label_cn}\n"
            user_prompt = user_prompt + rag_context + "\n\n### 分析任务\n基于以上相似案例和你的知识，请对目标URL进行深度分析。"
        
        messages = [
            {
                "role": "system",
                "content": self.deep_analysis_prompt
            },
            {
                "role": "user",
                "content": user_prompt
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
        
        elapsed_time = perf_counter() - start_time
        
        response = self.tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:], 
            skip_special_tokens=True
        ).strip()
        
        return {
            'url': url,
            'response': response,
            'elapsed_time': elapsed_time
        }