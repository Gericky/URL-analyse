"""
Qwen模型封装 - 支持LoRA微调
"""
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from time import perf_counter
import os


class QwenModel:
    def __init__(self, model_path: str, config: dict, dtype: str = "float16"):
        """
        初始化Qwen模型
        
        Args:
            model_path: 基础模型路径
            config: 完整配置字典
            dtype: 数据类型 ("float16" 或 "float32")
        """
        print(f"🚀 正在从本地加载 Qwen 模型: {model_path}...")
        
        self.config = config
        self.model_path = model_path
        
        # ✨ 调试模式开关
        self.debug = config.get('debug', False)
        
        # 加载tokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_path, 
            trust_remote_code=True,
            local_files_only=True
        )
        
        # 确定数据类型
        dtype_mapping = {"float16": torch.float16, "float32": torch.float32}
        self.dtype = dtype_mapping.get(dtype, torch.float16)
        
        # ========== 加载基础模型 ==========
        print(f"🔄 加载基础模型...")
        self.base_model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=self.dtype,
            device_map="auto",
            trust_remote_code=True,
            local_files_only=True
        )
        print(f"✅ 基础模型已加载到设备: {self.base_model.device}")
        
        # ========== 加载LoRA微调模型（如果启用）==========
        self.lora_model = None
        self.lora_enabled = config.get('model', {}).get('lora', {}).get('enabled', False)
        
        if self.lora_enabled:
            self._load_lora_adapter()
        
        # ========== 加载提示词模板 ==========
        self._load_prompts()
        
        print(f"✅ 模型初始化完成\n")
    
    def _load_lora_adapter(self):
        """加载LoRA adapter权重"""
        lora_config = self.config['model']['lora']
        adapter_path = lora_config['adapter_path']
        checkpoint = lora_config.get('checkpoint', '')
        
        # 构建完整路径
        if checkpoint:
            full_path = os.path.join(adapter_path, checkpoint)
            if not os.path.exists(full_path):
                print(f"⚠️  指定的checkpoint不存在: {full_path}")
                print(f"   回退到主adapter路径: {adapter_path}")
                full_path = adapter_path
        else:
            full_path = adapter_path
        
        # 验证路径
        if not os.path.exists(full_path):
            print(f"❌ LoRA adapter路径不存在: {full_path}")
            print(f"   将使用原始基础模型")
            self.lora_enabled = False
            return
        
        print(f"🔄 加载LoRA adapter: {full_path}")
        
        try:
            self.lora_model = PeftModel.from_pretrained(
                self.base_model,
                full_path,
                local_files_only=True
            )
            self.lora_model.eval()
            print(f"✅ LoRA adapter加载成功")
        except Exception as e:
            print(f"❌ LoRA adapter加载失败: {e}")
            print(f"   将使用原始基础模型")
            self.lora_enabled = False
    
    def _load_prompts(self):
        """从配置文件指定的路径加载提示词模板"""
        # 加载快速检测提示词
        fast_prompt_path = self.config['model']['fast_detection'].get('prompt', '')
        if fast_prompt_path and os.path.exists(fast_prompt_path):
            with open(fast_prompt_path, 'r', encoding='utf-8') as f:
                self.fast_detection_prompt = f.read().strip()
            print(f"✅ 已加载快速检测提示词: {fast_prompt_path}")
        else:
            self.fast_detection_prompt = self._get_default_fast_prompt()
            print(f"⚠️  快速检测提示词文件未找到，使用默认提示词")
        
        # 加载深度分析提示词
        deep_prompt_path = self.config['model']['deep_analysis'].get('prompt', '')
        if deep_prompt_path and os.path.exists(deep_prompt_path):
            with open(deep_prompt_path, 'r', encoding='utf-8') as f:
                self.deep_analysis_prompt = f.read().strip()
            print(f"✅ 已加载深度分析提示词: {deep_prompt_path}")
        else:
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
    
    def _select_model(self, stage: str):
        """
        根据阶段和配置选择使用的模型
        
        Args:
            stage: "fast_detection" 或 "deep_analysis"
            
        Returns:
            选中的模型实例
        """
        stage_config = self.config['model'][stage]
        use_lora = stage_config.get('use_lora', False)
        
        # 如果配置要求使用LoRA且LoRA模型已加载，则使用LoRA模型
        if use_lora and self.lora_model is not None:
            return self.lora_model
        else:
            return self.base_model
    
    def fast_detect(self, url: str, similar_cases=None) -> dict:
        """
        第一阶段：快速检测模式
        
        Args:
            url: 待检测URL
            similar_cases: RAG检索的相似案例列表（可选）
        
        Returns:
            包含response和elapsed_time的字典
        """
        stage_config = self.config['model']['fast_detection']
        max_new_tokens = stage_config.get('max_new_tokens', 50)
        temperature = stage_config.get('temperature', 0.0)
        use_lora = stage_config.get('use_lora', False)
        
        # ========== 选择模型 ==========
        model = self._select_model('fast_detection')
        
        # ========== 构建prompt ==========
        if use_lora and model == self.lora_model:
            prompt = self._build_lora_fast_prompt(url, similar_cases)
            text = prompt
        else:
            # 使用原始chat格式
            user_prompt = f"URL: {url}\n判定结果："
            
            if similar_cases:
                rag_context = "\n\n参考相似案例:\n"
                for i, case in enumerate(similar_cases[:3], 1):
                    label_cn = "攻击" if case['label'] == 'attack' else "正常"
                    rag_context += f"{i}. {label_cn} (相似度 {case['similarity_score']:.1%}): {case['url'][:60]}...\n"
                user_prompt = rag_context + "\n" + user_prompt
            
            messages = [
                {"role": "system", "content": self.fast_detection_prompt},
                {"role": "user", "content": user_prompt}
            ]
            
            text = self.tokenizer.apply_chat_template(
                messages, 
                tokenize=False, 
                add_generation_prompt=True,
                enable_thinking=False
            )
        
        # ✨ 调试输出（仅在debug模式）
        if self.debug:
            self._print_debug_fast(url, model, use_lora, text)
        
        # ========== 生成 ==========
        result = self._generate(model, text, max_new_tokens, temperature, url)
        
        # ✨ 调试输出结果（仅在debug模式）
        if self.debug:
            self._print_debug_result(result)
        
        return result
    
    def deep_analyze(self, url: str, attack_type: str, similar_cases=None) -> dict:
        """
        第二阶段：深度分析模式
        
        Args:
            url: 待分析URL
            attack_type: 第一阶段识别的攻击类型
            similar_cases: RAG检索的相似案例列表（可选）
        
        Returns:
            包含response和elapsed_time的字典
        """
        stage_config = self.config['model']['deep_analysis']
        max_new_tokens = stage_config.get('max_new_tokens', 512)
        temperature = stage_config.get('temperature', 0.3)
        use_lora = stage_config.get('use_lora', False)
        
        # ========== 选择模型 ==========
        model = self._select_model('deep_analysis')
        
        # ========== 构建prompt ==========
        if use_lora and model == self.lora_model:
            prompt = self._build_lora_deep_prompt(url, attack_type, similar_cases)
            text = prompt
        else:
            user_prompt = f"""请对以下URL进行深度安全分析：

URL: {url}
初步判定: {attack_type}"""
            
            if similar_cases:
                rag_context = "\n\n### 参考相似案例:\n"
                for i, case in enumerate(similar_cases[:5], 1):
                    label_cn = "攻击" if case['label'] == 'attack' else "正常"
                    rag_context += f"\n**案例{i}** (相似度: {case['similarity_score']:.2%})\n"
                    rag_context += f"- URL: `{case['url'][:80]}{'...' if len(case['url']) > 80 else ''}`\n"
                    rag_context += f"- 类型: {label_cn}\n"
                user_prompt = user_prompt + rag_context + "\n\n### 分析任务\n基于以上相似案例和你的知识，请对目标URL进行深度分析。"
            
            messages = [
                {"role": "system", "content": self.deep_analysis_prompt},
                {"role": "user", "content": user_prompt}
            ]
            
            text = self.tokenizer.apply_chat_template(
                messages, 
                tokenize=False, 
                add_generation_prompt=True,
                enable_thinking=False
            )
        
        # ✨ 调试输出（仅在debug模式）
        if self.debug:
            self._print_debug_deep(url, attack_type, model, use_lora, text)
        
        # ========== 生成 ==========
        result = self._generate(model, text, max_new_tokens, temperature, url)
        
        # ✨ 调试输出结果（仅在debug模式）
        if self.debug:
            self._print_debug_result(result)
        
        return result
    
    def _build_lora_fast_prompt(self, url: str, similar_cases=None) -> str:
        """构建LoRA微调模型的快速检测prompt（指令格式）"""
        system_content = """你是一个URL安全检测系统,专门识别恶意URL。请判断给定URL是否存在威胁。
输出格式要求: 
- 如果URL安全,输出: 0|benign
- 如果URL存在威胁,输出: 1|威胁类型 (如 phishing, malware, sql_injection, xss, command_injection 等)"""
        
        if similar_cases:
            rag_context = "\n\n参考案例:\n"
            for i, case in enumerate(similar_cases[:3], 1):
                label_cn = "威胁" if case['label'] == 'attack' else "安全"
                rag_context += f"{i}. {label_cn} (相似度 {case['similarity_score']:.1%}): {case['url'][:60]}...\n"
            system_content += rag_context
        
        prompt = f"""<|im_start|>system
{system_content}
<|im_end|>
<|im_start|>user
判断以下URL是否存在安全威胁
输入URL: {url}<|im_end|>
<|im_start|>assistant
"""
        return prompt
    
    def _build_lora_deep_prompt(self, url: str, attack_type: str, similar_cases=None) -> str:
        """构建LoRA微调模型的深度分析prompt"""
        system_content = f"""你是一个URL安全分析系统。请对检测到的威胁URL进行详细分析。

初步判定: {attack_type}"""
        
        if similar_cases:
            rag_context = "\n\n参考案例:\n"
            for i, case in enumerate(similar_cases[:5], 1):
                label_cn = "威胁" if case['label'] == 'attack' else "安全"
                rag_context += f"{i}. {label_cn}: {case['url'][:60]}...\n"
            system_content += rag_context
        
        prompt = f"""<|im_start|>system
{system_content}
<|im_end|>
<|im_start|>user
请详细分析以下URL的威胁情况:
{url}<|im_end|>
<|im_start|>assistant
"""
        return prompt
    
    def _generate(self, model, text: str, max_new_tokens: int, temperature: float, url: str) -> dict:
        """内部生成方法"""
        inputs = self.tokenizer([text], return_tensors="pt").to(model.device)
        
        start_time = perf_counter()
        
        with torch.no_grad():
            if temperature > 0:
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=True,
                    temperature=temperature,
                    top_p=0.9,
                    top_k=50,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            else:
                outputs = model.generate(
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
    
    # ========== 调试输出方法（仅在debug=true时调用）==========
    
    def _print_debug_fast(self, url: str, model, use_lora: bool, text: str):
        """打印快速检测的调试信息"""
        print("\n" + "="*80)
        print("🔍 【调试】快速检测阶段")
        print("="*80)
        print(f"📌 URL: {url[:100]}{'...' if len(url) > 100 else ''}")
        print(f"🤖 模型: {'LoRA微调模型' if (use_lora and model == self.lora_model) else '原始基础模型'}")
        print("\n" + "-"*80)
        print("📝 完整输入Prompt:")
        print("-"*80)
        print(text)
        print("-"*80)
    
    def _print_debug_deep(self, url: str, attack_type: str, model, use_lora: bool, text: str):
        """打印深度分析的调试信息"""
        print("\n" + "="*80)
        print("🔍 【调试】深度分析阶段")
        print("="*80)
        print(f"📌 URL: {url[:100]}{'...' if len(url) > 100 else ''}")
        print(f"🎯 初步判定: {attack_type}")
        print(f"🤖 模型: {'LoRA微调模型' if (use_lora and model == self.lora_model) else '原始基础模型'}")
        print("\n" + "-"*80)
        print("📝 完整输入Prompt:")
        print("-"*80)
        print(text)
        print("-"*80)
    
    def _print_debug_result(self, result: dict):
        """打印模型输出结果"""
        print("\n" + "-"*80)
        print("🎯 模型原始输出:")
        print("-"*80)
        print(result['response'])
        print("-"*80)
        print(f"⏱️  耗时: {result['elapsed_time']:.3f}秒")
        print("="*80 + "\n")
    
    def get_model_info(self, stage: str = "fast_detection") -> dict:
        """获取当前使用的模型信息"""
        stage_config = self.config['model'][stage]
        use_lora = stage_config.get('use_lora', False)
        
        info = {
            'base_model': self.model_path,
            'lora_enabled': self.lora_enabled,
            'stage': stage,
            'using_lora': use_lora and self.lora_model is not None,
            'generation_config': {
                'max_new_tokens': stage_config.get('max_new_tokens'),
                'temperature': stage_config.get('temperature')
            }
        }
        
        if self.lora_enabled:
            lora_config = self.config['model']['lora']
            info['lora_adapter'] = lora_config['adapter_path']
            if lora_config.get('checkpoint'):
                info['checkpoint'] = lora_config['checkpoint']
        
        return info