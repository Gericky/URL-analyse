"""
LoRA 微调脚本 - URL威胁检测指令微调
输入: URL
输出: 0|benign 或 1|threat_type
"""

import os
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
    BitsAndBytesConfig
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

# ========================
# 路径与基础配置
# ========================

BASE_MODEL = "d:/code/URL-analyse/Qwen3-0.6B"
DATA_DIR = "d:/code/URL-analyse/script/data/finetune_online"
# DATA_DIR = "d:/code/URL-analyse/script/data/finetune_online/test"
TRAIN_PATH = os.path.join(DATA_DIR, "train.jsonl")
VAL_PATH = os.path.join(DATA_DIR, "val.jsonl")
OUTPUT_DIR = "d:/code/URL-analyse/script/output/lora_online"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ========================
# 模型与 Tokenizer 加载
# ========================

print("🚀 加载模型与分词器...")

tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL, 
    use_fast=False,
    trust_remote_code=True
)

if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.pad_token_id = tokenizer.eos_token_id

# 配置 4-bit 量化
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
    torch_dtype=torch.bfloat16
)

# ========================
# LoRA 配置
# ========================

print("⚙️ 设置 LoRA 参数...")
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = prepare_model_for_kbit_training(model)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# ========================
# 数据加载与预处理
# ========================

print("📂 加载数据集...")

if not os.path.exists(TRAIN_PATH):
    raise FileNotFoundError(f"训练数据不存在: {TRAIN_PATH}")
if not os.path.exists(VAL_PATH):
    raise FileNotFoundError(f"验证数据不存在: {VAL_PATH}")

dataset = load_dataset(
    "json",
    data_files={"train": TRAIN_PATH, "validation": VAL_PATH}
)

print(f"✅ 训练集样本数: {len(dataset['train'])}")
print(f"✅ 验证集样本数: {len(dataset['validation'])}")

# 打印数据示例
print("\n📝 数据集示例:")
sample = dataset["train"][0]
print(f"  instruction: {sample['instruction']}")
print(f"  input: {sample['input'][:80]}...")
print(f"  output: {sample['output']}")

# ========================
# 指令格式化
# ========================

PROMPT_TEMPLATE = """<|im_start|>system
你是一个URL安全检测系统,专门识别恶意URL。请判断给定URL是否存在威胁。
输出格式要求: 
- 如果URL安全,输出: 0|benign
- 如果URL存在威胁,输出: 1|威胁类型 (如 phishing, malware, defacement 等)
<|im_end|>
<|im_start|>user
{instruction}
输入URL: {input}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""

def format_instruction(example):
    """将数据格式化为指令模板"""
    prompt = PROMPT_TEMPLATE.format(
        instruction=example["instruction"],
        input=example["input"],
        output=example["output"]
    )
    return {"text": prompt}

print("\n📝 格式化指令数据...")
dataset = dataset.map(format_instruction, remove_columns=dataset["train"].column_names)

# 打印格式化后的示例
print("\n📄 格式化后的完整提示词示例:")
print(dataset["train"][0]["text"][:500] + "...")

# ========================
# Tokenize
# ========================

def tokenize_fn(examples):
    """批量分词处理 - 只对 assistant 的输出计算损失"""
    
    model_inputs = {"input_ids": [], "attention_mask": [], "labels": []}
    
    for text in examples["text"]:
        # Tokenize 完整文本
        tokenized = tokenizer(
            text,
            truncation=True,
            max_length=512,
            padding=False,
            add_special_tokens=True
        )
        
        input_ids = tokenized["input_ids"]
        attention_mask = tokenized["attention_mask"]
        
        # 找到 assistant 开始位置
        assistant_marker = "<|im_start|>assistant\n"
        assistant_start_idx = text.find(assistant_marker)
        
        if assistant_start_idx != -1:
            # 分别 tokenize prefix 和完整文本
            prefix = text[:assistant_start_idx + len(assistant_marker)]
            
            # Tokenize prefix (不添加特殊 token,因为完整文本已经添加了)
            prefix_ids = tokenizer(
                prefix, 
                add_special_tokens=True,
                truncation=True,
                max_length=512
            )["input_ids"]
            
            prefix_len = len(prefix_ids)
            
            # 确保 prefix_len 不超过 input_ids 长度
            if prefix_len > len(input_ids):
                prefix_len = len(input_ids)
            
            # 创建 labels: assistant 之前的部分设为 -100
            labels = [-100] * prefix_len + input_ids[prefix_len:]
            
            # 确保 labels 和 input_ids 长度一致
            if len(labels) > len(input_ids):
                labels = labels[:len(input_ids)]
            elif len(labels) < len(input_ids):
                labels = labels + [-100] * (len(input_ids) - len(labels))
        else:
            # 如果没找到 assistant 标记,整个序列都计算损失
            labels = input_ids.copy()
        
        model_inputs["input_ids"].append(input_ids)
        model_inputs["attention_mask"].append(attention_mask)
        model_inputs["labels"].append(labels)
    
    return model_inputs

print("\n✂️ 进行分词...")
tokenized_datasets = dataset.map(
    tokenize_fn,
    batched=True,
    remove_columns=["text"],
    desc="Tokenizing"
)

print(f"✅ Tokenize 完成")
# 验证数据长度
sample = tokenized_datasets['train'][0]
print(f"   训练集样本示例:")
print(f"   - input_ids 长度: {len(sample['input_ids'])}")
print(f"   - labels 长度: {len(sample['labels'])}")
print(f"   - attention_mask 长度: {len(sample['attention_mask'])}")

# 检查所有样本的长度一致性
print("\n🔍 验证数据一致性...")
for i in range(min(5, len(tokenized_datasets['train']))):
    sample = tokenized_datasets['train'][i]
    input_len = len(sample['input_ids'])
    label_len = len(sample['labels'])
    mask_len = len(sample['attention_mask'])
    
    if input_len != label_len or input_len != mask_len:
        print(f"⚠️ 样本 {i} 长度不一致: input_ids={input_len}, labels={label_len}, attention_mask={mask_len}")
    else:
        print(f"✅ 样本 {i} 长度一致: {input_len}")

# ========================
# 数据整理器
# ========================

data_collator = DataCollatorForSeq2Seq(
    tokenizer=tokenizer,
    model=model,
    label_pad_token_id=-100,
    pad_to_multiple_of=8
)

# ========================
# 训练参数
# ========================

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=5,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=8,
    learning_rate=3e-4,
    warmup_ratio=0.1,
    logging_steps=10,
    save_steps=100,
    eval_strategy="steps",
    eval_steps=100,
    save_total_limit=3,
    bf16=True,
    lr_scheduler_type="cosine",
    optim="paged_adamw_8bit",
    report_to="none",
    gradient_checkpointing=True,
    dataloader_num_workers=0,
    remove_unused_columns=False,
    max_grad_norm=0.3,
    weight_decay=0.01,
    load_best_model_at_end=True,
    metric_for_best_model="eval_loss"
)

# ========================
# Trainer 设置
# ========================

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets["train"],
    eval_dataset=tokenized_datasets["validation"],
    data_collator=data_collator,
    tokenizer=tokenizer
)

# ========================
# 开始训练
# ========================

print("\n" + "=" * 70)
print("🚀 开始 LoRA 微调...")
print("=" * 70)
print(f"📊 训练配置:")
print(f"   - 训练样本数: {len(tokenized_datasets['train'])}")
print(f"   - 验证样本数: {len(tokenized_datasets['validation'])}")
print(f"   - Batch Size: {training_args.per_device_train_batch_size}")
print(f"   - 梯度累积步数: {training_args.gradient_accumulation_steps}")
print(f"   - 有效 Batch Size: {training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps}")
print(f"   - 学习率: {training_args.learning_rate}")
print(f"   - 训练轮数: {training_args.num_train_epochs}")
print(f"   - 最大序列长度: 512")
print("=" * 70)

trainer.train()

# ========================
# 保存模型
# ========================

print("\n💾 保存微调后的模型...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

print("\n" + "=" * 70)
print("✅ LoRA 微调完成!")
print("=" * 70)
print(f"📁 模型输出目录: {OUTPUT_DIR}")
print("\n📌 使用示例:")
print("```python")
print("from peft import PeftModel")
print("from transformers import AutoModelForCausalLM, AutoTokenizer")
print("")
print(f"# 加载模型")
print(f"base_model = AutoModelForCausalLM.from_pretrained('{BASE_MODEL}')")
print(f"model = PeftModel.from_pretrained(base_model, '{OUTPUT_DIR}')")
print(f"tokenizer = AutoTokenizer.from_pretrained('{OUTPUT_DIR}')")
print("model.eval()")
print("")
print("# 推理示例")
print('prompt = """<|im_start|>system')
print("你是一个URL安全检测系统,专门识别恶意URL。请判断给定URL是否存在威胁。")
print("输出格式要求: ")
print("- 如果URL安全,输出: 0|benign")
print("- 如果URL存在威胁,输出: 1|威胁类型")
print('<|im_end|>')
print('<|im_start|>user')
print("判断以下URL是否存在安全威胁")
print('输入URL: http://suspicious-phishing-site.com/login<|im_end|>')
print('<|im_start|>assistant')
print('"""')
print("")
print("inputs = tokenizer(prompt, return_tensors='pt').to(model.device)")
print("outputs = model.generate(**inputs, max_new_tokens=50, do_sample=False)")
print("result = tokenizer.decode(outputs[0], skip_special_tokens=False)")
print("")
print("# 提取预测结果")
print("prediction = result.split('<|im_start|>assistant')[-1].split('<|im_end|>')[0].strip()")
print("print(f'预测结果: {prediction}')")
print("```")
print("=" * 70)