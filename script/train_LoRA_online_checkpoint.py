"""
LoRA 微调脚本 - URL威胁检测指令微调（支持断点续训）
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
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, PeftModel
import glob
import json

# ========================
# 路径与基础配置
# ========================

BASE_MODEL = "d:/code/URL-analyse/Qwen3-0.6B"
DATA_DIR = "d:/code/URL-analyse/script/data/finetune_online/raw"
TRAIN_PATH = os.path.join(DATA_DIR, "train.jsonl")
VAL_PATH = os.path.join(DATA_DIR, "val.jsonl")
OUTPUT_DIR = "d:/code/URL-analyse/script/output/lora_online_v2"

# ✨✨✨ 是否从最新 checkpoint 恢复训练
RESUME_FROM_CHECKPOINT = True

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ========================
# 检测最新 checkpoint
# ========================

def get_latest_checkpoint(output_dir):
    """查找最新的 checkpoint 目录"""
    checkpoints = glob.glob(os.path.join(output_dir, "checkpoint-*"))
    
    if not checkpoints:
        return None, 0
    
    # 按步数排序
    checkpoints = sorted(checkpoints, key=lambda x: int(x.split("-")[-1]))
    latest = checkpoints[-1]
    latest_step = int(latest.split("-")[-1])
    
    print(f"\n📍 找到 {len(checkpoints)} 个 checkpoint:")
    for ckpt in checkpoints[-5:]:
        step = ckpt.split("-")[-1]
        marker = " ← 最新" if ckpt == latest else ""
        print(f"   checkpoint-{step}{marker}")
    
    return latest, latest_step


def get_training_state(checkpoint_path):
    """
    读取 checkpoint 的训练状态
    
    Returns:
        dict: 包含 epoch, global_step, total_steps 等信息
    """
    trainer_state_path = os.path.join(checkpoint_path, "trainer_state.json")
    
    if not os.path.exists(trainer_state_path):
        return None
    
    with open(trainer_state_path, 'r') as f:
        state = json.load(f)
    
    return {
        'epoch': state.get('epoch', 0),
        'global_step': state.get('global_step', 0),
        'max_steps': state.get('max_steps', 0),
        'total_flos': state.get('total_flos', 0)
    }


# 查找 checkpoint
resume_checkpoint = None
resume_step = 0

if RESUME_FROM_CHECKPOINT:
    resume_checkpoint, resume_step = get_latest_checkpoint(OUTPUT_DIR)
    
    if resume_checkpoint:
        state = get_training_state(resume_checkpoint)
        if state:
            print(f"\n✅ 将从以下 checkpoint 恢复训练:")
            print(f"   路径: {resume_checkpoint}")
            print(f"   已训练: {state['global_step']} 步 (Epoch {state['epoch']:.2f})")
            print(f"   总步数: {state['max_steps']} 步")
            resume_step = state['global_step']
        else:
            print(f"\n⚠️  无法读取训练状态，将从步数 {resume_step} 估算恢复")
    else:
        print(f"\n⚠️  未找到 checkpoint，将从头开始训练")
else:
    print(f"\n🔄 从头开始训练（已禁用断点续训）")

# ========================
# 模型与 Tokenizer 加载
# ========================

print("\n🚀 加载模型与分词器...")

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

# ✨✨✨ 根据是否有 checkpoint 决定加载方式
if resume_checkpoint:
    print(f"📂 从 checkpoint 加载模型: {os.path.basename(resume_checkpoint)}")
    
    # 加载基础模型
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16
    )
    
    model = prepare_model_for_kbit_training(model)
    
    # 加载 LoRA adapter
    model = PeftModel.from_pretrained(
        model,
        resume_checkpoint,
        is_trainable=True  # ⚠️ 必须设为 True
    )
    
    print(f"✅ 已加载 LoRA 权重 (步数: {resume_step})")
    
else:
    print(f"📂 从零开始初始化模型")
    
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.bfloat16
    )
    
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        # target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        target_modules=["q_proj", "v_proj"],
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

print("\n📂 加载数据集...")

dataset = load_dataset(
    "json",
    data_files={"train": TRAIN_PATH, "validation": VAL_PATH}
)

print(f"✅ 训练集: {len(dataset['train'])} 条")
print(f"✅ 验证集: {len(dataset['validation'])} 条")

# ========================
# 指令格式化
# ========================

PROMPT_TEMPLATE = """<|im_start|>system
你是一个URL安全检测系统,专门识别恶意URL。请判断给定URL是否存在威胁。
输出格式要求: 
- 如果URL安全,输出: 0|benign
- 如果URL存在威胁,输出: 1|威胁类型 (如 SQli,XSS,RCE等)
<|im_end|>
<|im_start|>user
{instruction}
输入URL: {input}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""

def format_instruction(example):
    """将数据格式化为指令模板"""
    # ✨ 处理可能缺失 instruction 字段的情况
    instruction = example.get("instruction", "判断以下URL是否存在安全威胁")
    
    prompt = PROMPT_TEMPLATE.format(
        instruction=instruction,
        input=example["input"],
        output=example["output"]
    )
    return {"text": prompt}

print("\n📝 格式化指令数据...")
dataset = dataset.map(format_instruction, remove_columns=dataset["train"].column_names)

# ========================
# Tokenize
# ========================

def tokenize_fn(examples):
    """批量分词处理"""
    model_inputs = {"input_ids": [], "attention_mask": [], "labels": []}
    
    for text in examples["text"]:
        tokenized = tokenizer(
            text,
            truncation=True,
            max_length=512,
            padding=False,
            add_special_tokens=True
        )
        
        input_ids = tokenized["input_ids"]
        attention_mask = tokenized["attention_mask"]
        
        # 找到 assistant 开始位置，只对输出部分计算损失
        assistant_marker = "<|im_start|>assistant\n"
        assistant_start_idx = text.find(assistant_marker)
        
        if assistant_start_idx != -1:
            prefix = text[:assistant_start_idx + len(assistant_marker)]
            prefix_ids = tokenizer(
                prefix, 
                add_special_tokens=True,
                truncation=True,
                max_length=512
            )["input_ids"]
            
            prefix_len = len(prefix_ids)
            
            if prefix_len > len(input_ids):
                prefix_len = len(input_ids)
            
            labels = [-100] * prefix_len + input_ids[prefix_len:]
            
            if len(labels) > len(input_ids):
                labels = labels[:len(input_ids)]
            elif len(labels) < len(input_ids):
                labels = labels + [-100] * (len(input_ids) - len(labels))
        else:
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

# ✨✨✨ 计算剩余训练步数
total_epochs = 5
per_device_batch_size = 2
gradient_accumulation = 8
effective_batch_size = per_device_batch_size * gradient_accumulation

# 计算总步数
num_samples = len(tokenized_datasets["train"])
steps_per_epoch = num_samples // effective_batch_size
total_steps = steps_per_epoch * total_epochs

# 如果从 checkpoint 恢复，计算剩余步数
if resume_checkpoint and resume_step > 0:
    remaining_steps = total_steps - resume_step
    remaining_epochs = remaining_steps / steps_per_epoch
    
    print(f"\n📊 训练进度:")
    print(f"   总步数: {total_steps}")
    print(f"   已完成: {resume_step} 步")
    print(f"   剩余: {remaining_steps} 步 ({remaining_epochs:.2f} epochs)")
else:
    remaining_steps = total_steps
    print(f"\n📊 训练配置:")
    print(f"   总步数: {total_steps}")

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=total_epochs,
    per_device_train_batch_size=per_device_batch_size,
    gradient_accumulation_steps=gradient_accumulation,
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
    metric_for_best_model="eval_loss",
    # ✨✨✨ 关键参数
    ignore_data_skip=False,  # ⚠️ 设为 False，让 Trainer 跳过已训练的数据
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
if resume_checkpoint:
    print("🔄 从 checkpoint 恢复训练...")
    print(f"📍 起始步数: {resume_step}")
    print(f"📍 剩余步数: {remaining_steps}")
else:
    print("🚀 开始全新 LoRA 微调...")

print("=" * 70)
print(f"📊 训练配置:")
print(f"   - 训练样本: {len(tokenized_datasets['train'])}")
print(f"   - 验证样本: {len(tokenized_datasets['validation'])}")
print(f"   - Batch Size: {per_device_batch_size}")
print(f"   - 梯度累积: {gradient_accumulation}")
print(f"   - 有效 Batch: {effective_batch_size}")
print(f"   - 学习率: {training_args.learning_rate}")
print(f"   - 总 Epochs: {total_epochs}")
print(f"   - 每 Epoch 步数: {steps_per_epoch}")
print("=" * 70)

# ✨✨✨ 关键：传入 resume_from_checkpoint 参数
trainer.train(resume_from_checkpoint=resume_checkpoint)

# ========================
# 保存模型
# ========================

print("\n💾 保存最终模型...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

print("\n" + "=" * 70)
print("✅ LoRA 微调完成!")
print("=" * 70)
print(f"📁 模型输出目录: {OUTPUT_DIR}")
print(f"📊 最终步数: {trainer.state.global_step}")
print("=" * 70)