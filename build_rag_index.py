"""构建RAG向量索引"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.until.config_loader import load_config
from src.rag.rag_engine import RAGEngine
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def load_urls(filepath: str) -> list:
    """加载URL文件"""
    if not os.path.exists(filepath):
        logger.error(f"❌ 文件不存在: {filepath}")
        return []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls


def main():
    print(f"\n{'='*60}")
    print(f"🔧 RAG向量库构建工具")
    print(f"{'='*60}\n")
    
    # 加载配置
    config = load_config('config.yaml')
    
    # 检查RAG是否启用
    if not config.get('rag', {}).get('enabled', False):
        logger.error("❌ RAG功能未启用，请在 config.yaml 中设置 rag.enabled: true")
        return
    
    # 初始化RAG引擎
    rag_engine = RAGEngine(config['rag'])
    
    # 加载训练数据
    data_dir = config['data']['dir']
    normal_file = os.path.join(data_dir, config['data']['normal_file'])
    attack_file = os.path.join(data_dir, config['data']['attack_file'])
    
    logger.info("📂 加载训练数据...")
    normal_urls = load_urls(normal_file)
    attack_urls = load_urls(attack_file)
    
    if not normal_urls and not attack_urls:
        logger.error("❌ 没有可用的训练数据")
        return
    
    logger.info(f"✅ 正常URL: {len(normal_urls)} 条")
    logger.info(f"✅ 攻击URL: {len(attack_urls)} 条")
    
    # 构建向量索引
    rag_engine.build_index(normal_urls, attack_urls)
    
    print(f"\n{'='*60}")
    print(f"✅ 向量库构建完成!")
    print(f"{'='*60}")
    print(f"\n💡 提示:")
    print(f"   现在可以运行 python main.py 进行URL检测")
    print(f"   系统将自动使用RAG增强检测能力\n")


if __name__ == '__main__':
    main()