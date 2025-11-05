"""构建RAG向量索引"""
import os
import sys
import logging

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.until.config_loader import load_config
from src.rag.vector_store import VectorStore

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def load_urls(filepath: str) -> list:
    """从文件加载URL列表"""
    with open(filepath, 'r', encoding='utf-8') as f:
        # 每行格式: URL\t参数（可选）
        # 只取第一列作为URL
        urls = []
        for line in f:
            line = line.strip()
            if line:
                # 如果有tab，只取第一部分
                url = line.split('\t')[0] if '\t' in line else line
                urls.append(url)
        return urls


def main():
    """主函数：构建RAG向量索引"""
    
    print("=" * 60)
    print("🔧 RAG向量库构建工具")
    print("=" * 60)
    
    # ========== 加载配置 ==========
    config = load_config()
    rag_config = config['rag']
    data_config = config['data']
    
    # ========== 初始化向量存储（不加载旧索引） ==========
    print("\n" + "=" * 60)
    print("🚀 初始化向量存储")
    print("=" * 60)
    
    vector_store = VectorStore(
        model_name=rag_config['model_name'],
        dimension=rag_config['dimension']
    )
    print("=" * 60)
    
    # ========== 加载训练数据 ==========
    print("\n📂 加载训练数据...")
    
    normal_file = os.path.join(data_config['dir'], data_config['normal_file'])
    attack_file = os.path.join(data_config['dir'], data_config['attack_file'])
    
    normal_urls = load_urls(normal_file)
    attack_urls = load_urls(attack_file)
    
    print(f"✅ 正常URL: {len(normal_urls)} 条")
    print(f"✅ 攻击URL: {len(attack_urls)} 条")
    
    # ========== 合并数据 ==========
    all_urls = normal_urls + attack_urls
    all_labels = ['normal'] * len(normal_urls) + ['attack'] * len(attack_urls)
    
    # ========== 构建向量索引 ==========
    print("\n" + "=" * 60)
    print("📊 构建向量索引")
    print("=" * 60)
    print(f"正常URL: {len(normal_urls)} 条")
    print(f"攻击URL: {len(attack_urls)} 条")
    print(f"总计: {len(all_urls)} 条")
    print("=" * 60 + "\n")
    
    print(f"🔄 正在编码 {len(all_urls)} 条URL...")
    vector_store.build_index(all_urls, all_labels)
    
    # ========== 保存向量库 ==========
    index_path = rag_config['index_path']
    metadata_path = rag_config['metadata_path']
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(index_path), exist_ok=True)
    
    vector_store.save(index_path, metadata_path)
    
    # ========== 完成 ==========
    print("\n" + "=" * 60)
    print("✅ 向量库构建完成!")
    print("=" * 60)
    
    # ========== 测试检索 ==========
    print("\n" + "=" * 60)
    print("🧪 测试向量检索")
    print("=" * 60)
    
    test_urls = [
        "/api/user?id=1' or 1=1--",
        "/api/user?id=123",
        "/admin/login"
    ]
    
    for test_url in test_urls:
        print(f"\n查询: {test_url}")
        results = vector_store.search(test_url, top_k=3)
        
        for i, (idx, similarity) in enumerate(results, 1):
            case = vector_store.metadata[idx]
            print(f"  {i}. [{case['label']:6s}] 相似度: {similarity:.2%} | {case['url'][:60]}")
    
    print("\n" + "=" * 60)
    print("🎉 测试完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()