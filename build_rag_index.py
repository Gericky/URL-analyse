"""构建RAG向量索引"""
import sys
import os

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.rag.vector_store import VectorStore
from src.until.config_loader import load_config


def build_index():
    """构建向量索引"""
    # 加载配置
    config = load_config()
    rag_config = config.get('rag', {})
    
    # 初始化向量存储
    print("🚀 初始化向量存储...")
    vector_store = VectorStore(
        model_name=rag_config.get('model_name', 'BAAI/bge-small-en-v1.5'),
        dimension=rag_config.get('dimension', 384)
    )
    
    # 1. 添加URL历史（从文件夹加载）
    url_history_folder = rag_config.get('url_history_folder', './data/rag/url_history')
    print(f"\n📚 加载URL历史文件夹: {url_history_folder}")
    vector_store.add_url_history_folder(url_history_folder)
    
    # 2. 添加知识库文档
    chunks_folder = rag_config.get('chunks_folder', './data/rag/chunks')
    print(f"\n📚 加载知识库文档: {chunks_folder}")
    vector_store.add_knowledge_documents(chunks_folder)
    
    # 3. 保存向量索引
    index_path = rag_config.get('index_path', './data/rag/faiss.index')
    metadata_path = rag_config.get('metadata_path', './data/rag/metadata.pkl')
    
    os.makedirs(os.path.dirname(index_path), exist_ok=True)
    
    print(f"\n💾 保存向量索引...")
    vector_store.save(index_path, metadata_path)
    
    print(f"\n✅ 向量索引构建完成!")
    print(f"   - 索引文件: {index_path}")
    print(f"   - 元数据文件: {metadata_path}")
    print(f"   - 总文档数: {len(vector_store.metadata)}")
    
    # 统计信息
    url_count = sum(1 for m in vector_store.metadata if m.get('type') == 'url_case')
    knowledge_count = sum(1 for m in vector_store.metadata if m.get('type') == 'knowledge')
    print(f"   - URL案例: {url_count}")
    print(f"   - 知识文档: {knowledge_count}")


if __name__ == '__main__':
    build_index()