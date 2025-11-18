"""RAG引擎 - 检索增强生成"""
import os
from typing import List, Dict, Optional
from .vector_store import VectorStore


class RAGEngine:
    """RAG引擎"""
    
    def __init__(self, config: dict):
        """
        初始化RAG引擎
        
        Args:
            config: RAG配置字典
        """
        self.config = config
        self.vector_store = None
        
        if config.get('enabled', False):
            self._init_vector_store()
    
    def _init_vector_store(self):
        """初始化向量存储"""
        self.vector_store = VectorStore(
            model_name=self.config.get('model_name', 'BAAI/bge-small-en-v1.5'),
            dimension=self.config.get('dimension', 512)
        )
        
        # 加载已有的向量库
        index_path = self.config.get('index_path', './data/rag/faiss.index')
        metadata_path = self.config.get('metadata_path', './data/rag/metadata.pkl')
        
        # ✨ 检查文件是否存在
        if os.path.exists(index_path) and os.path.exists(metadata_path):
            try:
                self.vector_store.load(index_path, metadata_path)
            except Exception as e:
                print(f"⚠️  加载向量库失败: {e}")
                print(f"💡 将创建新的向量库")
        else:
            print(f"⚠️  向量库文件不存在:")
            if not os.path.exists(index_path):
                print(f"   - 缺失: {index_path}")
            if not os.path.exists(metadata_path):
                print(f"   - 缺失: {metadata_path}")
            print(f"💡 请运行构建命令或等待自动构建")
    
    def retrieve_similar_cases(self, url: str, top_k: int = 5) -> List[Dict]:
        """
        检索相似的URL案例
        
        Args:
            url: 待检测的URL
            top_k: 返回前k个最相似的案例
            
        Returns:
            相似案例列表，按相似度降序排列
        """
        if not self.vector_store or not self.vector_store.index:
            return []
        
        # 1. 向量检索（返回余弦相似度）
        search_results = self.vector_store.search(url, top_k=top_k)
        
        # 2. 转换为相似案例
        similar_cases = []
        for idx, similarity_score in search_results:
            # ✅ similarity_score 已经是余弦相似度 [0, 1]
            
            # 获取元数据
            case_data = self.vector_store.metadata[idx]
            
            similar_cases.append({
                'url': case_data['url'],
                'label': case_data['label'],  # 'normal' or 'attack'
                'similarity_score': similarity_score,  # ✅ 余弦相似度
                'metadata': case_data.get('metadata', {})
            })
        
        return similar_cases
    
