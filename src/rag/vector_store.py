"""FAISS向量存储管理器"""
import faiss
import numpy as np
import pickle
import os
from typing import List, Tuple, Optional
from sentence_transformers import SentenceTransformer


class VectorStore:
    """FAISS向量存储管理器"""
    
    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5", dimension: int = 512):
        """
        初始化向量存储
        
        Args:
            model_name: BGE模型名称
            dimension: 向量维度
        """
        print(f"🔄 正在加载BGE模型: {model_name}")
        self.encoder = SentenceTransformer(model_name)
        self.dimension = dimension
        self.index = faiss.IndexFlatL2(dimension)  # L2距离索引
        self.metadata = []  # 存储URL和标签信息
        print(f"✅ BGE模型加载完成")
        
    def add_texts(self, texts: List[str], labels: List[str], metadata: Optional[List[dict]] = None):
        """
        添加文本到向量库
        
        Args:
            texts: URL文本列表
            labels: 标签列表 (normal/attack)
            metadata: 额外元数据
        """
        print(f"🔄 正在编码 {len(texts)} 条URL...")
        # 编码文本
        embeddings = self.encoder.encode(texts, convert_to_numpy=True, show_progress_bar=True)
        
        # 添加到FAISS索引
        self.index.add(embeddings.astype('float32'))
        
        # 保存元数据
        for i, text in enumerate(texts):
            self.metadata.append({
                'text': text,
                'label': labels[i],
                'metadata': metadata[i] if metadata else {}
            })
        print(f"✅ 成功添加 {len(texts)} 条向量")
    
    def search(self, query: str, k: int = 5) -> List[Tuple[str, str, float, dict]]:
        """
        搜索最相似的URL
        
        Args:
            query: 查询URL
            k: 返回top-k结果
            
        Returns:
            [(url, label, distance, metadata), ...]
        """
        # 编码查询
        query_embedding = self.encoder.encode([query], convert_to_numpy=True)
        
        # 搜索
        distances, indices = self.index.search(query_embedding.astype('float32'), k)
        
        # 返回结果
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < len(self.metadata) and idx != -1:  # -1表示没找到足够的邻居
                meta = self.metadata[idx]
                results.append((
                    meta['text'],
                    meta['label'],
                    float(dist),
                    meta['metadata']
                ))
        
        return results
    
    def save(self, index_path: str, metadata_path: str):
        """保存向量库"""
        os.makedirs(os.path.dirname(index_path), exist_ok=True)
        faiss.write_index(self.index, index_path)
        with open(metadata_path, 'wb') as f:
            pickle.dump(self.metadata, f)
        print(f"💾 向量库已保存:")
        print(f"   索引: {index_path}")
        print(f"   元数据: {metadata_path}")
    
    def load(self, index_path: str, metadata_path: str):
        """加载向量库"""
        if os.path.exists(index_path) and os.path.exists(metadata_path):
            self.index = faiss.read_index(index_path)
            with open(metadata_path, 'rb') as f:
                self.metadata = pickle.load(f)
            print(f"✅ 成功加载向量库: {len(self.metadata)} 条记录")
            return True
        return False