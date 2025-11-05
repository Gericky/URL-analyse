"""FAISS向量存储管理器"""
import faiss
import numpy as np
import pickle
from typing import List, Tuple, Optional
from sentence_transformers import SentenceTransformer


class VectorStore:
    """FAISS向量存储管理器"""
    
    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5", dimension: int = 512):
        """
        初始化向量存储
        
        Args:
            model_name: SentenceTransformer模型名称
            dimension: 向量维度
        """
        print(f"🔄 正在加载BGE模型: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.dimension = dimension
        self.index = None
        self.metadata = []
        print(f"✅ BGE模型加载完成")
    
    def encode(self, texts: List[str]) -> np.ndarray:
        """
        将文本编码为向量
        
        Args:
            texts: 文本列表
            
        Returns:
            np.ndarray: 向量数组 (N, dimension)
        """
        # ✅ 归一化向量（使内积 = 余弦相似度）
        embeddings = self.model.encode(
            texts,
            normalize_embeddings=True,  # ← 关键：归一化
            show_progress_bar=False
        )
        return embeddings.astype('float32')
    
    def build_index(self, texts: List[str], labels: List[str], 
                    metadata: List[dict] = None):
        """
        构建向量索引
        
        Args:
            texts: 文本列表
            labels: 标签列表 ('normal' or 'attack')
            metadata: 元数据列表（可选）
        """
        if len(texts) != len(labels):
            raise ValueError("文本数量与标签数量不匹配")
        
        # 1. 文本向量化
        embeddings = self.encode(texts)
        
        # 2. ✨ 使用内积索引（对归一化向量等价于余弦相似度）
        self.index = faiss.IndexFlatIP(self.dimension)
        #                  ^^^^^^^^
        #                  内积索引（Inner Product）
        
        # 3. 添加向量到索引
        self.index.add(embeddings)
        
        # 4. 保存元数据
        self.metadata = [
            {
                'url': texts[i],
                'label': labels[i],
                'metadata': metadata[i] if metadata else {}
            }
            for i in range(len(texts))
        ]
        
        print(f"✅ 成功添加 {len(texts)} 条向量")
    
    def search(self, query_text: str, top_k: int = 5) -> List[Tuple[int, float]]:
        """
        搜索最相似的文本（使用余弦相似度）
        
        Args:
            query_text: 查询文本
            top_k: 返回前k个结果
            
        Returns:
            List[Tuple[int, float]]: [(索引, 余弦相似度), ...]
                                     余弦相似度范围: [0, 1]
        """
        if self.index is None:
            raise ValueError("向量库未初始化")
        
        # 1. 查询文本向量化（归一化）
        query_vector = self.encode([query_text])
        
        # 2. ✨ FAISS 检索（返回内积 = 余弦相似度）
        similarities, indices = self.index.search(query_vector, top_k)
        #   ^^^^^^^^^^^^  
        #   内积分数（对归一化向量 = 余弦相似度）
        
        # 3. 返回结果
        results = []
        for idx, sim in zip(indices[0], similarities[0]):
            if idx != -1:  # FAISS 用 -1 表示无效结果
                # ✅ 余弦相似度已经在 [0, 1] 范围内，无需转换
                results.append((int(idx), float(sim)))
        
        return results
    
    def save(self, index_path: str, metadata_path: str):
        """保存向量库和元数据"""
        if self.index is None:
            raise ValueError("向量库未初始化")
        
        # 保存FAISS索引
        faiss.write_index(self.index, index_path)
        
        # 保存元数据
        with open(metadata_path, 'wb') as f:
            pickle.dump(self.metadata, f)
        
        print(f"💾 向量库已保存:")
        print(f"   索引: {index_path}")
        print(f"   元数据: {metadata_path}")
    
    def load(self, index_path: str, metadata_path: str):
        """加载向量库和元数据"""
        # 加载FAISS索引
        self.index = faiss.read_index(index_path)
        
        # 加载元数据
        with open(metadata_path, 'rb') as f:
            self.metadata = pickle.load(f)
        
        print(f"✅ 成功加载向量库: {len(self.metadata)} 条记录")