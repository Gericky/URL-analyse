"""FAISS向量存储管理器"""
import faiss
import numpy as np
import pickle
from typing import List, Tuple, Optional
from sentence_transformers import SentenceTransformer
import os 

class VectorStore:
    """FAISS向量存储管理器"""
    
    def __init__(self, model_name: str, dimension: int):
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
        print(f"✅ BGE模型加载完成 (维度: {dimension})")
    
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

    def add_url_history_folder(self, history_folder: str):
        """
        从文件夹加载URL历史（按攻击类型分类）
        
        Args:
            history_folder: URL历史文件夹路径
        """
        if not os.path.exists(history_folder):
            print(f"❌ URL历史文件夹不存在: {history_folder}")
            return
        
        urls = []
        url_metadata = []
        
        # 遍历文件夹中的所有文件
        for filename in os.listdir(history_folder):
            if filename.endswith('.txt'):
                # 文件名即为攻击类型
                attack_type = filename.replace('.txt', '')
                file_path = os.path.join(history_folder, filename)
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            urls.append(url)
                            url_metadata.append({
                                'type': 'url_case',
                                'url': url,
                                'label': attack_type,  # 'normal', 'sqli', 'xss', etc.
                                'metadata': {}
                            })
        
        if not urls:
            print(f"⚠️  未找到任何URL记录")
            return
        
        # 生成embeddings
        print(f"🔄 正在为 {len(urls)} 个URL生成向量...")
        embeddings = self.model.encode(urls, show_progress_bar=True)
        embeddings = np.array(embeddings).astype('float32')
        
        # 归一化
        faiss.normalize_L2(embeddings)
        
        # 添加到索引
        if self.index is None:
            self.index = faiss.IndexFlatIP(self.dimension)
        
        self.index.add(embeddings)
        self.metadata.extend(url_metadata)
        
        print(f"✅ 成功添加 {len(urls)} 个URL案例")        

        
    def add_knowledge_documents(self, chunks_folder: str):
        """
        添加知识库文档到向量库
        
        Args:
            chunks_folder: chunks文件夹路径
        """
        if not os.path.exists(chunks_folder):
            print(f"❌ Chunks文件夹不存在: {chunks_folder}")
            return
        
        texts = []
        chunk_metadata = []
        
        # 读取所有chunk文件
        for filename in os.listdir(chunks_folder):
            if filename.endswith('.txt'):
                file_path = os.path.join(chunks_folder, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                texts.append(content)
                chunk_metadata.append({
                    'type': 'knowledge',  # 标记为知识库文档
                    'attack_id': filename.replace('.txt', ''),
                    'source': filename
                })
        
        if not texts:
            print(f"⚠️  未找到任何chunk文件")
            return
        
        # 生成embeddings
        embeddings = self.model.encode(texts, show_progress_bar=True)
        embeddings = np.array(embeddings).astype('float32')
        
        # 归一化（用于余弦相似度）
        faiss.normalize_L2(embeddings)
        
        # 添加到索引
        if self.index is None:
            self.index = faiss.IndexFlatIP(self.dimension)
        
        self.index.add(embeddings)
        self.metadata.extend(chunk_metadata)
        
        print(f"✅ 成功添加 {len(texts)} 个知识库文档")
    def search_in_url_cases_only(self, query_text: str, top_k: int = 5) -> List[Tuple[int, float]]:
        """
        只在URL案例中检索
        
        Args:
            query_text: 查询文本
            top_k: 返回前k个结果
            
        Returns:
            List[Tuple[int, float]]: (索引, 相似度分数) 列表
        """
        if not self.index:
            return []
        
        # 1. 找出所有URL案例的索引
        url_indices = [i for i, m in enumerate(self.metadata) if m.get('type') == 'url_case']
        
        if not url_indices:
            return []
        
        # 2. 对查询文本编码
        query_embedding = self.encode([query_text])[0:1]
        
        # 3. 获取所有向量
        all_vectors = self.index.reconstruct_n(0, self.index.ntotal)
        
        # 4. 只取URL案例的向量
        url_vectors = np.array([all_vectors[i] for i in url_indices])
        
        # 5. 计算相似度
        similarities = np.dot(query_embedding, url_vectors.T)[0]
        
        # 6. 排序并取top k
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # 7. 返回原始索引和相似度
        results = []
        for idx in top_indices:
            original_idx = url_indices[idx]
            score = float(similarities[idx])
            results.append((original_idx, score))
        
        return results
    
    # ✨ 新增方法2：只在知识库文档中检索
    def search_in_knowledge_only(self, query_text: str, top_k: int = 5) -> List[Tuple[int, float]]:
        """
        只在知识库文档中检索
        
        Args:
            query_text: 查询文本
            top_k: 返回前k个结果
            
        Returns:
            List[Tuple[int, float]]: (索引, 相似度分数) 列表
        """
        if not self.index:
            return []
        
        # 1. 找出所有知识库文档的索引
        knowledge_indices = [i for i, m in enumerate(self.metadata) if m.get('type') == 'knowledge']
        
        if not knowledge_indices:
            return []
        
        # 2. 对查询文本编码
        query_embedding = self.encode([query_text])[0:1]
        
        # 3. 获取所有向量
        all_vectors = self.index.reconstruct_n(0, self.index.ntotal)
        
        # 4. 只取知识库文档的向量
        knowledge_vectors = np.array([all_vectors[i] for i in knowledge_indices])
        
        # 5. 计算相似度
        similarities = np.dot(query_embedding, knowledge_vectors.T)[0]
        
        # 6. 排序并取top k
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # 7. 返回原始索引和相似度
        results = []
        for idx in top_indices:
            original_idx = knowledge_indices[idx]
            score = float(similarities[idx])
            results.append((original_idx, score))
        
        return results