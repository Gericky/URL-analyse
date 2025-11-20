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
            model_name=self.config.get('model_name','BAAI/bge-small-en-v1.5'),
            dimension=self.config.get('dimension', 384)
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
        检索相似的URL案例（只在URL案例中检索）
        
        Args:
            url: 待检测的URL
            top_k: 返回前k个最相似的案例
            
        Returns:
            相似案例列表，按相似度降序排列
        """
        if not self.vector_store or not self.vector_store.index:
            return []
        
        # ✨ 改动：调用新方法，只在URL案例中检索
        search_results = self.vector_store.search_in_url_cases_only(url, top_k=top_k)
        
        # 转换为相似案例
        similar_cases = []
        for idx, similarity_score in search_results:
            case_data = self.vector_store.metadata[idx]
            similar_cases.append({
                'url': case_data.get('url', ''),
                'label': case_data.get('label', ''),
                'similarity_score': similarity_score,
                'metadata': case_data.get('metadata', {})
            })
        
        return similar_cases
    def retrieve_knowledge(self, query: str, top_k: int = 3) -> List[Dict]:
        """
        检索相关的攻击知识（只在知识库文档中检索）
        
        Args:
            query: 查询文本（URL或描述）
            top_k: 返回前k个最相关的知识
            
        Returns:
            相关知识列表
        """
        if not self.vector_store or not self.vector_store.index:
            return []
        
        # ✨ 改动：调用新方法，只在知识库文档中检索
        search_results = self.vector_store.search_in_knowledge_only(query, top_k=top_k)
        
        # 转换为知识列表
        knowledge_list = []
        for idx, similarity_score in search_results:
            case_data = self.vector_store.metadata[idx]
            knowledge_list.append({
                'attack_id': case_data.get('attack_id', ''),
                'source': case_data.get('source', ''),
                'similarity_score': similarity_score,
            })
        
        return knowledge_list
    
    def get_knowledge_content(self, attack_id: str) -> str:
        """
        获取完整的知识内容
        
        Args:
            attack_id: 攻击类型ID
            
        Returns:
            知识内容文本
        """
        chunks_folder = self.config.get('chunks_folder', './data/rag/chunks')
        file_path = os.path.join(chunks_folder, f"{attack_id}.txt")
        
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        return ""
    
    def enhance_prompt_with_knowledge(self, url: str, top_k: int = 2) -> str:
        """
        用知识库增强提示词
        
        Args:
            url: 待分析的URL
            top_k: 检索top k个知识
            
        Returns:
            增强后的上下文文本
        """
        knowledge_list = self.retrieve_knowledge(url, top_k=top_k)
        
        if not knowledge_list:
            context_parts = ["\n## 相关攻击知识库:\n", "无相关知识"]
            return "".join(context_parts)
        
        context_parts = ["\n## 相关攻击知识库:\n"]
        
        for i, knowledge in enumerate(knowledge_list, 1):
            content = self.get_knowledge_content(knowledge['attack_id'])
            if content:
                context_parts.append(f"\n### 知识 {i} (相似度: {knowledge['similarity_score']:.2f})")
                context_parts.append(content)
                context_parts.append("\n")
        
        return "".join(context_parts)
