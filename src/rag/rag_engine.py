"""RAG增强引擎"""
from typing import List, Dict, Any
from .vector_store import VectorStore
import logging

logger = logging.getLogger(__name__)


class RAGEngine:
    """RAG增强引擎"""
    
    def __init__(self, config: dict):
        """
        初始化RAG引擎
        
        Args:
            config: RAG配置
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        
        if not self.enabled:
            logger.info("RAG功能未启用")
            return
        
        print(f"\n{'='*60}")
        print(f"🚀 初始化RAG引擎")
        print(f"{'='*60}")
        
        self.vector_store = VectorStore(
            model_name=config.get('model_name', 'BAAI/bge-small-zh-v1.5'),
            dimension=config.get('dimension', 512)
        )
        
        # 尝试加载已有的向量库
        index_path = config.get('index_path', './data/rag/faiss.index')
        metadata_path = config.get('metadata_path', './data/rag/metadata.pkl')
        
        if self.vector_store.load(index_path, metadata_path):
            logger.info("✅ RAG引擎初始化完成")
        else:
            logger.warning("⚠️  未找到已有向量库，请先运行 build_rag_index.py 构建索引")
        
        print(f"{'='*60}\n")
    
    def build_index(self, normal_urls: List[str], attack_urls: List[str]):
        """
        构建向量索引（包含正常和攻击样本）
        
        Args:
            normal_urls: 正常URL列表
            attack_urls: 攻击URL列表
        """
        all_urls = normal_urls + attack_urls
        labels = ['normal'] * len(normal_urls) + ['attack'] * len(attack_urls)
        
        print(f"\n{'='*60}")
        print(f"📊 构建向量索引")
        print(f"{'='*60}")
        print(f"正常URL: {len(normal_urls)} 条")
        print(f"攻击URL: {len(attack_urls)} 条")
        print(f"总计: {len(all_urls)} 条")
        print(f"{'='*60}\n")
        
        self.vector_store.add_texts(all_urls, labels)
        
        # 保存索引
        index_path = self.config.get('index_path', './data/rag/faiss.index')
        metadata_path = self.config.get('metadata_path', './data/rag/metadata.pkl')
        
        self.vector_store.save(index_path, metadata_path)
        
        print(f"\n✅ 向量索引构建完成!")
    
    def retrieve_similar_cases(self, url: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        检索相似案例
        
        Args:
            url: 查询URL
            top_k: 返回数量
            
        Returns:
            相似案例列表
        """
        if not self.enabled:
            return []
        
        results = self.vector_store.search(url, k=top_k)
        
        similar_cases = []
        for text, label, distance, metadata in results:
            similar_cases.append({
                'url': text,
                'label': label,
                'similarity_score': 1.0 / (1.0 + distance),  # 转换为相似度分数
                'distance': distance,
                'metadata': metadata
            })
        
        return similar_cases
    
    def enhance_prompt(self, url: str, base_prompt: str, top_k: int = 3) -> str:
        """
        使用RAG增强提示词
        
        Args:
            url: 待分析URL
            base_prompt: 基础提示词
            top_k: 检索案例数量
            
        Returns:
            增强后的提示词
        """
        if not self.enabled:
            return base_prompt
        
        similar_cases = self.retrieve_similar_cases(url, top_k)
        
        if not similar_cases:
            return base_prompt
        
        # 构建案例说明
        examples_text = "\n\n### 参考相似案例:\n"
        for i, case in enumerate(similar_cases, 1):
            label_cn = "正常访问" if case['label'] == 'normal' else "攻击行为"
            examples_text += f"\n**案例 {i}** (相似度: {case['similarity_score']:.2%})\n"
            examples_text += f"- URL: `{case['url'][:100]}{'...' if len(case['url']) > 100 else ''}`\n"
            examples_text += f"- 类型: {label_cn}\n"
        
        # 增强提示词
        enhanced_prompt = base_prompt + examples_text + "\n\n### 任务\n基于以上相似案例和你的知识，请分析目标URL。"
        
        return enhanced_prompt