"""Nexus AI: local-first assistant and tool-orchestration primitives."""

from .engine import NexusAI, NexusAIConfig
from .rag import Document, KnowledgeIndex

__all__ = ["Document", "KnowledgeIndex", "NexusAI", "NexusAIConfig"]
