"""Nexus AI: local-first assistant and tool-orchestration primitives."""

from .engine import NexusAI, NexusAIConfig
from .performance import AIProfile, HardwareInfo, detect_hardware, select_profile
from .rag import Document, KnowledgeIndex

__all__ = [
    "AIProfile",
    "Document",
    "HardwareInfo",
    "KnowledgeIndex",
    "NexusAI",
    "NexusAIConfig",
    "detect_hardware",
    "select_profile",
]
