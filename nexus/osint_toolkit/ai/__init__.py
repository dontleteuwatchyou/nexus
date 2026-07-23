"""Nexus AI: local-first assistant and tool-orchestration primitives."""

from .engine import NexusAI, NexusAIConfig
from .performance import (
    AIProfile,
    HardwareInfo,
    collect_live_metrics,
    detect_hardware,
    format_live_metrics,
    select_profile,
)
from .rag import Document, KnowledgeIndex

__all__ = [
    "AIProfile",
    "Document",
    "HardwareInfo",
    "KnowledgeIndex",
    "NexusAI",
    "NexusAIConfig",
    "collect_live_metrics",
    "detect_hardware",
    "format_live_metrics",
    "select_profile",
]
