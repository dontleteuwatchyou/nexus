"""Nexus AI: local-first assistant and tool-orchestration primitives."""

from .engine import (
    AgentDecision,
    NexusAI,
    NexusAIConfig,
    ReviewDecision,
    enforce_evidence_contract,
    sanitize_model_answer,
)
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
    "AgentDecision",
    "Document",
    "HardwareInfo",
    "KnowledgeIndex",
    "NexusAI",
    "NexusAIConfig",
    "ReviewDecision",
    "collect_live_metrics",
    "detect_hardware",
    "enforce_evidence_contract",
    "format_live_metrics",
    "sanitize_model_answer",
    "select_profile",
]
