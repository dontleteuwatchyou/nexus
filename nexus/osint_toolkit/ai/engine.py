"""Local-first conversational engine for Nexus.

The engine owns the Nexus prompt, memory and provider protocol.  It talks to
any OpenAI-compatible *local* server (llama.cpp, Ollama proxy, LM Studio, etc.)
and retains a useful deterministic mode when no model is running.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from .performance import AIProfile, select_profile
from .rag import KnowledgeIndex

SYSTEM_PROMPT = """/no_think
Tu es Nexus AI, assistant spécialisé en OSINT et sécurité.
Tu aides à collecter et corréler des informations publiques, à analyser les
résultats Nexus et à travailler dans des laboratoires de pentest autorisés.
Sois précis, réponds en 8 lignes maximum, distingue faits et hypothèses, ne fabrique jamais de
résultat. Propose les modules Nexus adaptés. Pour une action intrusive,
demande une confirmation d'autorisation une fois par session. Favorise les
méthodes défensives et les preuves reproductibles."""


@dataclass(frozen=True)
class NexusAIConfig:
    profile: AIProfile = field(default_factory=select_profile)
    endpoint: str = field(
        default_factory=lambda: os.getenv(
            "NEXUS_AI_ENDPOINT", "http://127.0.0.1:8080/v1"
        ).rstrip("/")
    )
    model: str | None = None
    api_key: str = field(
        default_factory=lambda: os.getenv("NEXUS_AI_API_KEY", "nexus-local")
    )
    timeout: float | None = None
    max_tokens: int | None = None
    enabled: bool | None = None

    def __post_init__(self) -> None:
        model = os.getenv("NEXUS_AI_MODEL") or self.model or (
            "local" if self.profile.uses_model else None
        )
        timeout = self.timeout
        if timeout is None:
            timeout = float(os.getenv("NEXUS_AI_TIMEOUT", "120"))
        max_tokens = self.max_tokens
        if max_tokens is None:
            max_tokens = int(
                os.getenv("NEXUS_AI_MAX_TOKENS", str(self.profile.max_tokens or 180))
            )
        enabled_env = os.getenv("NEXUS_AI_LOCAL", "auto").lower()
        enabled = self.enabled
        if enabled is None:
            enabled = self.profile.uses_model and enabled_env not in {"0", "false", "off"}
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "timeout", timeout)
        object.__setattr__(self, "max_tokens", max_tokens)
        object.__setattr__(self, "enabled", enabled)


class NexusAI:
    """Small provider-independent assistant with bounded in-memory history."""

    def __init__(self, config: NexusAIConfig | None = None) -> None:
        self.config = config or NexusAIConfig()
        self.history: list[dict[str, str]] = []
        self.knowledge = KnowledgeIndex.bundled()

    @property
    def mode(self) -> str:
        return self.config.profile.name if self.config.enabled else "core"

    @property
    def runtime_summary(self) -> str:
        profile = self.config.profile
        if not self.config.enabled:
            return "core · sans modèle"
        return f"{profile.name} · {profile.model} · contexte {profile.context_size}"

    def reset(self) -> None:
        self.history.clear()

    async def answer(self, message: str) -> str:
        message = message.strip()
        if not message:
            return "Écris une question ou une cible à analyser."

        if self.config.enabled:
            try:
                answer = await self._local_completion(message)
                if answer:
                    self._remember(message, answer)
                    return answer
            except (httpx.HTTPError, OSError, ValueError):
                pass

        answer = self._core_answer(message)
        self._remember(message, answer)
        return answer

    async def _local_completion(self, message: str) -> str:
        context = self.knowledge.context(message)
        system = SYSTEM_PROMPT
        if context:
            system += (
                "\n\nContexte documentaire Nexus à utiliser avec prudence. "
                "Cite le nom de la source et n'invente rien au-delà :\n" + context
            )
        messages = [{"role": "system", "content": system}]
        messages.extend(self.history[-12:])
        messages.append({"role": "user", "content": message})
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.endpoint}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.config.api_key}"},
            )
            response.raise_for_status()
        data = response.json()
        return str(data["choices"][0]["message"]["content"]).strip()

    def _remember(self, user: str, assistant: str) -> None:
        self.history.extend(
            (
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            )
        )
        del self.history[:-24]

    @staticmethod
    def _core_answer(message: str) -> str:
        lowered = message.lower()
        if any(word in lowered for word in ("aide", "help", "possible", "faire")):
            return (
                "Nexus AI Core fonctionne sans modèle. Donne-moi un email, pseudo, "
                "domaine, URL, IP ou téléphone : je sélectionnerai les modules OSINT "
                "et corrélerai leurs résultats. Un modèle local peut enrichir les "
                "explications via NEXUS_AI_ENDPOINT."
            )
        if any(word in lowered for word in ("bonjour", "salut", "hello", "yo")):
            return (
                "Salut, je suis Nexus AI. Envoie une cible publique à analyser ou "
                "décris ton objectif OSINT/pentest."
            )
        return (
            "Le moteur conversationnel local n’est pas démarré. Les scans Nexus "
            "restent disponibles : saisis directement une cible. Pour le mode IA, "
            "lance `./scripts/local_ai.sh start`."
        )
