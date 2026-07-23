"""Local-first conversational engine for Nexus.

The engine owns the Nexus prompt, memory and provider protocol.  It talks to
any OpenAI-compatible *local* server (llama.cpp, Ollama proxy, LM Studio, etc.)
and retains a useful deterministic mode when no model is running.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

import httpx

from .performance import AIProfile, select_profile
from .rag import KnowledgeIndex

SYSTEM_PROMPT = """/no_think
Tu es Nexus AI, analyste OSINT et sécurité. Réponds en français sauf demande
contraire. Tu analyses exclusivement les données fournies par Nexus et les
faits explicitement donnés par l'utilisateur.

CONTRAT DE PREUVE OBLIGATOIRE
- Un pseudo identique ne prouve jamais une identité identique. « yanis » peut
  appartenir à de nombreuses personnes. N'attribue aucun compte, fuite,
  ordinateur ou lieu à une personne sans au moins deux attributs indépendants
  et concordants (par exemple nom + photo + ville, ou email + profil lié).
- Une URL construite par les modules social/manual lookup est une piste à
  visiter, pas la preuve que la page existe ni qu'elle appartient à la cible.
- Un statut HTTP ou une détection automatisée de pseudo est une observation
  technique, pas une attribution d'identité.
- Une correspondance breach/infostealer sur un pseudo concerne l'identifiant
  saisi. Elle ne prouve ni que la personne visée est victime, ni que les
  occurrences appartiennent au même individu. Ne dis jamais « ses ordinateurs »
  ou « ses comptes » sans corrélation probante.
- Les documents RAG (`osint.md`, `reporting.md`, etc.) sont des guides de
  méthode, jamais des sources d'un constat. Ne les affiche pas comme Source.
- Ne transforme jamais une quantité, un lien de recherche manuelle, une erreur,
  un timeout ou une absence de résultat en fait confirmé.
- Utilise ces niveaux : CONFIRMÉ (preuve directe), PROBABLE (plusieurs attributs
  concordants), PISTE (un seul signal), NON ATTRIBUÉ (pseudo générique).
- Si la preuve est insuffisante, écris clairement « attribution impossible avec
  les données actuelles ». Ne complète rien de mémoire et n'invente rien.

FORMAT TERMINAL
Réponds une seule fois, sans répéter de bloc et sans tableau Markdown. Pour une
synthèse de scan, utilise au maximum quatre rubriques courtes : Verdict,
Observations, Limites, Prochaine étape. Une observation doit nommer sa vraie
source technique et son niveau de confiance. Évite les longues listes de liens :
regroupe-les et montre seulement les plus utiles.

PENTEST
Les actions actives sont réservées à un périmètre explicitement autorisé.
Distingue détection, validation et exploitabilité. Une bannière, une version ou
un header absent ne confirme pas une vulnérabilité. Favorise la reproduction,
la remédiation et les laboratoires isolés."""

PLANNER_PROMPT = """/no_think
Tu es le planificateur d'outils de Nexus AI. Décide si la demande exige une
action réelle ou seulement une réponse conversationnelle. Tu ne dois jamais
lancer un scan à cause de la simple présence d'une cible : l'intention de
l'utilisateur et le contexte priment. Choisis uniquement une cible candidate
et les modules strictement utiles.

Réponds uniquement avec un objet JSON :
{"action":"chat|scan","target":null|string,"modules":[],"active":false,
"rationale":"raison courte"}

Modules OSINT passifs : email, username, domain, ip, phone, url, social,
breach, github, discord, image, crypto.
Modules pentest : ports, subdomains, fingerprint, ssl, dirs, cors,
open-redirect, spring, js, s3, headers, dns-sec, graphql.
Les modules pentest nécessitent une demande explicite et une autorisation.
Si la demande est ambiguë, choisis chat et pose une question dans la réponse."""

REVIEWER_PROMPT = """/no_think
Tu es la couche d'analyse de Nexus AI. Après un premier passage d'outils, tu
évalues si les observations répondent réellement à la demande. Tu ne récites
pas les résultats : tu identifies le niveau de preuve, une contradiction ou
le principal manque, puis tu décides s'il faut arrêter ou effectuer un unique
pivot complémentaire.

Règles :
- Ne demande jamais un module déjà exécuté.
- Maximum deux modules complémentaires, strictement nécessaires.
- Ne change jamais de cible et ne transforme pas une URL/pseudo en identité.
- Un pseudo générique ou une preuve non attribuée doit normalement mener à
  `stop`, sauf si un module peut vérifier un attribut déjà présent.
- Les modules pentest actifs nécessitent toujours une autorisation explicite.
- `summary`, `gap` et `rationale` sont des justifications courtes destinées à
  l'utilisateur, pas une chaîne de pensée détaillée.

Réponds uniquement avec un objet JSON :
{"decision":"stop|pivot","confidence":"confirmed|probable|lead|unattributed",
"next_modules":[],"summary":"constat court","gap":"preuve manquante",
"rationale":"raison courte"}"""

ALLOWED_AGENT_MODULES = frozenset(
    {
        "email", "username", "domain", "ip", "phone", "url", "social",
        "breach", "github", "discord", "image", "crypto", "ports",
        "subdomains", "fingerprint", "ssl", "dirs", "cors",
        "open-redirect", "spring", "js", "s3", "headers", "dns-sec",
        "graphql",
    }
)

GUIDE_SOURCE_LINE = re.compile(
    r"^\s*(?:[-*]\s*)?(?:\*\*)?source(?:\*\*)?\s*:\s*"
    r"(?:osint|reporting|modules|web_security|identity_correlation|"
    r"breach_analysis|pentest_methodology)\.md\s*$",
    re.IGNORECASE,
)
EXPLICIT_SCAN_INTENT = re.compile(
    r"\b(?:analyse(?:r)?|cherche(?:r)?|recherche(?:r)?|scan(?:ne|ner)?|"
    r"trouve(?:r)?|vérifie(?:r)?|verifie(?:r)?|enqu[eê]te|osint|recon)\b",
    re.IGNORECASE,
)


def sanitize_model_answer(answer: str) -> str:
    """Make small-model output readable and remove exact repeated material."""
    cleaned: list[str] = []
    seen: set[str] = set()
    blank = False
    for raw_line in answer.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        line = raw_line.strip()
        if GUIDE_SOURCE_LINE.match(line):
            continue
        line = re.sub(r"^\s{0,3}#{1,6}\s*", "", line)
        line = line.replace("**", "").replace("__", "")
        if not line:
            if cleaned and not blank:
                cleaned.append("")
            blank = True
            continue
        blank = False
        signature = re.sub(r"^[\s>*•+\-–—]+", "", line)
        signature = re.sub(r"\s+", " ", signature).casefold()
        if len(signature) >= 4 and signature in seen:
            continue
        if len(signature) >= 4:
            seen.add(signature)
        cleaned.append(line)
    while cleaned and not cleaned[-1]:
        cleaned.pop()
    return "\n".join(cleaned).strip()


def enforce_evidence_contract(answer: str, runtime_context: str | None) -> str:
    """Apply non-negotiable attribution postconditions to model prose."""
    if not runtime_context or "NON ATTRIBUÉ" not in runtime_context.upper():
        return answer
    context_upper = runtime_context.upper()
    ambiguous_identity = (
        "MÊME PSEUDO != MÊME IDENTITÉ" in context_upper
        or "OCCURRENCES DE L'IDENTIFIANT UNIQUEMENT" in context_upper
    )
    if not ambiguous_identity:
        return answer

    observations: list[str] = []
    candidate_urls = list(
        dict.fromkeys(re.findall(r"https?://[^\s,)]+", runtime_context))
    )
    if candidate_urls:
        examples = ", ".join(candidate_urls[:3])
        suffix = f" (+{len(candidate_urls) - 3})" if len(candidate_urls) > 3 else ""
        observations.append(
            f"- SOCIAL · {len(candidate_urls)} URL candidate(s) : {examples}{suffix}. "
            "Existence et propriété non confirmées."
        )

    username_count = re.search(
        r"(?:Accounts found|Comptes trouvés)\s*:\s*(\d+)",
        runtime_context,
        re.IGNORECASE,
    )
    if username_count:
        observations.append(
            f"- USERNAME · {username_count.group(1)} correspondance(s) automatisée(s) "
            "du pseudo ; aucune identité n'est confirmée."
        )

    breach_seen: set[tuple[str, str, str]] = set()
    for line in runtime_context.splitlines():
        match = re.match(
            r"-\s*NON ATTRIBUÉ\s*\|\s*([^|]+)\s*\|\s*([^:]+):\s*(.+)",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        source, label, value = (part.strip() for part in match.groups())
        value = re.sub(r"\s*\(sévérité:.*$", "", value, flags=re.IGNORECASE)
        item = (source, label, value)
        if item in breach_seen:
            continue
        breach_seen.add(item)
        observations.append(
            f"- BREACH · {source} retourne « {label}: {value} » pour "
            "l'identifiant saisi ; résultat non attribué à une personne."
        )
        if len(breach_seen) >= 4:
            break

    if not observations:
        observations.append(
            "- Des signaux automatisés existent pour l'identifiant saisi, sans "
            "attribution d'identité possible."
        )

    report = [
        "Verdict",
        "NON ATTRIBUÉ — attribution impossible avec les données actuelles.",
        "",
        "Observations",
        *observations,
        "",
        "Limites",
        "- Même pseudo ≠ même identité ; une URL candidate n'est pas une preuve.",
        "- Les volumes breach décrivent l'index du fournisseur, pas les comptes "
        "ou appareils de la personne recherchée.",
        "",
        "Prochaine étape",
        "- Vérifier un pivot public et discriminant autorisé (profil connu, email "
        "ou domaine), puis corréler au moins deux attributs indépendants.",
        "- Ne pas consulter ni exposer de données de fuite sensibles.",
    ]
    return "\n".join(report)


@dataclass(frozen=True)
class AgentDecision:
    action: str = "chat"
    target: str | None = None
    target_type: str | None = None
    modules: tuple[str, ...] = ()
    active: bool = False
    rationale: str = ""


@dataclass(frozen=True)
class ReviewDecision:
    decision: str = "stop"
    confidence: str = "unattributed"
    next_modules: tuple[str, ...] = ()
    summary: str = "Preuves examinées ; aucun pivot automatique nécessaire."
    gap: str = ""
    rationale: str = ""


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

    @staticmethod
    def _fallback_plan(
        message: str, candidate_targets: list[tuple[str, str]]
    ) -> AgentDecision:
        if len(candidate_targets) != 1:
            return AgentDecision()
        target, target_type = candidate_targets[0]
        target_only = message.strip().rstrip(".,;:!?").casefold() == target.casefold()
        if not target_only and not EXPLICIT_SCAN_INTENT.search(message):
            return AgentDecision()
        minimal_modules = {
            "email": ("email",),
            "username": ("username",),
            "ip": ("ip",),
            "domain": ("domain",),
            "url": ("url",),
            "phone": ("phone",),
            "crypto": ("crypto",),
        }
        return AgentDecision(
            action="scan",
            target=target,
            target_type=target_type,
            modules=minimal_modules.get(target_type, ()),
            active=False,
            rationale="Demande explicite ; premier passage minimal avant revue.",
        )

    async def plan(
        self, message: str, candidate_targets: list[tuple[str, str]]
    ) -> AgentDecision:
        """Let the model decide whether Nexus should act and which tools to use."""
        if not candidate_targets:
            return AgentDecision()
        if not self.config.enabled:
            return self._fallback_plan(message, candidate_targets)

        candidates = [
            {"target": target, "type": target_type}
            for target, target_type in candidate_targets
        ]
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": PLANNER_PROMPT},
                *self.history[-6:],
                {
                    "role": "user",
                    "content": json.dumps(
                        {"request": message, "candidate_targets": candidates},
                        ensure_ascii=False,
                    ),
                },
            ],
            "temperature": 0,
            "max_tokens": 220,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        try:
            data = await self._post_completion(payload)
            content = str(data["choices"][0]["message"]["content"]).strip()
            match = re.search(r"\{.*\}", content, flags=re.DOTALL)
            raw = json.loads(match.group(0) if match else content)
        except (
            httpx.HTTPError, OSError, ValueError, KeyError, IndexError, TypeError
        ):
            return self._fallback_plan(message, candidate_targets)

        if str(raw.get("action", "")).lower() != "scan":
            fallback = self._fallback_plan(message, candidate_targets)
            if fallback.action == "scan":
                return fallback
            return AgentDecision(
                rationale=str(raw.get("rationale", ""))[:240]
            )

        requested_target = str(raw.get("target") or "")
        selected = next(
            (
                (target, target_type)
                for target, target_type in candidate_targets
                if target.casefold() == requested_target.casefold()
            ),
            None,
        )
        if selected is None:
            return AgentDecision(rationale="Cible proposée hors des candidates.")

        modules = tuple(
            dict.fromkeys(
                str(module).lower()
                for module in raw.get("modules", [])
                if str(module).lower() in ALLOWED_AGENT_MODULES
            )
        )[:4]
        return AgentDecision(
            action="scan",
            target=selected[0],
            target_type=selected[1],
            modules=modules,
            active=bool(raw.get("active", False)),
            rationale=str(raw.get("rationale", ""))[:240],
        )

    async def review(
        self,
        message: str,
        target: str,
        target_type: str,
        runtime_context: str,
        attempted_modules: set[str],
    ) -> ReviewDecision:
        """Evaluate evidence and optionally select one bounded follow-up pivot."""
        if not self.config.enabled:
            return ReviewDecision()
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": REVIEWER_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "request": message,
                            "target": target,
                            "target_type": target_type,
                            "attempted_modules": sorted(attempted_modules),
                            "evidence": runtime_context,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
            "temperature": 0,
            "max_tokens": 260,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        try:
            data = await self._post_completion(payload)
            content = str(data["choices"][0]["message"]["content"]).strip()
            match = re.search(r"\{.*\}", content, flags=re.DOTALL)
            raw = json.loads(match.group(0) if match else content)
        except (
            httpx.HTTPError, OSError, ValueError, KeyError, IndexError, TypeError
        ):
            return ReviewDecision(summary="Revue IA indisponible ; arrêt prudent.")

        confidence = str(raw.get("confidence", "unattributed")).lower()
        if confidence not in {"confirmed", "probable", "lead", "unattributed"}:
            confidence = "unattributed"
        modules = tuple(
            dict.fromkeys(
                str(module).lower()
                for module in raw.get("next_modules", [])
                if str(module).lower() in ALLOWED_AGENT_MODULES
                and str(module).lower() not in attempted_modules
            )
        )[:2]
        wants_pivot = str(raw.get("decision", "")).lower() == "pivot"
        if target_type == "username":
            confidence = "unattributed"
            modules = ()
            wants_pivot = False
            summary = (
                "Le pseudo produit des pistes, mais aucune identité réelle "
                "n'est attribuable avec ces seules preuves."
            )
            gap = (
                "Un pivot public et discriminant déjà connu : profil exact, "
                "email autorisé, domaine ou identifiant stable."
            )
            rationale = "Arrêt prudent : même pseudo ne signifie pas même personne."
        else:
            summary = sanitize_model_answer(str(raw.get("summary", "")))[:280]
            gap = sanitize_model_answer(str(raw.get("gap", "")))[:240]
            rationale = sanitize_model_answer(str(raw.get("rationale", "")))[:240]
        return ReviewDecision(
            decision="pivot" if wants_pivot and modules else "stop",
            confidence=confidence,
            next_modules=modules if wants_pivot else (),
            summary=summary or "Preuves examinées.",
            gap=gap,
            rationale=rationale,
        )

    async def answer(self, message: str, runtime_context: str | None = None) -> str:
        message = message.strip()
        if not message:
            return "Écris une question ou une cible à analyser."

        if self.config.enabled:
            try:
                answer = await self._local_completion(message, runtime_context)
                if answer:
                    self._remember(message, answer)
                    return answer
            except (
                httpx.HTTPError, OSError, ValueError, KeyError, IndexError, TypeError
            ):
                pass

        answer = self._core_answer(message)
        self._remember(message, answer)
        return answer

    async def _local_completion(
        self, message: str, runtime_context: str | None = None
    ) -> str:
        context = self.knowledge.context(message)
        system = SYSTEM_PROMPT
        if context:
            system += (
                "\n\nContexte documentaire Nexus à utiliser avec prudence. "
                "Cite le nom de la source et n'invente rien au-delà :\n" + context
            )
        if runtime_context:
            system += (
                "\n\nRésultats produits à l'instant par les outils Nexus. "
                "Fais-en une synthèse utile, indique les erreurs et n'ajoute aucun "
                "fait absent de ces résultats :\n" + runtime_context
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
        data = await self._post_completion(payload)
        return enforce_evidence_contract(
            sanitize_model_answer(
                str(data["choices"][0]["message"]["content"])
            ),
            runtime_context,
        )

    async def _post_completion(self, payload: dict[str, object]) -> dict:
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(
                f"{self.config.endpoint}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.config.api_key}"},
            )
            response.raise_for_status()
        return response.json()

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
            "lance `nexus-ai start`. Le premier lancement télécharge l’image CUDA "
            "et le modèle sélectionné pour ton matériel."
        )
