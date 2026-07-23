"""Tests for the provider-independent Nexus AI core."""

import asyncio
import json

import httpx
import respx

from osint_toolkit.ai import (
    AIProfile,
    KnowledgeIndex,
    NexusAI,
    NexusAIConfig,
    enforce_evidence_contract,
    remove_authorization_boilerplate,
    sanitize_model_answer,
)


def test_core_mode_works_without_model():
    ai = NexusAI(NexusAIConfig(enabled=False))
    answer = ai._core_answer("bonjour")
    assert "Nexus AI" in answer


def test_memory_is_bounded():
    ai = NexusAI(NexusAIConfig(enabled=False))
    for number in range(20):
        ai._remember(str(number), "ok")
    assert len(ai.history) == 24


def test_configuration_has_local_default():
    config = NexusAIConfig()
    assert config.endpoint.startswith("http://127.0.0.1:")


def test_configuration_uses_profile_token_budget():
    profile = AIProfile("test", "test profile", "test/model", 2048, 77, 2)
    config = NexusAIConfig(profile=profile)
    assert config.max_tokens == 77
    assert config.enabled is True


def test_rag_retrieves_relevant_document():
    index = KnowledgeIndex.bundled()
    results = index.search("CSP security header web vulnerability")
    assert results
    assert results[0].source == "web_security.md"


def test_local_model_receives_retrieved_context():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        route = respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "Analyse CSP"}}]}
            )
        )
        answer = asyncio.run(ai.answer("Analyse un header CSP absent"))
    assert answer == "Analyse CSP"
    system_prompt = json.loads(route.calls[0].request.read())["messages"][0]["content"]
    assert "web_security.md" in system_prompt


def test_local_model_receives_fresh_tool_results():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        route = respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200, json={"choices": [{"message": {"content": "Synthèse fiable"}}]}
            )
        )
        answer = asyncio.run(
            ai.answer(
                "analyse example.com",
                runtime_context="dns | adresse: 203.0.113.10",
            )
        )
    assert answer == "Synthèse fiable"
    system_prompt = json.loads(route.calls[0].request.read())["messages"][0]["content"]
    assert "203.0.113.10" in system_prompt
    assert "Un pseudo identique" in system_prompt
    assert "URL construite" in system_prompt


def test_model_answer_is_deduplicated_and_guide_is_not_evidence():
    repeated = """**Source**: osint.md
## Verdict
- Attribution impossible avec les données actuelles.

**Source**: osint.md
## Verdict
- Attribution impossible avec les données actuelles.
"""
    answer = sanitize_model_answer(repeated)
    assert "osint.md" not in answer
    assert answer.count("Verdict") == 1
    assert answer.count("Attribution impossible") == 1


def test_empty_source_wording_is_repaired_and_vague_question_is_concretised():
    raw = (
        "La source  indique que l'absence de résultat ne prouve pas l'absence. "
        "\nPour une analyse plus précise, veuillez préciser votre objectif et "
        "la source spécifique que vous souhaitez examiner."
    )
    answer = sanitize_model_answer(raw)
    assert "La source" not in answer
    assert "En OSINT," in answer
    assert "source spécifique" not in answer
    assert "pivot concret" in answer


def test_verbose_authorization_refusal_can_be_replaced_by_ui_notice():
    raw = (
        "Je ne peux pas effectuer une attaque intrusive sans autorisation. "
        "Pour une analyse défensive, je peux vous proposer des modules de pentest "
        "tels que subdomains ou headers. Confirmez votre demande et je me mettrai "
        "à votre disposition."
    )
    assert remove_authorization_boilerplate(raw) == ""


def test_unattributed_username_contract_overrides_small_model_claims():
    unsafe = """Verdict : PROBABLE
Observations :
- Il y a 165 comptes trouvés, ce qui indique une activité active.
- Il y a 1000 entrées, ce qui suggère une grande quantité de fuites.
Prochaine étape :
- Analyser les fuites pour vérifier si elles sont liées à lui.
"""
    context = (
        "Même pseudo != même identité.\n"
        "NON ATTRIBUÉ : occurrences de l'identifiant uniquement"
    )
    answer = enforce_evidence_contract(unsafe, context)
    assert answer.startswith("Verdict\nNON ATTRIBUÉ")
    assert "PROBABLE" not in answer
    assert "comptes trouvés" not in answer
    assert "activité active" not in answer
    assert "Analyser les fuites" not in answer
    assert "signaux automatisés" in answer


def test_agent_model_decides_and_selects_tools():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"action":"scan","target":"example.com",'
                                    '"modules":["domain","breach"],'
                                    '"active":false,"rationale":"OSINT demandé"}'
                                )
                            }
                        }
                    ]
                },
            )
        )
        decision = asyncio.run(
            ai.plan("Enquête sur example.com", [("example.com", "domain")])
        )
    assert decision.action == "scan"
    assert decision.target == "example.com"
    assert decision.modules == ("domain", "breach")
    assert decision.active is False


def test_agent_model_can_keep_a_target_in_conversation():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"action":"chat","target":null,"modules":[],'
                                    '"active":false,"rationale":"question générale"}'
                                )
                            }
                        }
                    ]
                },
            )
        )
        decision = asyncio.run(
            ai.plan(
                "Que penses-tu de github.com ?",
                [("github.com", "domain")],
            )
        )
    assert decision.action == "chat"
    assert decision.modules == ()


def test_agent_rejects_an_invented_target():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"action":"scan","target":"other.example",'
                                    '"modules":["domain"],"active":false}'
                                )
                            }
                        }
                    ]
                },
            )
        )
        decision = asyncio.run(
            ai.plan("Analyse example.com", [("example.com", "domain")])
        )
    assert decision.action == "chat"


def test_agent_reviews_evidence_and_selects_bounded_new_pivots():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        route = respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "decision": "pivot",
                                        "confidence": "lead",
                                        "next_modules": [
                                            "domain",
                                            "headers",
                                            "ssl",
                                            "invented",
                                        ],
                                        "summary": "Configuration web partielle.",
                                        "gap": "TLS et en-têtes non vérifiés.",
                                        "rationale": "Compléter les contrôles passifs.",
                                    }
                                )
                            }
                        }
                    ]
                },
            )
        )
        review = asyncio.run(
            ai.review(
                "Recherche ce pseudo",
                "example.com",
                "domain",
                "[module=domain] une observation",
                {"domain"},
            )
        )
    assert review.decision == "pivot"
    assert review.confidence == "lead"
    assert review.next_modules == ("headers", "ssl")
    assert "TLS" in review.gap
    request = json.loads(route.calls[0].request.read())
    assert request["messages"][0]["content"].startswith("/no_think")
    assert "unique" in request["messages"][0]["content"]


def test_agent_review_stops_even_if_model_lists_modules():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"decision":"stop","confidence":"unattributed",'
                                    '"next_modules":["breach"],'
                                    '"summary":"Preuve insuffisante."}'
                                )
                            }
                        }
                    ]
                },
            )
        )
        review = asyncio.run(
            ai.review("analyse", "yanis", "username", "NON ATTRIBUÉ", {"username"})
        )
    assert review.decision == "stop"
    assert review.next_modules == ()


def test_explicit_scan_request_has_a_safe_fallback_when_model_says_chat():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"action":"chat","target":null,"modules":[],'
                                    '"rationale":"hésitation"}'
                                )
                            }
                        }
                    ]
                },
            )
        )
        decision = asyncio.run(
            ai.plan(
                "Recherche le pseudo yanis",
                [("yanis", "username")],
            )
        )
    assert decision.action == "scan"
    assert decision.modules == ("username",)
    assert "premier passage minimal" in decision.rationale


def test_username_review_cannot_claim_identity_even_if_model_does():
    endpoint = "http://127.0.0.1:18888/v1"
    ai = NexusAI(NexusAIConfig(endpoint=endpoint, model="test", enabled=True))
    with respx.mock:
        respx.post(f"{endpoint}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": json.dumps(
                                    {
                                        "decision": "pivot",
                                        "confidence": "confirmed",
                                        "next_modules": ["social", "breach"],
                                        "summary": "Identité confirmée.",
                                        "gap": "",
                                        "rationale": "Même pseudo.",
                                    }
                                )
                            }
                        }
                    ]
                },
            )
        )
        review = asyncio.run(
            ai.review(
                "Recherche Yanis",
                "yanis",
                "username",
                "[module=username] 165 pistes",
                {"username"},
            )
        )
    assert review.decision == "stop"
    assert review.confidence == "unattributed"
    assert review.next_modules == ()
    assert "aucune identité réelle" in review.summary
