"""Tests for the provider-independent Nexus AI core."""

import asyncio

import httpx
import respx

from osint_toolkit.ai import KnowledgeIndex, NexusAI, NexusAIConfig


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
    system_prompt = route.calls[0].request.read().decode()
    assert "web_security.md" in system_prompt
