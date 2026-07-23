"""Tests for the provider-independent Nexus AI core."""

from osint_toolkit.ai import NexusAI, NexusAIConfig


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
