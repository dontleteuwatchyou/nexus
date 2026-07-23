"""Regression tests for external-tool discovery."""

from osint_toolkit.external.toutatis import Toutatis


def test_pip_tool_detection_works_without_preimporting_importlib_util():
    status = Toutatis.install_status()
    assert status["name"] == "toutatis"
    assert isinstance(status["installed"], bool)
    assert status["checks"]
