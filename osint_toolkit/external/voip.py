"""Inviteflood / ProtosSip / Siparmyknife / Sipcrack / Sipp / Sippts /
Sipsak / Voiphopper — VoIP & SIP testing tools."""

from __future__ import annotations

from ..models import ScanResult
from .base import ExternalTool


class Inviteflood(ExternalTool):
    name = "inviteflood"
    bin_name = "inviteflood"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("inviteflood", "Note", "Inviteflood is a SIP INVITE flood tool. Run manually: inviteflood", "info")
        return result


class ProtosSip(ExternalTool):
    name = "protos-sip"
    bin_name = "protos-sip"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("protos-sip", "Note", "Protos SIP is a SIP protocol testing tool. Run manually: protos-sip", "info")
        return result


class Siparmyknife(ExternalTool):
    name = "siparmyknife"
    bin_name = "siparmyknife"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("siparmyknife", "Note", "Siparmyknife is a SIP testing tool. Run manually: siparmyknife", "info")
        return result


class Sipcrack(ExternalTool):
    name = "sipcrack"
    bin_name = "sipcrack"
    accepted_kinds = {"file", "ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 120.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sipcrack", "Note", "Sipcrack is a SIP password cracker. Run manually: sipcrack", "info")
        return result


class Sipp(ExternalTool):
    name = "sipp"
    bin_name = "sipp"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sipp", "Note", "Sipp is a SIP traffic generator. Run manually: sipp", "info")
        return result


class Sippts(ExternalTool):
    name = "sippts"
    bin_name = "sippts"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sippts", "Note", "Sippts is a SIP security testing tool. Run manually: sippts", "info")
        return result


class Sipsak(ExternalTool):
    name = "sipsak"
    bin_name = "sipsak"
    accepted_kinds = {"ip", "domain"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("sipsak", "Note", "Sipsak is a SIP test tool. Run manually: sipsak", "info")
        return result


class Voiphopper(ExternalTool):
    name = "voiphopper"
    bin_name = "voiphopper"
    accepted_kinds = {"interface", "ip"}

    @classmethod
    async def scan(
        cls,
        target: str,
        *,
        timeout: float = 60.0,
        **kwargs,
    ) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.add("voiphopper", "Note", "Voiphopper is a VoIP VLAN hopping tool. Run manually: voiphopper", "info")
        return result
