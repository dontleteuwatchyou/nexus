"""Tests for the passive Discord identifier checker."""

import asyncio

from osint_toolkit import correlate as C
from osint_toolkit.modules import discord


def test_classify_discord_identifiers():
    assert discord.classify("@new.user") == ("username", "new.user")
    assert discord.classify("Legacy#1234") == ("legacy-tag", "Legacy#1234")
    assert discord.classify("175928847299117063") == (
        "snowflake",
        "175928847299117063",
    )
    assert discord.classify("bad username!") == ("invalid", "bad username!")


def test_snowflake_timestamp():
    assert discord.snowflake_created_at("175928847299117063").startswith(
        "2016-04-30T11:18:25"
    )


def test_scan_is_passive_and_has_limitations():
    result = asyncio.run(discord.scan("@new.user"))
    assert result.module == "discord"
    assert not result.errors
    assert result.raw["normalized"] == "new.user"
    assert result.by_source("manual lookup")
    assert result.by_source("limitations")


def test_discord_module_registered_explicit_only():
    assert C.OSINT_MODULES["discord"] is discord.scan
    assert C.OSINT_TARGET_TYPES["discord"] == set()
