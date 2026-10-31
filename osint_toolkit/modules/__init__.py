"""OSINT scan modules — passive sources, one per target type + add-ons."""

from . import breach, domain, email, github, ip, phone, social, username, web

__all__ = ["email", "username", "domain", "ip", "phone", "web",
            "social", "breach", "github"]
