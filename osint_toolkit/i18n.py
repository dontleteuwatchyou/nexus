"""Minimal internationalisation layer (EN / FR / RU / ES).

Usage::

    from . import i18n
    i18n.t("report.title")            # -> localized string
    i18n.set_lang("fr")               # force a language

Language resolution order: an explicit :func:`set_lang`, then the
``NEXUS_LANG`` / ``OSINT_LANG`` environment variables, then the system locale,
then English. Unknown keys fall back to English, then to the key itself, so a
missing translation is never fatal.
"""

from __future__ import annotations

import os

DEFAULT_LANG = "en"
SUPPORTED = ("en", "fr", "ru", "es")

LANG_NAMES = {"en": "English", "fr": "Français", "ru": "Русский", "es": "Español"}

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": {
        "app.subtitle": "intelligence framework",
        "app.open_sources": "100% open sources",
        "app.no_keys": "no API keys required",
        "scan.scanning": "Scanning",
        "scan.probing": "Probing",
        "scan.full": "Full scanning",
        "scan.all_modules": "all applicable modules",
        "report.title": "Vulnerability report",
        "report.summary": "Summary",
        "report.none": "No security-relevant findings reported.",
        "sev.critical": "critical", "sev.high": "high",
        "sev.medium": "medium", "sev.low": "low",
        "save.json": "JSON saved", "save.html": "HTML report saved",
        "list.osint": "OSINT modules:", "list.pentest": "PENTEST modules:",
        "list.external": "EXTERNAL tools:",
        "status.installed": "installed", "status.not_installed": "not installed",
        "err.no_type": "Could not detect target type",
        "msg.interrupted": "Interrupted.",
    },
    "fr": {
        "app.subtitle": "framework de renseignement",
        "app.open_sources": "100% sources ouvertes",
        "app.no_keys": "aucune clé API requise",
        "scan.scanning": "Analyse",
        "scan.probing": "Sondage",
        "scan.full": "Analyse complète",
        "scan.all_modules": "tous les modules applicables",
        "report.title": "Rapport de vulnérabilités",
        "report.summary": "Résumé",
        "report.none": "Aucun résultat pertinent pour la sécurité.",
        "sev.critical": "critique", "sev.high": "élevée",
        "sev.medium": "moyenne", "sev.low": "faible",
        "save.json": "JSON enregistré", "save.html": "Rapport HTML enregistré",
        "list.osint": "Modules OSINT :", "list.pentest": "Modules PENTEST :",
        "list.external": "Outils EXTERNES :",
        "status.installed": "installé", "status.not_installed": "non installé",
        "err.no_type": "Impossible de détecter le type de cible",
        "msg.interrupted": "Interrompu.",
    },
    "ru": {
        "app.subtitle": "платформа разведки",
        "app.open_sources": "100% открытые источники",
        "app.no_keys": "API-ключи не требуются",
        "scan.scanning": "Сканирование",
        "scan.probing": "Зондирование",
        "scan.full": "Полное сканирование",
        "scan.all_modules": "все применимые модули",
        "report.title": "Отчёт об уязвимостях",
        "report.summary": "Сводка",
        "report.none": "Значимых для безопасности находок нет.",
        "sev.critical": "критический", "sev.high": "высокий",
        "sev.medium": "средний", "sev.low": "низкий",
        "save.json": "JSON сохранён", "save.html": "HTML-отчёт сохранён",
        "list.osint": "Модули OSINT:", "list.pentest": "Модули PENTEST:",
        "list.external": "Внешние инструменты:",
        "status.installed": "установлен", "status.not_installed": "не установлен",
        "err.no_type": "Не удалось определить тип цели",
        "msg.interrupted": "Прервано.",
    },
    "es": {
        "app.subtitle": "marco de inteligencia",
        "app.open_sources": "100% fuentes abiertas",
        "app.no_keys": "no requiere claves API",
        "scan.scanning": "Escaneando",
        "scan.probing": "Sondeando",
        "scan.full": "Escaneo completo",
        "scan.all_modules": "todos los módulos aplicables",
        "report.title": "Informe de vulnerabilidades",
        "report.summary": "Resumen",
        "report.none": "No se encontraron hallazgos relevantes de seguridad.",
        "sev.critical": "crítica", "sev.high": "alta",
        "sev.medium": "media", "sev.low": "baja",
        "save.json": "JSON guardado", "save.html": "Informe HTML guardado",
        "list.osint": "Módulos OSINT:", "list.pentest": "Módulos PENTEST:",
        "list.external": "Herramientas EXTERNAS:",
        "status.installed": "instalado", "status.not_installed": "no instalado",
        "err.no_type": "No se pudo detectar el tipo de objetivo",
        "msg.interrupted": "Interrumpido.",
    },
}

_current: str | None = None


def _detect() -> str:
    for env in ("NEXUS_LANG", "OSINT_LANG", "LC_ALL", "LANG"):
        v = os.environ.get(env)
        if v:
            code = v.split(".")[0].split("_")[0].lower()
            if code in SUPPORTED:
                return code
    try:
        import locale
        loc = (locale.getlocale()[0] or "")
        code = loc.split("_")[0].lower()
        if code in SUPPORTED:
            return code
    except Exception:
        pass
    return DEFAULT_LANG


def set_lang(lang: str | None) -> None:
    global _current
    if lang and lang.lower() in SUPPORTED:
        _current = lang.lower()


def get_lang() -> str:
    global _current
    if _current is None:
        _current = _detect()
    return _current


def t(key: str, **kwargs) -> str:
    lang = get_lang()
    s = (_TRANSLATIONS.get(lang, {}).get(key)
         or _TRANSLATIONS["en"].get(key)
         or key)
    if kwargs:
        try:
            s = s.format(**kwargs)
        except Exception:
            pass
    return s
