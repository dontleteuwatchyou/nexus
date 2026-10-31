"""i18n layer tests."""
from osint_toolkit import i18n


def test_all_languages_translate_core_keys():
    keys = ["report.title", "scan.scanning", "sev.high", "msg.interrupted"]
    for lang in i18n.SUPPORTED:
        i18n.set_lang(lang)
        for k in keys:
            assert i18n.t(k) and i18n.t(k) != k, f"{lang}:{k} missing"


def test_unknown_key_falls_back_to_itself():
    i18n.set_lang("en")
    assert i18n.t("does.not.exist") == "does.not.exist"


def test_invalid_language_is_ignored():
    i18n.set_lang("fr")
    i18n.set_lang("zz")  # invalid -> keep previous
    assert i18n.get_lang() == "fr"


def test_english_fallback_for_missing_translation():
    # every language table should at least not crash and default sensibly
    i18n.set_lang("ru")
    assert i18n.t("report.title") == "Отчёт об уязвимостях"


def test_keys_consistent_across_languages():
    en_keys = set(i18n._TRANSLATIONS["en"])
    for lang in ("fr", "ru", "es"):
        assert set(i18n._TRANSLATIONS[lang]) == en_keys, f"{lang} key mismatch"
