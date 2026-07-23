"""Phone OSINT — fully offline using phonenumbers lib + free APIs.

Sources:
- phonenumbers lib (offline, parses E.164, type, carrier, region, timezone)
- phone-number-api.com (free, no key)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from urllib.parse import quote

import httpx

try:
    import phonenumbers
    from phonenumbers import carrier as ph_carrier
    from phonenumbers import geocoder as ph_geocoder
    from phonenumbers import timezone as ph_timezone
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

from ..http import get_json, session
from ..models import ScanResult

log = logging.getLogger("osint.phone")


# Default region for national-format numbers (no country code / leading 0).
# Override with the OSINT_DEFAULT_REGION env var (ISO-3166 alpha-2, e.g. "FR").
DEFAULT_REGION = (os.environ.get("OSINT_DEFAULT_REGION") or "BE").upper()


def normalize(phone: str, default_region: str | None = None) -> str:
    """Return an E.164 `+` number when possible.

    A national number (leading 0, no country code) is resolved against
    *default_region* — using the phonenumbers library when available so the
    right country code is applied, instead of blindly assuming one country.
    """
    region = (default_region or DEFAULT_REGION).upper()
    raw = re.sub(r"[\s\-\./\(\)]", "", phone or "")
    if not raw:
        return ""

    if raw.startswith("00"):
        return "+" + raw[2:]
    if raw.startswith("+"):
        return raw

    # National format (or bare digits). Prefer phonenumbers for a correct
    # country code; fall back to a simple region-code prefix map.
    if HAS_PHONENUMBERS:
        try:
            pn = phonenumbers.parse(raw, region)
            if phonenumbers.is_possible_number(pn):
                return phonenumbers.format_number(
                    pn, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException:
            pass

    if raw.startswith("0"):
        cc = _REGION_CC.get(region, "32")
        return f"+{cc}{raw[1:]}"
    return "+" + raw


# Minimal region → calling-code fallback (only used if phonenumbers absent).
_REGION_CC = {
    "BE": "32", "FR": "33", "US": "1", "GB": "44", "DE": "49", "NL": "31",
    "ES": "34", "IT": "39", "CH": "41", "LU": "352", "CA": "1", "PT": "351",
}


# ─── Sources ──────────────────────────────────────────────────────

def _offline_parse(e164: str) -> dict | None:
    if not HAS_PHONENUMBERS:
        return None
    try:
        pn = phonenumbers.parse(e164)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(pn):
        return None
    region = phonenumbers.region_code_for_number(pn) or "?"
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE:               "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE:           "Landline",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline / Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE:            "Toll-free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE:         "Premium",
        phonenumbers.PhoneNumberType.SHARED_COST:          "Shared cost",
        phonenumbers.PhoneNumberType.VOIP:                 "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER:      "Personal",
        phonenumbers.PhoneNumberType.PAGER:                "Pager",
        phonenumbers.PhoneNumberType.UAN:                  "UAN",
        phonenumbers.PhoneNumberType.VOICEMAIL:            "Voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN:              "Unknown",
    }
    return {
        "valid":       phonenumbers.is_valid_number(pn),
        "possible":    phonenumbers.is_possible_number(pn),
        "region":      region,
        "country_code": pn.country_code,
        "national":    pn.national_number,
        "type":        type_map.get(phonenumbers.number_type(pn), "Unknown"),
        "e164":        phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national_fmt":  phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL),
        "carrier":     ph_carrier.name_for_number(pn, "en") or None,
        "location":    ph_geocoder.description_for_number(pn, "en") or None,
        "timezones":   list(ph_timezone.time_zones_for_number(pn)) or None,
    }


async def _phone_api(client: httpx.AsyncClient, raw_digits: str) -> dict | None:
    """phone-number-api.com — free, no key."""
    j = await get_json(
        client, f"http://phone-number-api.com/newline/?number={raw_digits}",
        timeout=10,
    )
    if not j or not isinstance(j, dict) or j.get("status") != "success":
        return None
    return {
        "carrier":      j.get("carrier"),
        "line_type":    j.get("numberType"),
        "country":      j.get("countryName"),
        "country_code": j.get("country"),
        "city":         j.get("city"),
        "region":       j.get("regionName"),
        "lat":          j.get("lat"),
        "lon":          j.get("lon"),
        "timezone":     j.get("timezone"),
        "valid":        j.get("numberValid"),
    }


# ─── Orchestrator ─────────────────────────────────────────────────

async def scan(phone: str, timeout: float = 15.0,
               default_region: str | None = None) -> ScanResult:
    e164 = normalize(phone, default_region)
    result = ScanResult(target=phone, module="phone")

    if not e164:
        result.errors.append(f"Could not normalise number: {phone}")
        return result

    offline = _offline_parse(e164)
    if offline:
        result.raw["phonenumbers"] = offline
        result.add("phonenumbers", "Valid",
                   "Yes" if offline["valid"] else "No",
                   "found" if offline["valid"] else "warn")
        result.add("phonenumbers", "Region", offline["region"], "found")
        result.add("phonenumbers", "Type", offline["type"], "found")
        result.add("phonenumbers", "E.164", offline["e164"], "info")
        result.add("phonenumbers", "International", offline["international"], "info")
        result.add("phonenumbers", "National", offline["national_fmt"], "info")
        if offline.get("carrier"):
            result.add("phonenumbers", "Carrier", offline["carrier"], "found")
        if offline.get("location"):
            result.add("phonenumbers", "Location", offline["location"], "found")
        if offline.get("timezones"):
            result.add("phonenumbers", "Timezone(s)",
                       " · ".join(offline["timezones"]), "info")

    # Online cross-check
    digits = e164.lstrip("+")
    async with session(timeout=timeout) as client:
        api = await _phone_api(client, digits)

    if api:
        result.raw["phone_api"] = api
        for k, label in (
            ("carrier",   "Carrier (online)"),
            ("line_type", "Line type"),
            ("city",      "City"),
            ("region",    "Region"),
            ("lat",       "Latitude"),
            ("lon",       "Longitude"),
            ("timezone",  "Timezone"),
        ):
            v = api.get(k)
            if v:
                result.add("phone-api", label, str(v), "found")

    # Lookup suggestion links — these are recon-quality only
    if offline and offline.get("valid"):
        digits = e164.lstrip("+")
        region = (offline.get("region") or "us").lower()
        links = [
            ("WhatsApp",    f"https://wa.me/{digits}"),
            ("Telegram",    f"https://t.me/+{digits}"),
            ("Truecaller",  f"https://www.truecaller.com/search/{region}/{digits}"),
            ("Sync.me",     f"https://sync.me/search/?number={digits}"),
            ("NumLookup",   f"https://www.numlookup.com/?number={digits}"),
            ("Whocalld",    f"https://whocalld.com/+{digits}"),
            ("Google",      f"https://www.google.com/search?q=%22{quote('+' + digits)}%22"),
        ]
        for label, url in links:
            result.add("lookup", label, url, "info", url=url)

    return result
