"""Image OSINT — reverse image / face search + forensics link generator.

Given an image URL, generate direct reverse-image-search, face-recognition
and image-forensics links across the major engines. No API keys, no probing —
pure URL construction so it works offline and instantly.

Reverse image : Google Lens, Yandex, Bing Visual, TinEye, Baidu, Sogou
Face search   : PimEyes, FaceCheck.ID, Lenso.ai, Search4Faces
Forensics     : FotoForensics, ForensicallyBeta, Jimpl/EXIF, InVID
Reddit        : Karma Decay
"""

from __future__ import annotations

import re
from urllib.parse import quote, quote_plus

from ..models import ScanResult


URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def is_valid(target: str) -> bool:
    """Accept an http(s) URL — ideally pointing at an image."""
    return bool(URL_RE.match((target or "").strip()))


# ── Engines that accept an image URL as a query parameter ─────────

def _reverse_by_url(img: str) -> list[tuple[str, str]]:
    q = quote(img, safe="")
    return [
        ("Google Lens",     f"https://lens.google.com/uploadbyurl?url={q}"),
        ("Yandex Images",   f"https://yandex.com/images/search?rpt=imageview&url={q}"),
        ("Bing Visual",     f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}"),
        ("TinEye",          f"https://tineye.com/search?url={q}"),
        ("Baidu",           f"https://graph.baidu.com/details?image={q}"),
        ("Sogou",           f"https://pic.sogou.com/ris?query={q}"),
        ("Karma Decay (Reddit)", f"http://karmadecay.com/search?q={q}"),
    ]


def _face_by_url(img: str) -> list[tuple[str, str]]:
    q = quote(img, safe="")
    return [
        # These accept a pasted URL on their search page; deep-link where possible.
        ("FaceCheck.ID",    f"https://facecheck.id/?url={q}"),
        ("Lenso.ai",        "https://lenso.ai/en"),
        ("PimEyes",         "https://pimeyes.com/en"),
        ("Search4Faces",    "https://search4faces.com/en/"),
    ]


def _forensics(img: str) -> list[tuple[str, str]]:
    q = quote(img, safe="")
    return [
        ("FotoForensics (ELA)",  f"https://fotoforensics.com/?url={q}"),
        ("Forensically",         "https://29a.ch/photo-forensics/"),
        ("Metapicz (EXIF/GPS)",  f"https://metapicz.com/#landing?imgsrc={q}"),
        ("Jeffrey's EXIF viewer",f"http://exif.regex.info/exif.cgi?imgurl={q}"),
        ("Jimpl (EXIF/GPS)",     "https://jimpl.com/"),
        ("ExifData.com",         "https://exifdata.com/"),
        ("InVID / WeVerify",     "https://www.invid-project.eu/tools-and-services/invid-verification-plugin/"),
        ("Image Identify (AI)",  "https://imageidentify.com/"),
    ]


# ── Orchestrator ──────────────────────────────────────────────────

async def scan(target: str, *, timeout: float = 5.0) -> ScanResult:
    """Generate reverse-image / face / forensics links for an image URL.

    No network requests — pure URL construction.
    """
    result = ScanResult(target=target, module="image")

    if not is_valid(target):
        result.errors.append(
            "Provide a direct image URL (https://…/photo.jpg) — "
            "reverse-image engines need a hosted image."
        )
        # Still surface the engine homepages so the user can paste manually.
        for label, url in (
            ("Google Lens",   "https://lens.google.com/"),
            ("Yandex Images", "https://yandex.com/images/"),
            ("Bing Visual",   "https://www.bing.com/visualsearch"),
            ("TinEye",        "https://tineye.com/"),
            ("PimEyes",       "https://pimeyes.com/en"),
            ("FaceCheck.ID",  "https://facecheck.id/"),
        ):
            result.add("engines", label, url, "info", url=url)
        return result

    result.add("input", "Image URL", target, "info", url=target)

    for label, url in _reverse_by_url(target):
        result.add("reverse image", label, url, "info", url=url)
    for label, url in _face_by_url(target):
        result.add("face search", label, url, "warn", url=url)
    for label, url in _forensics(target):
        result.add("forensics", label, url, "info", url=url)

    result.raw["image_url"] = target
    return result
