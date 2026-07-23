"""Social media link generator — no probing, just URLs to pivot quickly.

Given a username/email/phone/name, generate direct search & profile URLs
across 25+ platforms. Useful as a "next step" pivot after username/email
OSINT scans.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus

from ..models import ScanResult


# ── URL templates per category ────────────────────────────────────

USERNAME_PLATFORMS: list[tuple[str, str, str]] = [
    # (label, URL template, category)
    ("Twitter / X",       "https://x.com/{u}",                            "main"),
    ("Instagram",         "https://www.instagram.com/{u}/",               "main"),
    ("Facebook",          "https://www.facebook.com/{u}",                 "main"),
    ("LinkedIn",          "https://www.linkedin.com/in/{u}/",             "main"),
    ("Reddit",            "https://www.reddit.com/user/{u}/",             "main"),
    ("GitHub",            "https://github.com/{u}",                       "dev"),
    ("GitLab",            "https://gitlab.com/{u}",                       "dev"),
    ("Bitbucket",         "https://bitbucket.org/{u}/",                   "dev"),
    ("TikTok",            "https://www.tiktok.com/@{u}",                  "video"),
    ("YouTube",           "https://www.youtube.com/@{u}",                 "video"),
    ("Twitch",            "https://www.twitch.tv/{u}",                    "video"),
    ("Pinterest",         "https://www.pinterest.com/{u}/",               "main"),
    ("Snapchat",          "https://www.snapchat.com/add/{u}",             "main"),
    ("Telegram",          "https://t.me/{u}",                             "chat"),
    ("Discord (search)",  "https://discord.id/?prefill={u}",              "chat"),
    ("Mastodon (search)", "https://mastodon.social/@{u}",                 "chat"),
    ("Bluesky",           "https://bsky.app/profile/{u}.bsky.social",     "chat"),
    ("Threads",           "https://www.threads.net/@{u}",                 "main"),
    ("Vimeo",             "https://vimeo.com/{u}",                        "video"),
    ("SoundCloud",        "https://soundcloud.com/{u}",                   "audio"),
    ("Spotify",           "https://open.spotify.com/user/{u}",            "audio"),
    ("Last.fm",           "https://www.last.fm/user/{u}",                 "audio"),
    ("Steam",             "https://steamcommunity.com/id/{u}/",           "game"),
    ("Xbox",              "https://account.xbox.com/profile?gamertag={u}", "game"),
    ("Roblox",            "https://www.roblox.com/users/profile?username={u}", "game"),
    ("Medium",            "https://medium.com/@{u}",                      "blog"),
    ("Dev.to",            "https://dev.to/{u}",                           "blog"),
    ("HackerNews",        "https://news.ycombinator.com/user?id={u}",     "dev"),
    ("Keybase",           "https://keybase.io/{u}",                       "dev"),
    ("Patreon",           "https://www.patreon.com/{u}",                  "blog"),
    ("Ko-fi",             "https://ko-fi.com/{u}",                        "blog"),
    ("BuyMeACoffee",      "https://www.buymeacoffee.com/{u}",             "blog"),
    ("Tryhackme",         "https://tryhackme.com/p/{u}",                  "dev"),
    ("HackTheBox",        "https://app.hackthebox.com/users/{u}",         "dev"),
    ("Tumblr",            "https://{u}.tumblr.com",                       "blog"),
    ("Flickr",            "https://www.flickr.com/people/{u}/",           "main"),
    # ── extended set ──
    ("VK",                "https://vk.com/{u}",                           "main"),
    ("OK.ru",             "https://ok.ru/{u}",                            "main"),
    ("Weibo",             "https://weibo.com/{u}",                        "main"),
    ("Kick",              "https://kick.com/{u}",                         "video"),
    ("Rumble",            "https://rumble.com/user/{u}",                  "video"),
    ("Odysee",            "https://odysee.com/@{u}",                      "video"),
    ("Bandcamp",          "https://{u}.bandcamp.com",                     "audio"),
    ("Mixcloud",          "https://www.mixcloud.com/{u}/",                "audio"),
    ("Chess.com",         "https://www.chess.com/member/{u}",             "game"),
    ("Lichess",           "https://lichess.org/@/{u}",                    "game"),
    ("PSN Profiles",      "https://psnprofiles.com/{u}",                  "game"),
    ("Codewars",          "https://www.codewars.com/users/{u}",           "dev"),
    ("Kaggle",            "https://www.kaggle.com/{u}",                   "dev"),
    ("Replit",            "https://replit.com/@{u}",                      "dev"),
    ("StackOverflow",     "https://stackoverflow.com/users/{u}",          "dev"),
    ("PyPI",              "https://pypi.org/user/{u}/",                   "dev"),
    ("NPM",               "https://www.npmjs.com/~{u}",                   "dev"),
    ("DockerHub",         "https://hub.docker.com/u/{u}",                 "dev"),
    ("Substack",          "https://{u}.substack.com",                     "blog"),
    ("Wattpad",           "https://www.wattpad.com/user/{u}",             "blog"),
    ("Goodreads",         "https://www.goodreads.com/{u}",                "blog"),
    ("Behance",           "https://www.behance.net/{u}",                  "blog"),
    ("Dribbble",          "https://dribbble.com/{u}",                     "blog"),
    ("DeviantArt",        "https://www.deviantart.com/{u}",               "blog"),
    ("Gravatar",          "https://gravatar.com/{u}",                     "main"),
    ("Linktree",          "https://linktr.ee/{u}",                        "main"),
    ("About.me",          "https://about.me/{u}",                         "main"),
    ("Signal (username)", "https://signal.me/#u/{u}",                     "chat"),
    ("Wire",              "https://account.wire.com/user/{u}",            "chat"),
]


def _email_searches(email: str) -> list[tuple[str, str, str]]:
    """(label, url, group) — email pivots from the OSINT4ALL collection."""
    q = quote_plus(f'"{email}"')
    e = quote_plus(email)
    domain = email.split("@", 1)[1] if "@" in email else email
    return [
        # dedicated email OSINT tools
        ("Epieos",            "https://epieos.com/",                              "tools"),  # app, no GET deep-link
        ("IDCrawl",           f"https://www.idcrawl.com/search?q={e}",            "tools"),
        ("Intelligence X",    f"https://intelx.io/?s={e}",                        "tools"),
        ("EmailRep.io",       f"https://emailrep.io/{e}",                         "tools"),
        ("That'sThem",        f"https://thatsthem.com/email/{e}",                 "tools"),
        ("Skymem",            f"https://www.skymem.info/srch?q={e}",              "tools"),
        ("Email-Format (dom)",f"https://www.email-format.com/d/{quote_plus(domain)}/", "tools"),
        ("Hunter.io (dom)",   f"https://hunter.io/search/{quote_plus(domain)}",   "tools"),
        ("CentralOps Dossier",f"https://centralops.net/co/EmailDossier.aspx",     "tools"),
        # breach / leak
        ("Have I Been Pwned", f"https://haveibeenpwned.com/account/{e}",          "breach"),
        ("DeHashed",          f"https://dehashed.com/search?query={e}",           "breach"),
        ("LeakCheck",         f"https://leakcheck.io/",                           "breach"),
        ("BreachDirectory",   f"https://breachdirectory.org/?q={e}",              "breach"),
        # search engines / dorks
        ("Google",            f"https://www.google.com/search?q={q}",             "dork"),
        ("DuckDuckGo",        f"https://duckduckgo.com/?q={q}",                   "dork"),
        ("Bing",              f"https://www.bing.com/search?q={q}",               "dork"),
        ("Google · LinkedIn", f"https://www.google.com/search?q={q}+site%3Alinkedin.com", "dork"),
        ("Google · Pastebin", f"https://www.google.com/search?q={q}+site%3Apastebin.com", "dork"),
        ("Gravatar",          f"https://gravatar.com/{e}",                        "dork"),
    ]


def _phone_searches(phone: str) -> list[tuple[str, str, str]]:
    digits = re.sub(r"[^\d]", "", phone)
    q = quote_plus(phone)
    return [
        # messaging
        ("WhatsApp",           f"https://wa.me/{digits}",                         "chat"),
        ("Telegram",           f"https://t.me/+{digits}",                         "chat"),
        # reverse-phone lookups
        ("Truecaller",         f"https://www.truecaller.com/search/us/{digits}",  "lookup"),
        ("Sync.me",            f"https://sync.me/search/?number={digits}",        "lookup"),
        ("NumLookup",          f"https://www.numlookup.com/?number={digits}",     "lookup"),  # ?number= (200 ✓)
        ("SpyDialer",          f"https://www.spydialer.com/",                     "lookup"),
        ("WhoCalledMe",        f"https://whocalledme.com/lookup/{digits}",        "lookup"),
        ("ZLookup",            f"https://www.zlookup.com/",                       "lookup"),
        ("FreeCarrierLookup",  f"https://freecarrierlookup.com/",                 "lookup"),
        ("CallerIDTest",       f"https://www.calleridtest.com/",                  "lookup"),
        ("PhoneValidator",     f"https://www.phonevalidator.com/",                "lookup"),
        ("That'sThem (rev)",   f"https://thatsthem.com/reverse-phone-lookup",     "lookup"),
        ("WhitePages",         f"https://www.whitepages.com/phone/{digits}",      "lookup"),
        ("411",                f"https://www.411.com/phone/{digits}",             "lookup"),
        ("IDCrawl",            f"https://www.idcrawl.com/search?q={digits}",      "lookup"),
        # search engines
        ("Google",             f"https://www.google.com/search?q={q}",            "dork"),
        ("Google · social",    f"https://www.google.com/search?q={q}+OR+site%3Afacebook.com", "dork"),
    ]


def _name_searches(name: str) -> list[tuple[str, str, str]]:
    q = quote_plus(f'"{name}"')
    nm = quote_plus(name)
    dash = quote_plus(name.replace(" ", "-"))
    dash_l = quote_plus(name.lower().replace(" ", "-"))   # sites that want lowercase
    us_l = quote_plus(name.lower().replace(" ", "_"))     # underscore, lowercase
    parts = name.split()
    first = quote_plus(parts[0]) if parts else nm
    last = quote_plus(parts[-1]) if len(parts) > 1 else ""
    return [
        # search engines
        ("Google",            f"https://www.google.com/search?q={q}",             "dork"),
        ("Google Images",     f"https://www.google.com/search?q={q}&tbm=isch",    "dork"),
        ("DuckDuckGo",        f"https://duckduckgo.com/?q={q}",                   "dork"),
        ("Bing",              f"https://www.bing.com/search?q={q}",               "dork"),
        ("Yandex",            f"https://yandex.com/search/?text={q}",             "dork"),
        # social
        ("LinkedIn",          f"https://www.linkedin.com/search/results/people/?keywords={nm}", "social"),
        ("Facebook",          f"https://www.facebook.com/search/people/?q={nm}",  "social"),
        ("Twitter / X",       f"https://x.com/search?q={q}&f=user",               "social"),
        ("Instagram (Google)",f"https://www.google.com/search?q={q}+site%3Ainstagram.com", "social"),
        ("Reddit",            f"https://www.reddit.com/search/?q={q}&type=user",  "social"),
        # people-search aggregators
        ("IDCrawl",           f"https://www.idcrawl.com/search?q={nm}",           "people"),  # 202 ✓
        ("TruePeopleSearch",  f"https://www.truepeoplesearch.com/results?name={nm}", "people"),
        ("FastPeopleSearch",  f"https://www.fastpeoplesearch.com/name/{dash_l}",  "people"),  # lowercase
        ("SearchPeopleFree",  f"https://www.searchpeoplefree.com/find/{dash_l}",  "people"),
        ("That'sThem",        f"https://thatsthem.com/name/{dash}",               "people"),  # 200 ✓
        ("WhitePages",        f"https://www.whitepages.com/name/{dash}",          "people"),
        ("Spokeo",            f"https://www.spokeo.com/{dash}",                   "people"),
        ("Radaris",           f"https://radaris.com/p/{first}/{last}/",           "people"),  # /p/First/Last/
        ("PeekYou",           f"https://www.peekyou.com/{us_l}",                  "people"),  # first_last lowercase
        ("ZabaSearch",        f"https://www.zabasearch.com/people/{dash_l}/",     "people"),
        ("FamilyTreeNow",     f"https://www.familytreenow.com/search/genealogy/results?first={first}&last={last}", "people"),
        ("BeenVerified",      f"https://www.beenverified.com/people/{dash_l}/",   "people"),
        ("MyLife",            f"https://www.mylife.com/{dash_l}",                 "people"),
        ("Webmii",            f"https://webmii.com/people?n={nm}",                "people"),  # 200 ✓
        ("Yasni",             f"https://www.yasni.com/{dash}/check+people",       "people"),  # 200 ✓
        ("SocialCatfish",     f"https://socialcatfish.com/",                      "people"),  # form-only
        ("Pipl",              f"https://pipl.com/search/?q={nm}",                 "people"),
        ("411",               f"https://www.411.com/name/{dash_l}",               "people"),
    ]


def _username_tools(username: str) -> list[tuple[str, str]]:
    """Cross-platform username checkers / aggregators (web tools)."""
    u = quote_plus(username)
    return [
        ("WhatsMyName (web)", f"https://whatsmyname.app/?q={u}"),       # 200 ✓
        ("IDCrawl",           f"https://www.idcrawl.com/u/{u}"),        # 202 ✓
        ("InstantUsername",   f"https://instantusername.com/#/{u}"),    # 200 ✓
        ("KnowEm",            "https://knowem.com/"),                    # form-only landing
        ("Namechk",           "https://namechk.com/"),                   # JS app landing
        ("NameCheckr",        "https://www.namecheckr.com/"),            # JS app landing
        ("UserSearch.org",    "https://usersearch.org/"),                # form-only landing
        ("Google dork",       f"https://www.google.com/search?q=%22{u}%22"),
    ]


# ── Orchestrator ────────────────────────────────────────────────

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
EMAIL_RE    = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_RE    = re.compile(r"^\+?\d[\d\s\-\.\(\)/]{6,17}$")


def detect_kind(target: str) -> str:
    t = (target or "").strip()
    if EMAIL_RE.match(t):                              return "email"
    if PHONE_RE.match(t):                              return "phone"
    if " " in t.strip() and len(t.split()) >= 2:       return "name"
    if USERNAME_RE.match(t):                           return "username"
    return "username"  # default fallback


async def scan(target: str, *, timeout: float = 5.0,
                kind: str | None = None) -> ScanResult:
    """Generate social / search links for `target`.

    No network requests — pure URL construction.
    """
    kind = kind or detect_kind(target)
    result = ScanResult(target=target, module="social")

    result.add("kind", "Detected target type", kind, "info")

    if kind == "username":
        u = quote_plus(target)
        by_cat: dict[str, list] = {}
        for label, tmpl, cat in USERNAME_PLATFORMS:
            url = tmpl.replace("{u}", u)
            by_cat.setdefault(cat, []).append((label, url))
        cat_labels = {
            "main":  "Major platforms",
            "dev":   "Developer / tech",
            "video": "Video",
            "audio": "Music / audio",
            "game":  "Gaming",
            "chat":  "Messaging",
            "blog":  "Blogging / creator",
        }
        for cat, label in cat_labels.items():
            if cat in by_cat:
                for plat, url in by_cat[cat]:
                    result.add(label, plat, url, "info", url=url)
        # Cross-platform username checkers / aggregators
        for label, url in _username_tools(target):
            result.add("Username tools", label, url, "info", url=url)

    elif kind == "email":
        groups = {"tools": "Email tools", "breach": "Breach lookup",
                  "dork": "Search engines"}
        for label, url, grp in _email_searches(target):
            result.add(groups.get(grp, "Email search"), label, url, "info", url=url)

    elif kind == "phone":
        groups = {"chat": "Messaging", "lookup": "Reverse-phone lookup",
                  "dork": "Search engines"}
        for label, url, grp in _phone_searches(target):
            result.add(groups.get(grp, "Phone lookup"), label, url, "info", url=url)

    elif kind == "name":
        groups = {"dork": "Search engines", "social": "Social",
                  "people": "People-search"}
        for label, url, grp in _name_searches(target):
            result.add(groups.get(grp, "Name search"), label, url, "info", url=url)

    result.raw["kind"] = kind
    return result
