"""Mr.Holmes — multi-purpose OSINT tool (Lucksi/Mr.Holmes).

Repo: https://github.com/Lucksi/Mr.Holmes
Accepted inputs: email, username, phone, IP, domain.

⚠ Mr.Holmes is primarily an interactive tool. The wrapper tries
non-interactive CLI flags first; if those aren't supported by the
installed version, the tool may hang or crash on import. Run it
manually if the wrapper output is incomplete:

    cd ~/.osint-toolkit/tools/mrholmes && python3 MrHolmes.py
"""

from __future__ import annotations

import re
import sys

from ..models import ScanResult
from .base import ExternalTool


class MrHolmes(ExternalTool):
    name = "Mr.Holmes"
    repo_url = "https://github.com/Lucksi/Mr.Holmes.git"
    # Cover all known entry-point names across forks/versions
    script_candidates = ["MrHolmes.py", "mr_holmes.py", "Mr.Holmes.py",
                          "mrholmes.py", "Mr_Holmes.py", "main.py", "holmes.py"]
    accepted_kinds = {"email", "username", "phone", "ip", "domain"}

    KIND_FLAGS = {
        "username": ["--username"],
        "email":    ["--email"],
        "phone":    ["--phone"],
        "ip":       ["--ip"],
        "domain":   ["--domain"],
    }

    @classmethod
    def _ensure_settings(cls) -> str | None:
        """Pre-create Settings.ini with a [Settings] section.

        Mr.Holmes crashes on first run because Core/Support/Language.py
        reads config['Settings'] at import time, but the .ini file may
        be missing the section. Returns a status string for the result.
        """
        install = cls.install_dir()
        if not install.exists():
            return None

        candidates = [
            install / "Core" / "Settings" / "Settings.ini",
            install / "Settings.ini",
            install / "Core" / "Settings.ini",
            install / "Settings" / "Settings.ini",
        ]
        target = None
        for c in candidates:
            if c.exists():
                target = c
                break
        if target is None:
            # Most common Mr.Holmes layout
            target = install / "Core" / "Settings" / "Settings.ini"

        needs_init = True
        if target.exists():
            try:
                content = target.read_text(encoding="utf-8", errors="ignore")
                if "[Settings]" in content:
                    needs_init = False
            except Exception:
                pass

        if not needs_init:
            return f"using existing {target.name}"

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "[Settings]\n"
                "Language = English\n"
                "Color = True\n"
                "Theme = Default\n"
                "\n"
                "[API_Keys]\n"
                "Shodan = None\n"
                "HIBP = None\n"
                "VirusTotal = None\n"
                "Hunter = None\n",
                encoding="utf-8",
            )
            return f"created {target}"
        except Exception as e:
            return f"could not write {target}: {e}"

    @classmethod
    async def scan(cls, target: str, *, kind: str = "username",
                    timeout: float = 90.0, **kwargs) -> ScanResult:
        if not cls.is_installed():
            return cls._not_installed_result(target)

        # Fall back to username if kind couldn't be detected
        if kind not in cls.KIND_FLAGS:
            kind = "username"

        flag = cls.KIND_FLAGS[kind]

        script = cls.find_script()
        if script is None:
            return cls._not_installed_result(target)

        # Pre-flight: ensure Settings.ini has [Settings] section
        settings_status = cls._ensure_settings()

        rc, stdout, stderr = await cls._run_subprocess(
            [sys.executable, str(script), *flag, target],
            timeout=timeout, cwd=cls.install_dir(),
        )

        result = ScanResult(target=target, module=f"external:{cls.name}")
        result.raw["return_code"]   = rc
        result.raw["stdout"]        = stdout[:50000]
        result.raw["stderr"]        = stderr[:8000]
        result.raw["script_used"]   = str(script)
        result.raw["settings_init"] = settings_status

        if settings_status:
            result.add("setup", "Settings.ini", settings_status, "info")

        if rc != 0 and not stdout:
            err_lines = [l for l in stderr.splitlines() if l.strip()]
            result.errors.append(f"Mr.Holmes exited {rc}. Last stderr lines:")
            for line in err_lines[-10:]:
                result.add("stderr", "line", line[:200], "error")
            result.add("hint", "Possible cause",
                        "Mr.Holmes may be interactive or incompatible with your Python "
                        "version. Try running manually: "
                        f"cd {cls.install_dir()} && python3 {script.name}",
                        "info")
            return result

        clean = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
        urls = re.findall(r"https?://[^\s\)\]]+", clean)
        url_set = sorted(set(urls))

        result.add("summary", "Run", "OK" if rc == 0 else f"rc={rc}",
                   "found" if rc == 0 else "warn")
        result.add("summary", "Script", script.name, "info")
        result.add("summary", "Kind", kind, "info")

        if url_set:
            result.add("summary", "URLs found", str(len(url_set)), "warn")
            for u in url_set[:30]:
                result.add("urls", u, u, "info", url=u)

        interest = []
        for line in clean.splitlines():
            l = line.strip()
            if not l or len(l) > 200:
                continue
            low = l.lower()
            if any(k in low for k in
                    ["found", "match", "leak", "breach", "vulnerab",
                     "exposed", "registered", "confirmed", "email",
                     "phone", "name:", "address", "carrier", "region",
                     "[+]"]):
                interest.append(l)
        for line in interest[:40]:
            result.add("findings", "line", line[:160], "info")

        return result
