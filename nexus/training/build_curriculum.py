#!/usr/bin/env python3
"""Generate safe tool-routing examples from the Nexus module catalogue."""

from __future__ import annotations

import json
from pathlib import Path

OSINT = {
    "email": ("email", "alice@example.test", "adresses email publiques et exposition"),
    "username": ("username", "alice_lab", "présence publique d'un pseudo"),
    "domain": ("domain", "example.test", "DNS, WHOIS et infrastructure d'un domaine"),
    "ip": ("ip", "192.0.2.10", "informations publiques relatives à une IP"),
    "phone": ("phone", "+33102030405", "normalisation et liens publics d'un téléphone"),
    "web": ("url", "https://example.test", "métadonnées publiques d'une page web"),
    "github": ("username", "alice_lab", "activité publique GitHub"),
    "discord": ("username", "alice_lab", "disponibilité explicite d'un pseudo Discord"),
}
PENTEST = {
    "headers": "en-têtes de défense HTTP",
    "ssl": "configuration TLS et certificats",
    "fingerprint": "technologies exposées",
    "dns-sec": "mesures de sécurité DNS",
    "js": "inventaire JavaScript et secrets accidentellement publiés",
    "ports": "services réseau exposés dans le périmètre",
    "dirs": "chemins web dans le périmètre du laboratoire",
}


def record(user: str, assistant: str, category: str) -> dict:
    return {
        "messages": [
            {"role": "system", "content": "Tu es Nexus AI, analyste précis."},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "source": "nexus-generated-curriculum",
        "license": "CC0-1.0",
        "category": category,
    }


def build() -> list[dict]:
    rows = []
    for module, (kind, target, purpose) in OSINT.items():
        rows.append(
            record(
                f"Analyse OSINT de {target}",
                f"Je classifie la cible comme {kind}. Je sélectionne le module "
                f"{module} pour {purpose}, conserve les sources et distingue les "
                "observations des hypothèses.",
                "osint-routing",
            )
        )
        rows.append(
            record(
                f"Quel module Nexus vérifie {purpose} ?",
                f"Le module adapté est {module}. Une absence de résultat ne prouve "
                "pas une absence d'information.",
                "osint-knowledge",
            )
        )
    for module, purpose in PENTEST.items():
        rows.append(
            record(
                f"Dans mon lab autorisé, je veux examiner les {purpose}.",
                f"Je sélectionne le module pentest {module}, limite les requêtes au "
                "périmètre confirmé, conserve la preuve et formule une correction.",
                "pentest-routing",
            )
        )
        rows.append(
            record(
                f"Le module {module} trouve un signal. Est-ce une faille confirmée ?",
                "Non. C'est un constat à vérifier manuellement. Le rapport doit "
                "séparer la preuve, l'hypothèse, l'impact et la remédiation.",
                "pentest-analysis",
            )
        )
    return rows


if __name__ == "__main__":
    root = Path(__file__).parent
    destination = root / "curriculum.jsonl"
    rows = build()
    examples = root / "examples.jsonl"
    if examples.is_file():
        rows.extend(
            json.loads(line)
            for line in examples.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    with destination.open("w", encoding="utf-8") as stream:
        for item in rows:
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    print(f"Generated {len(rows)} records -> {destination}")
