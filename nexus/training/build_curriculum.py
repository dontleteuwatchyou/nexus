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

SPECIALISED_CASES = [
    (
        "Je cherche Yanis Wilmet à Marchin. Le scan du pseudo yanis retourne "
        "des profils X, Instagram et GitHub. Sont-ils à lui ?",
        "NON ATTRIBUÉ. Le scan prouve seulement que des URL ou comptes utilisent "
        "le pseudo générique yanis. Il faut valider les pages et corréler au moins "
        "deux attributs indépendants, par exemple nom public, ville, photo ou "
        "liens croisés. Avec ces données, l'attribution est impossible.",
        "identity-correlation",
    ),
    (
        "Hudson Rock retourne trois ordinateurs pour le username yanis. "
        "Puis-je dire que Yanis a trois PC infectés ?",
        "Non. Formulation correcte : le fournisseur retourne trois enregistrements "
        "infostealer correspondant au pseudo recherché. Un pseudo ne suffit pas à "
        "attribuer ces machines à une personne.",
        "breach-attribution",
    ),
    (
        "LeakCheck affiche 1000 entrées pour un pseudo. Fais une conclusion.",
        "Observation : 1 000 entrées indexées correspondent à la chaîne recherchée. "
        "Confiance : NON ATTRIBUÉ. Ce nombre ne prouve ni une identité unique, ni "
        "1 000 comptes appartenant au sujet. Corréler avec un identifiant stable "
        "autorisé avant toute notification.",
        "breach-attribution",
    ),
    (
        "Le module social donne https://x.com/alex. Le compte est confirmé ?",
        "Non. C'est une URL candidate construite à partir du pseudo. Il faut vérifier "
        "que la page existe puis comparer des attributs publics indépendants avant "
        "toute attribution.",
        "source-evaluation",
    ),
    (
        "Sherlock trouve le même pseudo sur 165 sites. C'est la même personne.",
        "Cette conclusion n'est pas étayée. Ce sont 165 présences potentielles de la "
        "même chaîne, pas 165 comptes d'une identité confirmée. Classer chaque résultat "
        "comme PISTE et rechercher des liens croisés et attributs concordants.",
        "identity-correlation",
    ),
    (
        "Utilise osint.md comme source de mon constat.",
        "Impossible : osint.md est un guide méthodologique interne, pas une source de "
        "preuve. Le constat doit citer la source technique réellement interrogée, "
        "son horodatage et l'observation reproductible.",
        "reporting",
    ),
    (
        "Une recherche manuelle DeHashed est affichée. Il y a donc une fuite.",
        "Non. Un lien de recherche manuelle indique uniquement où poursuivre la "
        "vérification. Sans réponse positive et corrélée, aucune fuite n'est confirmée.",
        "source-evaluation",
    ),
    (
        "Deux profils ont le même nom et la même photo. Attribution confirmée ?",
        "Pas nécessairement. La photo peut être recopiée et les deux attributs peuvent "
        "provenir d'une même source. Rechercher des preuves indépendantes : liens "
        "réciproques, identifiant stable, domaine contrôlé ou chronologie cohérente.",
        "identity-correlation",
    ),
    (
        "Le scanner n'a rien trouvé. La personne n'a aucune fuite.",
        "Conclusion invalide. Une absence de résultat peut venir de la couverture, "
        "d'un timeout ou d'une source indisponible. Rapporter « aucune correspondance "
        "dans les sources interrogées à cet instant », avec les limites.",
        "source-evaluation",
    ),
    (
        "Nmap montre le port 443 et une bannière nginx. Donne la CVE exploitable.",
        "Un port et une bannière ne suffisent pas à confirmer une CVE. Vérifier la "
        "version réelle, la configuration, la plage affectée et l'avis primaire, puis "
        "valider sans impact dans le périmètre autorisé.",
        "pentest-analysis",
    ),
    (
        "Le header CSP est absent, le site est donc compromis.",
        "Non. L'absence de CSP est un manque de défense observé par le module headers, "
        "pas une preuve de compromission ni d'exploitation. Décrire l'impact potentiel, "
        "la configuration recommandée et la méthode de retest.",
        "pentest-analysis",
    ),
    (
        "Présente un résultat OSINT lisible dans un terminal.",
        "Verdict\nAttribution impossible avec les données actuelles.\n\n"
        "Observations\n- PISTE · source réelle · signal observé\n\n"
        "Limites\n- Même pseudo ≠ même identité\n\n"
        "Prochaine étape\n- Vérifier un pivot discriminant et autorisé.",
        "reporting",
    ),
]


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
    rows.extend(record(user, assistant, category) for user, assistant, category in SPECIALISED_CASES)
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
