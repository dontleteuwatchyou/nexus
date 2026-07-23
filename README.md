# Nexus Toolkit

Plateforme unifiée d’**OSINT**, de **reconnaissance technique autorisée** et
d’orchestration d’outils de sécurité. Ce dépôt contient le moteur Python,
sa CLI et son interface TUI.

> **Projet en développement actif.** Les résultats doivent être qualifiés
> manuellement. N’utilisez les modules actifs que sur vos propres systèmes, un
> laboratoire contrôlé ou une cible couverte par une autorisation écrite.

## Structure du dépôt

```text
.
├── nexus/                 # moteur Python, CLI, TUI, modules et tests
│   ├── osint_toolkit/
│   │   ├── modules/       # OSINT passif
│   │   ├── pentest/       # reconnaissance active, détection uniquement
│   │   └── external/      # adaptateurs d’outils tiers
│   ├── tests/
│   ├── pyproject.toml
│   └── install.sh
└── .github/workflows/     # intégration continue
```

## Nexus

Le moteur complet fonctionne en Python 3.10+ et fournit :

- 13 modules OSINT : email, pseudo, domaine, IP, téléphone, web, social,
  fuites, GitHub, Discord, image et crypto ;
- 13 modules de reconnaissance : ports, sous-domaines, TLS, CORS, en-têtes,
  empreintes, répertoires, JavaScript, GraphQL, Spring et cloud ;
- environ 80 adaptateurs d’outils externes ;
- une TUI Textual, une CLI Rich et des exports JSON/HTML ;
- un modèle commun `ScanResult` pour toutes les observations.

Installation :

```bash
cd nexus
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m osint_toolkit
```

Ou avec l’installateur :

```bash
cd nexus
chmod +x install.sh
./install.sh
```

Exemples :

```bash
nexus example.com
nexus -c osint -m domain example.com
nexus -c pentest -m headers example.com
nexus --list-modules
nexus --check-tools
```

## Développement

```bash
cd nexus
python -m pip install -e ".[dev]"
ruff check --select E9,F63,F7,F82 osint_toolkit tests
pytest
python -m build
```

## Avertissement légal

Les catégories pentest et external peuvent générer du trafic actif ou lancer
des outils offensifs installés séparément. Elles sont réservées aux contextes
explicitement autorisés. Nexus ne constitue ni une autorisation, ni une preuve
automatique de vulnérabilité ou d’attribution.

## Licence

MIT — voir [LICENSE](LICENSE).
