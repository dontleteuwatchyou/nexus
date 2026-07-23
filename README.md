# Nexus Toolkit

Plateforme unifiée d’**OSINT**, de **reconnaissance technique autorisée** et
d’orchestration d’outils de sécurité. Le dépôt réunit le moteur Python/TUI et
son compagnon web statique.

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
├── web/                   # sources du Web Lab statique
├── docs/                  # version publiée par GitHub Pages
└── .github/workflows/     # intégration continue
```

## Deux interfaces complémentaires

### Nexus local

Le moteur complet fonctionne en Python 3.10+ et fournit :

- 12 modules OSINT : email, pseudo, domaine, IP, téléphone, web, social,
  fuites, GitHub, image et crypto ;
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

### Web Lab

Le Web Lab est une version statique compatible GitHub Pages. Il propose :

- détection locale de cible et plus de 50 pivots publics ;
- enrichissement passif optionnel via Google Public DNS, GitHub, IPWhois et
  mempool.space ;
- 12 parcours OSINT et 8 parcours de reconnaissance guidée ;
- historique local et exports JSON, CSV et Markdown.

Il ne peut pas exécuter Nmap, des sockets TCP, Python ou les outils système du
moteur local. Les API passives ne sont contactées que lorsque l’utilisateur
active explicitement l’enrichissement.

**Site :** https://dontleteuwatchyou.github.io/nexus/

## APIs et confidentialité

| Source | Usage | Déclenchement |
|---|---|---|
| Google Public DNS | A, AAAA, MX et TXT | optionnel dans le Web Lab |
| GitHub API | profil public exact | optionnel dans le Web Lab |
| IPWhois | ASN et zone IP approximative | optionnel dans le Web Lab |
| mempool.space | données publiques Bitcoin | optionnel dans le Web Lab |
| Sources des modules Python | OSINT et registres publics | depuis Nexus local |

Chaque service reçoit la cible nécessaire à la requête et applique ses propres
conditions, quotas et règles de confidentialité. Aucun rapport opérationnel,
fichier de cibles ou résultat d’audit local n’est publié dans ce dépôt.

## Développement

```bash
cd nexus
python -m pip install -e ".[dev]"
ruff check --select E9,F63,F7,F82 osint_toolkit tests
pytest
python -m build --no-isolation
```

Le Web Lab ne requiert aucune compilation. `web/` contient les sources et
`docs/` la copie déployée.

## Avertissement légal

Les catégories pentest et external peuvent générer du trafic actif ou lancer
des outils offensifs installés séparément. Elles sont réservées aux contextes
explicitement autorisés. Nexus ne constitue ni une autorisation, ni une preuve
automatique de vulnérabilité ou d’attribution.

## Licence

MIT — voir [LICENSE](LICENSE).
