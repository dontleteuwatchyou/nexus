# Passation — Nexus AI

Date : 23 juillet 2026  
État : première fondation locale terminée, entraînement GPU à poursuivre.

## Ce qui a été réalisé

OpenCode a été retiré de l’architecture du chat. Nexus utilise maintenant son
propre moteur `osint_toolkit.ai.NexusAI`.

Le moteur possède :

- un mode **Core** sans modèle, compte, API ou GPU ;
- une mémoire conversationnelle locale et bornée ;
- un client indépendant compatible avec les serveurs locaux au format OpenAI ;
- un RAG lexical léger sans dépendance supplémentaire ;
- un corpus embarqué sur l’OSINT, les modules Nexus, la sécurité web et le
  reporting ;
- une intégration directe dans la TUI et dans `nexus --chat` ;
- un routage OSINT passif immédiat ;
- une confirmation pentest actif mémorisée une seule fois pendant la session.

Un serveur local llama.cpp est fourni par `scripts/local_ai.sh`. Le modèle de
référence est `Qwen/Qwen3-4B-GGUF:Q4_K_M`, accessible uniquement sur
`127.0.0.1:8080` avec une clé locale.

## Résultats mesurés sur le premier PC

Machine :

- Intel Core i5-4570T, 4 threads ;
- 15,5 Gio de RAM ;
- aucune accélération CUDA utilisable.

Résultats :

- Qwen3-4B Q4_K_M chargé avec environ 2,5 Gio de RAM ;
- environ 4 tokens/s ;
- réponses typiques entre 20 et 80 secondes ;
- évaluation RAG : 10/10 ;
- tests Python : 33 réussis ;
- wheel vérifiée avec le corpus RAG inclus ;
- évaluation réelle du modèle effectuée sur le routage username, CSP et CVE.

Le fichier `training/BASELINE.md` conserve les résultats avant entraînement.
Une faiblesse connue reste volontairement mesurée : le modèle de base peut
attribuer une sévérité trop précise à un header CSP absent. Le fine-tuning doit
améliorer cette calibration sans régresser les autres tests.

## Fichiers importants

| Fichier | Rôle |
|---|---|
| `osint_toolkit/ai/engine.py` | moteur, mémoire et appel du modèle local |
| `osint_toolkit/ai/rag.py` | index lexical et récupération documentaire |
| `osint_toolkit/ai/knowledge/` | connaissances embarquées |
| `scripts/local_ai.sh` | démarrage/arrêt du serveur llama.cpp |
| `training/examples.jsonl` | exemples SFT écrits manuellement |
| `training/build_curriculum.py` | génération du curriculum synthétique |
| `training/prepare_dataset.py` | validation, filtrage et déduplication |
| `training/evaluate_rag.py` | benchmark de récupération documentaire |
| `training/evaluate_model.py` | benchmark réel du modèle |
| `training/hardware_check.py` | diagnostic CPU/RAM/CUDA/VRAM |
| `training/train_qlora.py` | entraînement QLoRA sur GPU |

`training/curriculum.jsonl` et `training/ready.jsonl` sont générés localement et
ignorés par Git. Ils doivent être régénérés sur chaque machine afin de ne pas
versionner des datasets de travail ou des données privées.

## Reprise sur le PC RTX 4070 Ti

### 1. Récupérer le projet

```bash
git clone https://github.com/dontleteuwatchyou/nexus.git
cd nexus/nexus
chmod +x install.sh
./install.sh --dev
```

Si le dépôt existe déjà :

```bash
git pull --rebase origin main
cd nexus
./install.sh --dev
```

### 2. Vérifier le GPU

Le pilote NVIDIA, CUDA et une version CUDA de PyTorch doivent fonctionner :

```bash
nvidia-smi
.venv/bin/python training/hardware_check.py
```

Le résultat attendu pour commencer QLoRA 4B est :

```text
"cuda": true
"qlora_4b_ready": true
```

### 3. Installer les dépendances d’entraînement

```bash
.venv/bin/pip install -e '.[train]'
```

Puis vérifier :

```bash
.venv/bin/python -c \
  "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

### 4. Construire le dataset

```bash
.venv/bin/python training/build_curriculum.py
.venv/bin/python training/prepare_dataset.py \
  training/curriculum.jsonl training/ready.jsonl
wc -l training/ready.jsonl
```

Le curriculum actuel est uniquement un socle technique. Avant un entraînement
intensif, il faut viser plusieurs milliers d’exemples contrôlés et variés :

- classification de cibles ;
- sélection exacte des modules Nexus ;
- appels d’outils et interprétation des `ScanResult` ;
- corrélation OSINT multi-source ;
- incertitude, absence de résultat et faux positifs ;
- audits de laboratoires OWASP/DVWA/WebGoat ;
- preuves, sévérité et remédiations ;
- génération de rapports techniques et exécutifs.

Ne pas intégrer de secrets, mots de passe, dumps de fuite, données personnelles
réelles ou résultats provenant de cibles non autorisées.

### 5. Mesurer le modèle avant entraînement

```bash
.venv/bin/python training/evaluate_rag.py
./scripts/local_ai.sh start
.venv/bin/python training/evaluate_model.py
```

Conserver les résultats pour comparer objectivement l’adaptateur.

### 6. Lancer QLoRA

Premier essai recommandé :

```bash
.venv/bin/python training/train_qlora.py \
  --dataset training/ready.jsonl \
  --model Qwen/Qwen3-4B \
  --output artifacts/nexus-ai-lora \
  --epochs 2
```

Le script utilise une quantification 4-bit NF4, LoRA `r=32`, gradient
checkpointing, batch 1 et accumulation de gradients. Sur une 4070 Ti, commencer
avec une longueur de 2048 tokens. Réduire à 1024 en cas de manque de VRAM.

Les poids de base et les artefacts `artifacts/` ne doivent pas être poussés
directement dans le dépôt Git. Publier uniquement l’adaptateur si sa licence,
le dataset et les évaluations permettent sa distribution.

## Ce qu’il reste à faire

1. Enrichir et relire le dataset jusqu’à plusieurs milliers d’exemples.
2. Ajouter un découpage train/validation/test sans fuite entre les groupes.
3. Étendre les évaluations à tous les modules internes.
4. Lancer un premier QLoRA sur la 4070 Ti.
5. Comparer le modèle de base et l’adaptateur sur les mêmes cas.
6. Corriger le dataset plutôt que surentraîner les réponses erronées.
7. Exporter/fusionner l’adaptateur puis produire une version GGUF.
8. Tester la version quantifiée sur un PC sans GPU.
9. Ajouter à l’installateur le téléchargement optionnel du modèle Nexus validé.
10. Versionner une première release `Nexus AI` avec fiche de modèle et
    provenance du dataset.

## Commandes rapides

```bash
# Nexus sans modèle
nexus --chat

# Serveur local
./scripts/local_ai.sh start
./scripts/local_ai.sh status
./scripts/local_ai.sh logs
./scripts/local_ai.sh stop

# Validation complète
.venv/bin/pytest -q tests
.venv/bin/python training/evaluate_rag.py
.venv/bin/python training/evaluate_model.py
```

Derniers jalons Git au moment de cette passation :

- `bae077d` — moteur Nexus AI local-first ;
- `4570e1d` — RAG local et pipeline QLoRA ;
- `66250c0` — benchmark et catalogue exact des modules.
