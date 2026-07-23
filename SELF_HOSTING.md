# Auto-héberger Nexus avec DuckDNS

Cette configuration exécute trois services Docker :

- `web` : Caddy sert le Web Lab et gère automatiquement HTTPS ;
- `nexus-api` : FastAPI expose les modules OSINT passifs autorisés ;
- `duckdns` : actualise l’adresse IP publique toutes les cinq minutes.

Les modules pentest et les outils externes ne sont pas exposés par l’API Web.

## Prérequis

- une machine Linux qui reste allumée ;
- Docker avec le plugin Docker Compose ;
- un compte gratuit [DuckDNS](https://www.duckdns.org/) ;
- accès à la configuration NAT de votre routeur.

Si votre fournisseur utilise CGNAT, la redirection de ports ne fonctionnera pas
directement. Comparez l’adresse WAN affichée par le routeur à votre adresse IP
publique. Si elles diffèrent, demandez une IPv4 publique ou utilisez un tunnel.

## 1. Créer le sous-domaine

Dans DuckDNS, créez par exemple `mon-nexus`. L’adresse publique sera :

```text
https://mon-nexus.duckdns.org/
```

## 2. Configurer les secrets

Depuis la racine du dépôt :

```bash
cp .env.example .env
openssl rand -hex 32
```

Éditez `.env` :

```dotenv
DUCKDNS_SUBDOMAIN=mon-nexus
DUCKDNS_TOKEN=token-fourni-par-duckdns
NEXUS_ADMIN_USER=admin
NEXUS_ADMIN_PASSWORD=une-longue-phrase-de-passe-unique
NEXUS_SESSION_SECRET=valeur-retournee-par-openssl
```

Le fichier `.env` est ignoré par Git. Ne le publiez jamais.

## 3. Rediriger les ports

Attribuez une adresse IP locale fixe à la machine Nexus, puis créez sur le
routeur les redirections TCP suivantes vers cette machine :

| Port public | Port local | Usage |
|---|---|---|
| 80/TCP | 80 | validation et redirection HTTPS |
| 443/TCP | 443 | application HTTPS |
| 443/UDP | 443 | HTTP/3, facultatif |

N’exposez pas directement le port `8000` : l’API doit rester derrière Caddy.

## 4. Démarrer

```bash
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs -f web nexus-api duckdns
```

Caddy demande automatiquement un certificat TLS lorsque le domaine pointe vers
la bonne IP et que les ports 80/443 sont accessibles.

## 5. Mettre à jour

```bash
git pull --ff-only
docker compose up -d --build
```

## Sécurité

- utilisez un mot de passe unique ;
- ne commitez jamais `.env` ;
- gardez Docker et l’hôte à jour ;
- sauvegardez uniquement les rapports nécessaires ;
- n’exposez pas les catégories pentest sans contrôle de cible supplémentaire ;
- consultez les logs et arrêtez le service en cas de comportement inattendu :

```bash
docker compose down
```
