# Nexus Toolkit — site public et Web Lab

Ce dépôt contient la vitrine publique de **Nexus Toolkit v4** et son Web Lab expérimental. Le site est entièrement statique : HTML, CSS et JavaScript natif uniquement. Il ne nécessite ni Python, ni Node.js, ni PHP, ni base de données et peut être publié directement avec GitHub Pages.

Le moteur Nexus complet reste une application locale Python/CLI/TUI. Ce dépôt public n'inclut volontairement aucun rapport de pentest, aucune liste de cibles et aucune donnée d'investigation issue du projet local.

## Fonctionnement de cette édition

- `index.html` est la présentation publique du projet ;
- `login.html` est le point d'entrée du Web Lab ;
- `app.html` contient l'application statique protégée ;
- la session simulée est conservée dans `localStorage` sur l’appareil de l’utilisateur ;
- `app.html` vérifie la session et renvoie vers `login.html` lorsqu’elle est absente ;
- le bouton **Déconnexion** efface la session locale ;
- l’espace OSINT détecte localement le type de cible et prépare des liens vers des sources publiques ;
- l’espace d’audit prépare une checklist et des liens de validation manuelle ;
- un enrichissement passif optionnel peut interroger Google Public DNS, GitHub, IPWhois ou mempool.space selon le type de cible ;
- l’historique des analyses est conservé uniquement dans `localStorage` et peut être effacé depuis l’interface ;
- les rapports JSON, CSV et Markdown sont produits directement dans le navigateur.

Aucune cible saisie n’est transmise à un serveur Nexus. Un service externe reçoit la cible uniquement lorsque l’utilisateur clique explicitement sur son lien.

> La connexion est une protection d’interface locale, pas une authentification sécurisée. Le code et les fichiers d’un site GitHub Pages sont publics. N’y placez aucun secret et n’utilisez pas cette session simulée pour protéger des données sensibles.

## Publication sur GitHub Pages

### 1. Créer et pousser le dépôt

Placez ces fichiers à la racine de la branche principale :

```text
.
├── .nojekyll
├── index.html
├── login.html
├── app.html
├── auth.js
├── login.js
├── app.js
├── styles.css
└── README.md
```

Puis poussez le projet sur GitHub :

```bash
git init
git add .
git commit -m "Publish Nexus Web static edition"
git branch -M main
git remote add origin https://github.com/VOTRE-COMPTE/VOTRE-DEPOT.git
git push -u origin main
```

Si le dépôt existe déjà, un simple commit et un `git push` suffisent.

### 2. Activer GitHub Pages

Dans le dépôt GitHub :

1. ouvrez **Settings** ;
2. choisissez **Pages** dans la colonne de gauche ;
3. dans **Build and deployment**, sélectionnez **Deploy from a branch** ;
4. choisissez la branche **main** et le dossier **/(root)** ;
5. cliquez sur **Save**.

Après le déploiement, l’application sera disponible à une adresse similaire à :

```text
https://VOTRE-COMPTE.github.io/VOTRE-DEPOT/
```

La racine ouvre la présentation publique. Ouvrez `login.html` pour entrer dans le Web Lab :

```text
https://VOTRE-COMPTE.github.io/VOTRE-DEPOT/login.html
```

`app.html` redirige automatiquement un visiteur sans session vers cette page. Tous les chemins sont relatifs (`./...`) et fonctionnent donc aussi bien sur un domaine utilisateur que dans le sous-répertoire d’un dépôt GitHub Pages.

## Connexion

Cette version accepte uniquement les comptes explicitement autorisés dans `login.js`. Les mots de passe ne sont ni stockés en clair ni envoyés : leur empreinte SHA-256 est comparée localement, puis seule une session contenant le nom d’utilisateur et sa date de création est enregistrée dans `localStorage`.

Cette protection reste simulée : les empreintes et toute la logique JavaScript sont publiques sur GitHub Pages. Elle ne doit protéger aucune donnée sensible.

Pour supprimer manuellement la session depuis la console du navigateur :

```javascript
localStorage.removeItem("nexus_static_session");
```

Pour une véritable gestion de comptes, il faut connecter l’interface à un fournisseur externe tel que Firebase Authentication, Auth0 ou Supabase. Cela exige une configuration propre au projet et ne peut donc pas être livré sans configuration supplémentaire.

## Utilisation locale sans serveur

Vous pouvez ouvrir directement `login.html` dans un navigateur moderne. Aucun serveur local n’est requis. Certains navigateurs appliquent toutefois des restrictions supplémentaires aux pages ouvertes avec `file://`; la version publiée en HTTPS sur GitHub Pages est le mode recommandé.

## Limites du mode statique

Un navigateur ne peut pas reproduire correctement les anciens collecteurs Python : scans TCP, résolution DNS système, WHOIS, inspection TLS brute et requêtes cross-origin arbitraires sont bloqués ou limités par son modèle de sécurité. Ils ont donc été remplacés par des pivots publics et des contrôles manuels explicites.

Nexus n’effectue aucune exploitation automatique. Utilisez les outils externes et les checklists uniquement sur des cibles pour lesquelles vous disposez d’une base légale et d’une autorisation adaptée.
