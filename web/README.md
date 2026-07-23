# Nexus Web Lab

Sources statiques du compagnon web de Nexus Toolkit.

- `index.html` : vitrine publique ;
- `login.html` : connexion locale simulée ;
- `app.html` : interface OSINT et reconnaissance guidée ;
- `app.js` : détection, pivots, enrichissement passif et exports ;
- `auth.js` / `login.js` : session locale ;
- `styles.css` : design responsive.

Le site fonctionne sans compilation. Pour tester, ouvrez `index.html` dans un
navigateur moderne.

Lorsqu’il est servi par la configuration Docker située à la racine du dépôt,
le Web Lab détecte automatiquement le backend FastAPI : la connexion devient
une session serveur et l’enrichissement OSINT appelle les modules Python
autorisés. Sur GitHub Pages, il reste en mode statique.

Le dossier `docs/` à la racine est la copie publiée par GitHub Pages. Toute
modification fonctionnelle de `web/` doit être répercutée dans `docs/` avant le
déploiement.

Le Web Lab contient aussi une catégorie Discord dédiée. Son checker transmet
explicitement le username à Discord et affiche le statut pris/disponible
retourné au moment de la requête.

La connexion est uniquement une barrière d’interface côté navigateur. Elle ne
doit pas protéger de données sensibles.
