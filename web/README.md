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

Le dossier `docs/` à la racine est la copie publiée par GitHub Pages. Toute
modification fonctionnelle de `web/` doit être répercutée dans `docs/` avant le
déploiement.

La connexion est uniquement une barrière d’interface côté navigateur. Elle ne
doit pas protéger de données sensibles.
