# WorldifyAI

Application Node.js de traduction et d’apprentissage, avec MongoDB et e-mails transactionnels Brevo HTTP. Les comptes, sessions, historiques et scores sont gérés par le serveur et MongoDB.

## Configuration

Copier `.env.example` vers `.env`, puis renseigner :

- `MONGODB_URI` et `MONGODB_DB` pour MongoDB ;
- `BREVO_API_KEY`, `MAIL_FROM` et `MAIL_FROM_NAME` pour Brevo ;
- `ADMIN_EMAIL` et `ADMIN_PASSWORD` pour créer le compte administrateur au premier démarrage ;
- `APP_URL` avec l’URL Render publique qui recevra les liens de récupération.

## Démarrer

Nécessite Node.js 18 ou plus récent.

```bash
npm install
npm start
```

Les écrans d’authentification sont séparés : `/login`, `/register`, `/forgot-password` et `/reset-password`. L’application est accessible à la racine uniquement après connexion.

Sur Render : Build Command `npm install`, Start Command `npm start`, puis ajouter les variables du fichier `.env.example`. Dans MongoDB Atlas, autoriser les connexions réseau du service Render.

La récupération du mot de passe envoie un lien Brevo valable 15 minutes. Les e-mails envoyés sont : bienvenue, nouvelle connexion, changement de mot de passe et nouvelle inscription à l’administrateur.

Le lien du canal WhatsApp doit être remplacé dans les pages d’authentification et dans `index.html` par l’URL réelle du canal.
