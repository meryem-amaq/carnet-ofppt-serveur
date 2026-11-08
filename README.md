# Carnet OFPPT – Serveur & Application

Application web complète avec synchronisation serveur pour les révisions OFPPT (fiches, dissertations, quiz, cahier manuscrit).

## 📁 Structure du projet

- **`index.html`** : L'application web cliente (interface, fiches interactives, dissertations, quiz QCM, cahier de notes). Fonctionne hors-ligne avec synchronisation dès retour du réseau.
- **`api.php`** : API REST en PHP (gestion des comptes, authentification par jetons et sauvegarde SQLite).
- **`data/`** : Dossier contenant la base SQLite (`carnet.sqlite` créé automatiquement).
- **`data/.htaccess`** : Protection interdisant l'accès direct aux fichiers de données sous Apache.
- **`LISEZMOI.txt`** : Guide textuel d'origine.

---

## ⚙️ Prérequis

- Serveur web (Apache ou Nginx)
- **PHP 7.4** ou version ultérieure
- Extension **PDO SQLite** (`pdo_sqlite`) activée
- Connexion sécurisée **HTTPS** fortement recommandée (chiffrement des mots de passe en transit)

---

## 🚀 Installation rapide

1. **Déployer les fichiers** sur votre serveur web (par exemple `/var/www/html/carnet/`).
2. **Configurer les permissions** sur le dossier `data/` pour permettre à PHP d'écrire la base :
   ```bash
   sudo chown -R www-data:www-data /var/www/html/carnet/data
   sudo chmod 750 /var/www/html/carnet/data
   ```
3. **Tester l'API** en ouvrant l'URL :
   ```
   https://votre-domaine/carnet/api.php?action=ping
   ```
   Vous devez obtenir la réponse JSON suivante :
   ```json
   {"ok":true,"version":2,"register":true}
   ```
4. **Créer votre compte** :
   - Ouvrez `https://votre-domaine/carnet/` dans votre navigateur.
   - Cliquez sur **« Créer un compte »** (identifiant + mot de passe d'au moins 8 caractères).
5. **(Recommandé) Verrouiller les inscriptions** :
   - Une fois votre compte créé, éditez `api.php` :
     ```php
     const ALLOW_REGISTER = false;
     ```

---

## 🔒 Configuration Serveur

### Sous Apache
Le fichier `data/.htaccess` est déjà fourni et bloque l'accès direct aux fichiers SQLite. Vérifiez que la directive `AllowOverride` est activée dans la configuration d'Apache.

### Sous Nginx
Ajoutez la règle suivante dans votre bloc `server { ... }` :
```nginx
location ^~ /carnet/data/ {
    deny all;
    return 404;
}
```

---

## 💾 Sauvegarde & Sécurité

- **Base de données SQLite** : Pour sauvegarder toutes les données et la progression des utilisateurs, copiez simplement le fichier `data/carnet.sqlite`.
- **Mots de passe** : Hachés avec `password_hash` (bcrypt).
- **Sessions** : Jetons aléatoires stockés sous forme d'empreinte SHA-256 avec validité de 90 jours.
- **Protection anti-bruteforce** : Blocage temporaire (15 min) après 8 échecs consécutifs.
