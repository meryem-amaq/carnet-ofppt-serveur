<?php
/**
 * Carnet OFPPT – comptes et sauvegarde de la progression (PHP 7.4+ avec PDO SQLite)
 *
 * GET  api.php?action=ping                                   -> {"ok":true,"register":bool}
 * POST {"action":"register","username":"…","password":"…"}   -> {"ok":true,"token":"…","username":"…"}
 * POST {"action":"login","username":"…","password":"…"}      -> {"ok":true,"token":"…","username":"…"}
 * POST {"action":"me","token":"…"}                           -> {"ok":true,"username":"…"}
 * POST {"action":"logout","token":"…"}                       -> {"ok":true}
 * POST {"action":"password","token":"…","old":"…","new":"…"} -> {"ok":true}
 * POST {"action":"load","token":"…"}                         -> {"ok":true,"state":{clé:{v,t}}}
 * POST {"action":"save","token":"…","items":{…}}             -> {"ok":true,"saved":n}
 *
 * Mots de passe : password_hash (bcrypt). Jetons de session : aléatoires,
 * stockés sous forme d'empreinte SHA-256, valables 90 jours.
 */

declare(strict_types=1);

/* ---------- Réglages ---------- */
const ALLOW_REGISTER = true;            // passez à false une fois votre compte créé
const DATA_DIR       = __DIR__ . '/data';
const DB_FILE        = DATA_DIR . '/carnet.sqlite';
const SESSION_DAYS   = 90;
const MAX_BODY       = 12 * 1024 * 1024;
const MAX_VALUE      = 4 * 1024 * 1024;
const MAX_ITEMS      = 500;
const MAX_FAILS      = 8;               // tentatives ratées avant blocage
const LOCK_MINUTES   = 15;

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function reply(array $data, int $status = 200): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function db(): PDO {
    static $pdo = null;
    if ($pdo) { return $pdo; }
    if (!is_dir(DATA_DIR) && !mkdir(DATA_DIR, 0750, true)) {
        reply(['ok' => false, 'error' => 'Impossible de créer le dossier data'], 500);
    }
    $pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pass_hash TEXT NOT NULL,
        created INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS state (
        profile TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, t INTEGER NOT NULL,
        PRIMARY KEY (profile, k))');
    $pdo->exec('CREATE TABLE IF NOT EXISTS attempts (
        akey TEXT PRIMARY KEY, fails INTEGER NOT NULL, until INTEGER NOT NULL)');
    return $pdo;
}

function client_ip(): string { return $_SERVER['REMOTE_ADDR'] ?? 'inconnu'; }

function check_lock(string $username): void {
    $st = db()->prepare('SELECT fails, until FROM attempts WHERE akey = ?');
    foreach (['u:' . mb_strtolower($username), 'ip:' . client_ip()] as $key) {
        $st->execute([$key]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row && (int) $row['until'] > time()) {
            $min = (int) ceil(((int) $row['until'] - time()) / 60);
            reply(['ok' => false, 'error' => "Trop de tentatives. Réessayez dans $min minute(s)."], 429);
        }
    }
}

function record_fail(string $username): void {
    $pdo = db();
    foreach (['u:' . mb_strtolower($username), 'ip:' . client_ip()] as $key) {
        $st = $pdo->prepare('SELECT fails FROM attempts WHERE akey = ?');
        $st->execute([$key]);
        $fails = (int) ($st->fetchColumn() ?: 0) + 1;
        $until = $fails >= MAX_FAILS ? time() + LOCK_MINUTES * 60 : 0;
        if ($fails >= MAX_FAILS) { $fails = 0; }
        $pdo->prepare('INSERT INTO attempts (akey, fails, until) VALUES (?, ?, ?)
                       ON CONFLICT(akey) DO UPDATE SET fails = excluded.fails, until = excluded.until')
            ->execute([$key, $fails, $until]);
    }
}

function clear_fails(string $username): void {
    db()->prepare('DELETE FROM attempts WHERE akey IN (?, ?)')->execute(['u:' . mb_strtolower($username), 'ip:' . client_ip()]);
}

function valid_username($u): string {
    if (!is_string($u)) { reply(['ok' => false, 'error' => 'Identifiant manquant'], 400); }
    $u = trim($u);
    if (!preg_match('/^[A-Za-z0-9._\-@]{3,40}$/', $u)) {
        reply(['ok' => false, 'error' => "L'identifiant doit contenir 3 à 40 caractères : lettres sans accent, chiffres, point, tiret, @."], 400);
    }
    return $u;
}

function valid_password($p): string {
    if (!is_string($p) || mb_strlen($p) < 8 || mb_strlen($p) > 200) {
        reply(['ok' => false, 'error' => 'Le mot de passe doit contenir au moins 8 caractères.'], 400);
    }
    return $p;
}

function new_session(int $userId): string {
    $token = bin2hex(random_bytes(32));
    $pdo = db();
    $pdo->prepare('DELETE FROM sessions WHERE expires < ?')->execute([time()]);
    $pdo->prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)')
        ->execute([hash('sha256', $token), $userId, time() + SESSION_DAYS * 86400]);
    return $token;
}

function auth(array $body): array {
    $token = $body['token'] ?? '';
    if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        reply(['ok' => false, 'error' => 'Session expirée, reconnectez-vous.', 'auth' => false], 401);
    }
    $st = db()->prepare('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
                         WHERE s.token_hash = ? AND s.expires > ?');
    $st->execute([hash('sha256', $token), time()]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) { reply(['ok' => false, 'error' => 'Session expirée, reconnectez-vous.', 'auth' => false], 401); }
    return $row;
}

/* ---------- Routage ---------- */
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'GET') {
    if (($_GET['action'] ?? '') === 'ping') {
        db();
        reply(['ok' => true, 'version' => 2, 'register' => ALLOW_REGISTER]);
    }
    reply(['ok' => false, 'error' => 'Action inconnue'], 400);
}
if ($method !== 'POST') { reply(['ok' => false, 'error' => 'Méthode non autorisée'], 405); }

if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_BODY) { reply(['ok' => false, 'error' => 'Requête trop volumineuse'], 413); }
$raw = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
if ($raw === false || strlen($raw) > MAX_BODY) { reply(['ok' => false, 'error' => 'Requête trop volumineuse'], 413); }
$body = json_decode($raw, true);
if (!is_array($body)) { reply(['ok' => false, 'error' => 'JSON invalide'], 400); }

$action = $body['action'] ?? '';
$pdo = db();

switch ($action) {
    case 'register': {
        if (!ALLOW_REGISTER) { reply(['ok' => false, 'error' => "La création de compte est fermée sur ce serveur."], 403); }
        $u = valid_username($body['username'] ?? null);
        $p = valid_password($body['password'] ?? null);
        check_lock($u);
        $st = $pdo->prepare('SELECT 1 FROM users WHERE username = ?');
        $st->execute([$u]);
        if ($st->fetchColumn()) { reply(['ok' => false, 'error' => 'Cet identifiant existe déjà. Choisissez-en un autre ou connectez-vous.'], 409); }
        $pdo->prepare('INSERT INTO users (username, pass_hash, created) VALUES (?, ?, ?)')
            ->execute([$u, password_hash($p, PASSWORD_DEFAULT), time()]);
        $id = (int) $pdo->lastInsertId();
        reply(['ok' => true, 'token' => new_session($id), 'username' => $u]);
    }
    case 'login': {
        $u = valid_username($body['username'] ?? null);
        $p = is_string($body['password'] ?? null) ? $body['password'] : '';
        check_lock($u);
        $st = $pdo->prepare('SELECT id, username, pass_hash FROM users WHERE username = ?');
        $st->execute([$u]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row || !password_verify($p, $row['pass_hash'])) {
            record_fail($u);
            reply(['ok' => false, 'error' => 'Identifiant ou mot de passe incorrect.'], 401);
        }
        clear_fails($u);
        if (password_needs_rehash($row['pass_hash'], PASSWORD_DEFAULT)) {
            $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute([password_hash($p, PASSWORD_DEFAULT), $row['id']]);
        }
        reply(['ok' => true, 'token' => new_session((int) $row['id']), 'username' => $row['username']]);
    }
    case 'me': {
        $user = auth($body);
        reply(['ok' => true, 'username' => $user['username']]);
    }
    case 'logout': {
        $token = $body['token'] ?? '';
        if (is_string($token)) { $pdo->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute([hash('sha256', $token)]); }
        reply(['ok' => true]);
    }
    case 'password': {
        $user = auth($body);
        $st = $pdo->prepare('SELECT pass_hash FROM users WHERE id = ?');
        $st->execute([$user['id']]);
        if (!password_verify((string) ($body['old'] ?? ''), (string) $st->fetchColumn())) {
            reply(['ok' => false, 'error' => 'Ancien mot de passe incorrect.'], 401);
        }
        $new = valid_password($body['new'] ?? null);
        $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute([password_hash($new, PASSWORD_DEFAULT), $user['id']]);
        // Déconnecte les autres appareils, garde la session actuelle.
        $pdo->prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?')->execute([$user['id'], hash('sha256', (string) $body['token'])]);
        reply(['ok' => true]);
    }
    case 'load': {
        $user = auth($body);
        $st = $pdo->prepare('SELECT k, v, t FROM state WHERE profile = ?');
        $st->execute(['u:' . $user['id']]);
        $state = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $state[$row['k']] = ['v' => json_decode($row['v'], true), 't' => (int) $row['t']];
        }
        reply(['ok' => true, 'state' => (object) $state, 'username' => $user['username']]);
    }
    case 'save': {
        $user = auth($body);
        $items = $body['items'] ?? null;
        if (!is_array($items) || count($items) > MAX_ITEMS) { reply(['ok' => false, 'error' => 'Éléments invalides'], 400); }
        $st = $pdo->prepare('INSERT INTO state (profile, k, v, t) VALUES (:p, :k, :v, :t)
                             ON CONFLICT(profile, k) DO UPDATE SET v = excluded.v, t = excluded.t WHERE excluded.t > state.t');
        $saved = 0;
        $pdo->beginTransaction();
        foreach ($items as $k => $entry) {
            if (!is_string($k) || !preg_match('/^[A-Za-z0-9:_\-.]{1,80}$/', $k)) { continue; }
            if (!is_array($entry) || !array_key_exists('v', $entry) || !isset($entry['t'])) { continue; }
            $v = json_encode($entry['v'], JSON_UNESCAPED_UNICODE);
            if ($v === false || strlen($v) > MAX_VALUE) { continue; }
            $t = (int) $entry['t'];
            if ($t <= 0) { continue; }
            $st->execute([':p' => 'u:' . $user['id'], ':k' => $k, ':v' => $v, ':t' => $t]);
            $saved += $st->rowCount();
        }
        $pdo->commit();
        reply(['ok' => true, 'saved' => $saved]);
    }
}
reply(['ok' => false, 'error' => 'Action inconnue'], 400);
