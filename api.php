<?php
/**
 * Carnet OFPPT – comptes et sauvegarde de la progression
 * Compatible PHP 7.0 à 8.x, avec l'extension PDO SQLite (toute version de SQLite 3).
 *
 * GET  api.php?action=ping     -> {"ok":true,"register":bool}
 * GET  api.php?action=check    -> diagnostic de l'hébergement (à ouvrir dans le navigateur)
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

/* ---------- Réglages ---------- */
define('ALLOW_REGISTER', false);         // compte unique : la création de compte est fermée
// Compte unique créé automatiquement au premier lancement (mot de passe stocké chiffré, jamais en clair).
define('DEFAULT_USER', 'amine');
define('DEFAULT_HASH', '$2y$10$dkNZtx8xsHGbTx1yZYG6CuPY1thuifL8/rxTQrzXZ37yPOvhS636C');
define('DATA_DIR', __DIR__ . '/data');
define('DB_FILE', DATA_DIR . '/carnet.sqlite');
define('SESSION_DAYS', 90);
define('MAX_BODY', 12 * 1024 * 1024);
define('MAX_VALUE', 4 * 1024 * 1024);
define('MAX_ITEMS', 500);
define('MAX_FAILS', 8);                  // tentatives ratées avant blocage
define('LOCK_MINUTES', 15);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
ini_set('display_errors', '0');

class Reply extends Exception {
    public $data; public $status;
    public function __construct($data, $status) { parent::__construct(''); $this->data = $data; $this->status = $status; }
}
function reply($data, $status = 200) { throw new Reply($data, $status); }
function fail($message, $status = 400) { reply(array('ok' => false, 'error' => $message), $status); }

function str_len($s) { return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : strlen($s); }
function str_low($s) { return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s); }
function rand_hex($bytes) {
    if (function_exists('random_bytes')) { return bin2hex(random_bytes($bytes)); }
    if (function_exists('openssl_random_pseudo_bytes')) { return bin2hex(openssl_random_pseudo_bytes($bytes)); }
    fail("Le serveur ne fournit pas de générateur aléatoire sûr (PHP 7 ou plus requis).", 500);
}

/* ---------- Base de données ---------- */
function db() {
    static $pdo = null;
    if ($pdo) { return $pdo; }
    if (!extension_loaded('pdo_sqlite')) {
        fail("L'extension PHP « pdo_sqlite » n'est pas activée sur l'hébergement. Activez-la dans le panneau de votre hébergeur (sélecteur de version PHP › extensions), puis réessayez.", 500);
    }
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0755, true)) {
        fail("Impossible de créer le dossier « data » à côté de api.php. Créez-le vous-même et donnez-lui les droits d'écriture (755 ou 775).", 500);
    }
    if (!is_writable(DATA_DIR)) {
        fail("Le dossier « data » n'est pas accessible en écriture par PHP. Donnez-lui les droits 755 ou 775 (ou chown vers l'utilisateur du serveur web), puis réessayez.", 500);
    }
    if (file_exists(DB_FILE) && !is_writable(DB_FILE)) {
        fail("Le fichier data/carnet.sqlite existe mais n'est pas modifiable. Donnez-lui les droits 664, ou supprimez-le pour qu'il soit recréé.", 500);
    }
    try {
        $pdo = new PDO('sqlite:' . DB_FILE, null, null, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
    } catch (Exception $e) {
        fail("Impossible d'ouvrir la base de données : " . $e->getMessage(), 500);
    }
    try { $pdo->exec('PRAGMA journal_mode = WAL'); } catch (Exception $e) { /* certains hébergements l'interdisent */ }
    try { $pdo->exec('PRAGMA busy_timeout = 5000'); } catch (Exception $e) {}
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pass_hash TEXT NOT NULL,
        created INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE IF NOT EXISTS state (
        profile TEXT NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, t INTEGER NOT NULL,
        PRIMARY KEY (profile, k))');
    $pdo->exec('CREATE TABLE IF NOT EXISTS attempts (
        akey TEXT PRIMARY KEY, fails INTEGER NOT NULL, until INTEGER NOT NULL)');
    if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0) {
        $pdo->prepare('INSERT INTO users (username, pass_hash, created) VALUES (?, ?, ?)')->execute(array(DEFAULT_USER, DEFAULT_HASH, time()));
    }
    return $pdo;
}

/* ---------- Protection contre les essais répétés ---------- */
function client_ip() { return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'inconnu'; }
function lock_keys($username) { return array('u:' . str_low($username), 'ip:' . client_ip()); }

function check_lock($username) {
    $st = db()->prepare('SELECT until FROM attempts WHERE akey = ?');
    foreach (lock_keys($username) as $key) {
        $st->execute(array($key));
        $until = (int) $st->fetchColumn();
        if ($until > time()) {
            $min = (int) ceil(($until - time()) / 60);
            fail("Trop de tentatives. Réessayez dans $min minute(s).", 429);
        }
    }
}
function record_fail($username) {
    $pdo = db();
    foreach (lock_keys($username) as $key) {
        $st = $pdo->prepare('SELECT fails FROM attempts WHERE akey = ?');
        $st->execute(array($key));
        $fails = (int) $st->fetchColumn() + 1;
        $until = 0;
        if ($fails >= MAX_FAILS) { $until = time() + LOCK_MINUTES * 60; $fails = 0; }
        $pdo->prepare('INSERT OR REPLACE INTO attempts (akey, fails, until) VALUES (?, ?, ?)')->execute(array($key, $fails, $until));
    }
}
function clear_fails($username) {
    $k = lock_keys($username);
    db()->prepare('DELETE FROM attempts WHERE akey IN (?, ?)')->execute($k);
}

/* ---------- Comptes et sessions ---------- */
function valid_username($u) {
    if (!is_string($u)) { fail('Identifiant manquant.'); }
    $u = trim($u);
    if (!preg_match('/^[A-Za-z0-9._\-@]{3,40}$/', $u)) {
        fail("L'identifiant doit contenir 3 à 40 caractères : lettres sans accent, chiffres, point, tiret, @.");
    }
    return $u;
}
function valid_password($p) {
    if (!is_string($p) || str_len($p) < 8 || str_len($p) > 200) { fail('Le mot de passe doit contenir au moins 8 caractères.'); }
    return $p;
}
function new_session($userId) {
    $token = rand_hex(32);
    $pdo = db();
    $pdo->prepare('DELETE FROM sessions WHERE expires < ?')->execute(array(time()));
    $pdo->prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)')
        ->execute(array(hash('sha256', $token), (int) $userId, time() + SESSION_DAYS * 86400));
    return $token;
}
function auth($body) {
    $token = isset($body['token']) ? $body['token'] : '';
    if (!is_string($token) || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        reply(array('ok' => false, 'error' => 'Session expirée, reconnectez-vous.', 'auth' => false), 401);
    }
    $st = db()->prepare('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ?');
    $st->execute(array(hash('sha256', $token), time()));
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) { reply(array('ok' => false, 'error' => 'Session expirée, reconnectez-vous.', 'auth' => false), 401); }
    return $row;
}

/* ---------- Diagnostic ---------- */
function diagnostic() {
    $checks = array();
    $checks['php_version'] = PHP_VERSION;
    $checks['php_ok'] = version_compare(PHP_VERSION, '7.0.0', '>=');
    $checks['pdo_sqlite'] = extension_loaded('pdo_sqlite');
    $checks['password_hash'] = function_exists('password_hash');
    $checks['mbstring'] = function_exists('mb_strlen') ? 'présent' : 'absent (facultatif)';
    $checks['dossier_data_existe'] = is_dir(DATA_DIR);
    $checks['dossier_data_inscriptible'] = is_dir(DATA_DIR) && is_writable(DATA_DIR);
    $checks['sqlite_version'] = null;
    $checks['base_ok'] = false;
    if ($checks['pdo_sqlite'] && $checks['dossier_data_inscriptible']) {
        try {
            $pdo = db();
            $checks['sqlite_version'] = $pdo->query('SELECT sqlite_version()')->fetchColumn();
            $checks['base_ok'] = true;
            $checks['comptes'] = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
        } catch (Reply $r) { $checks['erreur'] = $r->data['error']; }
          catch (Exception $e) { $checks['erreur'] = $e->getMessage(); }
    }
    $checks['inscription_ouverte'] = ALLOW_REGISTER;
    $ok = $checks['php_ok'] && $checks['pdo_sqlite'] && $checks['password_hash'] && $checks['base_ok'];
    reply(array('ok' => $ok, 'diagnostic' => $checks, 'conseil' => $ok ? 'Tout est prêt.' :
        "Corrigez la ou les lignes à false : activez pdo_sqlite, ou rendez le dossier data inscriptible (droits 755 ou 775)."));
}

/* ---------- Routage ---------- */
function handle() {
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    if ($method === 'GET') {
        $action = isset($_GET['action']) ? $_GET['action'] : '';
        if ($action === 'ping') { db(); reply(array('ok' => true, 'version' => 3, 'register' => ALLOW_REGISTER)); }
        if ($action === 'check') { diagnostic(); }
        fail('Action inconnue.');
    }
    if ($method !== 'POST') { fail('Méthode non autorisée.', 405); }

    if ((int) (isset($_SERVER['CONTENT_LENGTH']) ? $_SERVER['CONTENT_LENGTH'] : 0) > MAX_BODY) { fail('Requête trop volumineuse.', 413); }
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > MAX_BODY) { fail('Requête trop volumineuse.', 413); }
    $body = json_decode($raw, true);
    if (!is_array($body)) { fail('Requête invalide (JSON).'); }

    $action = isset($body['action']) ? $body['action'] : '';
    $pdo = db();

    if ($action === 'register') {
        if (!ALLOW_REGISTER) { fail("La création de compte est fermée sur ce serveur.", 403); }
        $u = valid_username(isset($body['username']) ? $body['username'] : null);
        $p = valid_password(isset($body['password']) ? $body['password'] : null);
        check_lock($u);
        $st = $pdo->prepare('SELECT 1 FROM users WHERE username = ?');
        $st->execute(array($u));
        if ($st->fetchColumn()) { fail('Cet identifiant existe déjà. Choisissez-en un autre ou connectez-vous.', 409); }
        $hash = password_hash($p, PASSWORD_DEFAULT);
        if (!$hash) { fail("Le serveur n'a pas pu chiffrer le mot de passe.", 500); }
        $pdo->prepare('INSERT INTO users (username, pass_hash, created) VALUES (?, ?, ?)')->execute(array($u, $hash, time()));
        $id = (int) $pdo->lastInsertId();
        reply(array('ok' => true, 'token' => new_session($id), 'username' => $u));
    }

    if ($action === 'login') {
        $u = valid_username(isset($body['username']) ? $body['username'] : null);
        $p = (isset($body['password']) && is_string($body['password'])) ? $body['password'] : '';
        check_lock($u);
        $st = $pdo->prepare('SELECT id, username, pass_hash FROM users WHERE username = ?');
        $st->execute(array($u));
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if (!$row || !password_verify($p, $row['pass_hash'])) { record_fail($u); fail('Identifiant ou mot de passe incorrect.', 401); }
        clear_fails($u);
        if (password_needs_rehash($row['pass_hash'], PASSWORD_DEFAULT)) {
            $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute(array(password_hash($p, PASSWORD_DEFAULT), $row['id']));
        }
        reply(array('ok' => true, 'token' => new_session($row['id']), 'username' => $row['username']));
    }

    if ($action === 'me') { $user = auth($body); reply(array('ok' => true, 'username' => $user['username'])); }

    if ($action === 'logout') {
        if (isset($body['token']) && is_string($body['token'])) {
            $pdo->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute(array(hash('sha256', $body['token'])));
        }
        reply(array('ok' => true));
    }

    if ($action === 'password') {
        $user = auth($body);
        $st = $pdo->prepare('SELECT pass_hash FROM users WHERE id = ?');
        $st->execute(array($user['id']));
        $old = isset($body['old']) ? (string) $body['old'] : '';
        if (!password_verify($old, (string) $st->fetchColumn())) { fail('Ancien mot de passe incorrect.', 401); }
        $new = valid_password(isset($body['new']) ? $body['new'] : null);
        $pdo->prepare('UPDATE users SET pass_hash = ? WHERE id = ?')->execute(array(password_hash($new, PASSWORD_DEFAULT), $user['id']));
        $pdo->prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?')->execute(array($user['id'], hash('sha256', (string) $body['token'])));
        reply(array('ok' => true));
    }

    if ($action === 'load') {
        $user = auth($body);
        $st = $pdo->prepare('SELECT k, v, t FROM state WHERE profile = ?');
        $st->execute(array('u:' . $user['id']));
        $state = array();
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $state[$row['k']] = array('v' => json_decode($row['v'], true), 't' => (int) $row['t']);
        }
        reply(array('ok' => true, 'state' => (object) $state, 'username' => $user['username']));
    }

    if ($action === 'save') {
        $user = auth($body);
        $items = isset($body['items']) ? $body['items'] : null;
        if (!is_array($items) || count($items) > MAX_ITEMS) { fail('Éléments invalides.'); }
        $profile = 'u:' . $user['id'];
        // Sans « UPSERT » pour rester compatible avec les anciennes versions de SQLite :
        // on remplace seulement si la version reçue est plus récente.
        $upd = $pdo->prepare('UPDATE state SET v = ?, t = ? WHERE profile = ? AND k = ? AND t < ?');
        $ins = $pdo->prepare('INSERT OR IGNORE INTO state (profile, k, v, t) VALUES (?, ?, ?, ?)');
        $saved = 0;
        $pdo->beginTransaction();
        foreach ($items as $k => $entry) {
            if (!is_string($k) || !preg_match('/^[A-Za-z0-9:_\-.]{1,80}$/', $k)) { continue; }
            if (!is_array($entry) || !array_key_exists('v', $entry) || !isset($entry['t'])) { continue; }
            $v = json_encode($entry['v'], JSON_UNESCAPED_UNICODE);
            if ($v === false || strlen($v) > MAX_VALUE) { continue; }
            $t = (int) $entry['t'];
            if ($t <= 0) { continue; }
            $upd->execute(array($v, $t, $profile, $k, $t));
            if ($upd->rowCount() > 0) { $saved++; continue; }
            $ins->execute(array($profile, $k, $v, $t));
            $saved += $ins->rowCount();
        }
        $pdo->commit();
        reply(array('ok' => true, 'saved' => $saved));
    }

    fail('Action inconnue.');
}

try {
    handle();
} catch (Reply $r) {
    http_response_code($r->status);
    echo json_encode($r->data, JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    error_log('Carnet OFPPT api.php : ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(array('ok' => false, 'error' => 'Erreur du serveur : ' . $e->getMessage() . ' (ouvrez api.php?action=check pour le diagnostic)'), JSON_UNESCAPED_UNICODE);
}
