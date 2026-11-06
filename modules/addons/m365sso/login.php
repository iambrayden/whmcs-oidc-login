<?php

use WHMCS\Database\Capsule;
use M365Sso\IdTokenValidator;
use M365Sso\OidcClient;

require __DIR__ . '/../../../init.php';
require_once __DIR__ . '/m365sso.php';

function m365sso_fail($message, $logDetail = null)
{
    logActivity('Microsoft 365 admin login failed: ' . ($logDetail ?: $message));
    $loginUrl = htmlspecialchars(m365sso_admin_url() . 'login.php', ENT_QUOTES, 'UTF-8');
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Sign-in failed</title>'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f3f4f6;color:#1f2937;'
        . 'display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}'
        . '.box{background:#fff;padding:32px;border-radius:8px;max-width:440px;box-shadow:0 1px 3px rgba(0,0,0,.1)}'
        . 'a{color:#2563eb}</style></head><body><div class="box"><h2>Sign-in failed</h2><p>'
        . htmlspecialchars($message, ENT_QUOTES, 'UTF-8')
        . '</p><p><a href="' . $loginUrl . '">Back to admin login</a></p></div></body></html>';
    exit;
}

function m365sso_redirect($url)
{
    header('Location: ' . $url, true, 302);
    exit;
}

$settings = m365sso_settings();
$tenantId = strtolower(trim($settings['tenantId'] ?? ''));
$clientId = trim($settings['clientId'] ?? '');
$clientSecret = $settings['clientSecret'] ?? '';

if (function_exists('decrypt') && $clientSecret !== '') {
    $decrypted = decrypt($clientSecret);
    if ($decrypted !== '' && $decrypted !== false) {
        $clientSecret = $decrypted;
    }
}

if (!isset($settings['version'])) {
    m365sso_fail('Microsoft 365 login is not enabled.');
}
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $tenantId)) {
    m365sso_fail('Microsoft 365 login is not configured correctly.', 'tenant ID must be the directory GUID');
}
if ($clientId === '' || $clientSecret === '') {
    m365sso_fail('Microsoft 365 login is not configured correctly.', 'client ID or secret missing');
}

$client = new OidcClient($tenantId, $clientId, $clientSecret, m365sso_redirect_uri());

if (!isset($_GET['code']) && !isset($_GET['error'])) {
    $mode = 'login';
    if (($_GET['action'] ?? '') === 'link') {
        $key = $_SESSION['m365sso_link_key'] ?? '';
        if (empty($_SESSION['adminid']) || $key === '' || !hash_equals($key, (string) ($_GET['key'] ?? ''))) {
            m365sso_fail('Open the Microsoft 365 Admin Login addon page and use the link button there.');
        }
        unset($_SESSION['m365sso_link_key']);
        $mode = 'link';
    }

    $flow = [
        'state' => OidcClient::randomToken(),
        'nonce' => OidcClient::randomToken(),
        'verifier' => OidcClient::randomToken(48),
        'mode' => $mode,
        'admin_id' => $mode === 'link' ? (int) $_SESSION['adminid'] : 0,
        'started' => time(),
    ];
    $_SESSION['m365sso_flow'] = $flow;

    $prompt = !empty($settings['promptSelectAccount']) || $mode === 'link' ? 'select_account' : '';
    m365sso_redirect($client->authorizationUrl($flow['state'], $flow['nonce'], $flow['verifier'], $prompt));
}

$flow = $_SESSION['m365sso_flow'] ?? null;
unset($_SESSION['m365sso_flow']);

if (!is_array($flow) || !hash_equals($flow['state'], (string) ($_GET['state'] ?? ''))) {
    m365sso_fail('Your sign-in session expired or is invalid. Please try again.', 'state mismatch');
}
if (time() - $flow['started'] > 600) {
    m365sso_fail('Your sign-in session expired. Please try again.', 'flow older than 10 minutes');
}
if (isset($_GET['error'])) {
    $desc = strtok((string) ($_GET['error_description'] ?? ''), "\r\n");
    m365sso_fail('Microsoft returned an error: ' . $_GET['error'], $_GET['error'] . ' ' . $desc);
}

try {
    $tokens = $client->exchangeCode((string) $_GET['code'], $flow['verifier']);
    $validator = new IdTokenValidator($tenantId, $clientId);
    $claims = $validator->validate($tokens['id_token'], $client->jwks(), $flow['nonce']);
} catch (\Exception $e) {
    m365sso_fail('Microsoft sign-in could not be verified.', $e->getMessage());
}

$oid = (string) $claims['oid'];
$msEmail = strtolower(trim((string) ($claims['email'] ?? $claims['preferred_username'] ?? '')));
$msName = (string) ($claims['name'] ?? '');

$required = array_filter(array_map('trim', explode(',', (string) ($settings['allowedGroups'] ?? ''))));
if ($required) {
    if (isset($claims['_claim_names']['groups'])) {
        m365sso_fail('Your account is in too many groups for a group check. Ask an administrator to use app roles or "Groups assigned to the application".', 'group overage for ' . $msEmail);
    }
    $held = array_merge((array) ($claims['groups'] ?? []), (array) ($claims['roles'] ?? []));
    if (!array_intersect($required, $held)) {
        m365sso_fail('Your Microsoft account is not permitted to sign in to WHMCS admin.', 'missing required group/role for ' . $msEmail);
    }
}

$now = date('Y-m-d H:i:s');

if ($flow['mode'] === 'link') {
    $adminId = (int) $flow['admin_id'];
    if ($adminId <= 0 || (int) ($_SESSION['adminid'] ?? 0) !== $adminId) {
        m365sso_fail('You must be signed in to WHMCS to link an account.');
    }

    $existing = Capsule::table(M365SSO_TABLE)
        ->where('tenant_id', $tenantId)->where('object_id', $oid)->first();
    if ($existing && (int) $existing->admin_id !== $adminId) {
        m365sso_fail('That Microsoft account is already linked to another WHMCS admin.', $msEmail . ' already linked to admin ID ' . $existing->admin_id);
    }

    Capsule::table(M365SSO_TABLE)->where('admin_id', $adminId)->delete();
    Capsule::table(M365SSO_TABLE)->insert([
        'admin_id' => $adminId,
        'tenant_id' => $tenantId,
        'object_id' => $oid,
        'email' => $msEmail,
        'display_name' => $msName,
        'linked_at' => $now,
    ]);
    logActivity('Microsoft 365 account ' . $msEmail . ' linked to admin ID ' . $adminId);
    m365sso_redirect(m365sso_admin_url() . 'addonmodules.php?module=m365sso&linked=1');
}

$link = Capsule::table(M365SSO_TABLE)
    ->where('tenant_id', $tenantId)->where('object_id', $oid)->first();

if (!$link && !empty($settings['autoLinkByEmail']) && $msEmail !== '') {
    $matches = Capsule::table('tbladmins')->whereRaw('LOWER(email) = ?', [$msEmail])->pluck('id')->all();
    if (count($matches) === 1) {
        $alreadyLinked = Capsule::table(M365SSO_TABLE)->where('admin_id', $matches[0])->exists();
        if (!$alreadyLinked) {
            Capsule::table(M365SSO_TABLE)->insert([
                'admin_id' => (int) $matches[0],
                'tenant_id' => $tenantId,
                'object_id' => $oid,
                'email' => $msEmail,
                'display_name' => $msName,
                'linked_at' => $now,
            ]);
            logActivity('Microsoft 365 account ' . $msEmail . ' auto-linked to admin ID ' . $matches[0]);
            $link = Capsule::table(M365SSO_TABLE)
                ->where('tenant_id', $tenantId)->where('object_id', $oid)->first();
        }
    }
}

if (!$link) {
    m365sso_fail('No WHMCS administrator is linked to this Microsoft account (' . $msEmail . ').', 'no link for ' . $msEmail . ' oid ' . $oid);
}

$admin = Capsule::table('tbladmins')->where('id', $link->admin_id)->first();
if (!$admin) {
    Capsule::table(M365SSO_TABLE)->where('id', $link->id)->delete();
    m365sso_fail('The linked WHMCS administrator no longer exists.');
}
if (!empty($admin->disabled)) {
    m365sso_fail('This WHMCS administrator account is disabled.', 'disabled admin ' . $admin->username);
}

$auth = new \WHMCS\Auth();
if (!$auth->getInfobyID((int) $admin->id)) {
    m365sso_fail('Could not load the WHMCS administrator.', 'getInfobyID failed for ' . $admin->id);
}
$auth->setSessionVars();
$auth->processLogin();

Capsule::table(M365SSO_TABLE)->where('id', $link->id)->update([
    'last_login_at' => $now,
    'email' => $msEmail,
    'display_name' => $msName,
]);
logActivity('Admin ' . $admin->username . ' signed in with Microsoft 365 (' . $msEmail . ')');

m365sso_redirect(m365sso_admin_url());
