<?php

use WHMCS\Database\Capsule;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/OidcClient.php';
require_once __DIR__ . '/lib/IdTokenValidator.php';

const M365SSO_TABLE = 'mod_m365sso_links';

function m365sso_config()
{
    return [
        'name' => 'Microsoft 365 Admin Login',
        'description' => 'Lets WHMCS administrators sign in with their Microsoft 365 / Entra ID account using OpenID Connect.',
        'version' => '1.0.0',
        'author' => 'Waylon Ventures',
        'language' => 'english',
        'fields' => [
            'tenantId' => [
                'FriendlyName' => 'Directory (tenant) ID',
                'Type' => 'text',
                'Size' => '40',
                'Description' => 'GUID of your Entra ID tenant. Only accounts from this tenant can sign in.',
            ],
            'clientId' => [
                'FriendlyName' => 'Application (client) ID',
                'Type' => 'text',
                'Size' => '40',
            ],
            'clientSecret' => [
                'FriendlyName' => 'Client secret',
                'Type' => 'password',
                'Size' => '60',
                'Description' => 'The secret value (not the secret ID).',
            ],
            'allowedGroups' => [
                'FriendlyName' => 'Required groups / app roles',
                'Type' => 'text',
                'Size' => '60',
                'Description' => 'Optional. Comma separated group object IDs or app role values. The user must have at least one.',
            ],
            'autoLinkByEmail' => [
                'FriendlyName' => 'Auto-link by email',
                'Type' => 'yesno',
                'Description' => 'On first sign-in, link to the WHMCS admin whose email matches the Microsoft account. Leave off to require each admin to link from the module page.',
            ],
            'promptSelectAccount' => [
                'FriendlyName' => 'Always show account picker',
                'Type' => 'yesno',
                'Description' => 'Sends prompt=select_account so users can choose which Microsoft account to use.',
            ],
        ],
    ];
}

function m365sso_activate()
{
    try {
        if (!Capsule::schema()->hasTable(M365SSO_TABLE)) {
            Capsule::schema()->create(M365SSO_TABLE, function ($table) {
                $table->increments('id');
                $table->integer('admin_id')->unsigned()->unique();
                $table->string('tenant_id', 64);
                $table->string('object_id', 64);
                $table->string('email', 255)->default('');
                $table->string('display_name', 255)->default('');
                $table->timestamp('linked_at')->nullable();
                $table->timestamp('last_login_at')->nullable();
                $table->unique(['tenant_id', 'object_id']);
            });
        }
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => 'Could not create table: ' . $e->getMessage()];
    }

    return ['status' => 'success', 'description' => 'Module activated. Configure the tenant and app registration details, then link admin accounts from Addons > Microsoft 365 Admin Login.'];
}

function m365sso_deactivate()
{
    try {
        Capsule::schema()->dropIfExists(M365SSO_TABLE);
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => $e->getMessage()];
    }

    return ['status' => 'success', 'description' => 'Module deactivated and account links removed.'];
}

function m365sso_settings()
{
    return Capsule::table('tbladdonmodules')
        ->where('module', 'm365sso')
        ->pluck('value', 'setting')
        ->all();
}

function m365sso_system_url()
{
    $url = \WHMCS\Config\Setting::getValue('SystemURL');
    return rtrim((string) $url, '/') . '/';
}

function m365sso_redirect_uri()
{
    return m365sso_system_url() . 'modules/addons/m365sso/login.php';
}

function m365sso_admin_url()
{
    $folder = 'admin';
    if (class_exists('\App') && method_exists('\App', 'get_admin_folder_name')) {
        $folder = \App::get_admin_folder_name();
    } elseif (!empty($GLOBALS['customadminpath'])) {
        $folder = $GLOBALS['customadminpath'];
    }
    return m365sso_system_url() . trim($folder, '/') . '/';
}

function m365sso_output($vars)
{
    $modulelink = $vars['modulelink'];
    $currentAdmin = (int) ($_SESSION['adminid'] ?? 0);
    $message = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['m365action'] ?? '') === 'unlink') {
        check_token('WHMCS.admin.default');
        $adminId = (int) ($_POST['admin_id'] ?? 0);
        Capsule::table(M365SSO_TABLE)->where('admin_id', $adminId)->delete();
        logActivity('Microsoft 365 login unlinked from admin ID ' . $adminId);
        $message = '<div class="alert alert-success">Microsoft account unlinked.</div>';
    }

    if (isset($_GET['linked'])) {
        $message = '<div class="alert alert-success">Your Microsoft account is now linked. You can sign in with it from the admin login page.</div>';
    }

    $_SESSION['m365sso_link_key'] = \M365Sso\OidcClient::randomToken(16);
    $loginUrl = m365sso_redirect_uri();
    $linkUrl = $loginUrl . '?action=link&key=' . rawurlencode($_SESSION['m365sso_link_key']);

    $configured = !empty($vars['tenantId']) && !empty($vars['clientId']) && !empty($vars['clientSecret']);

    $admins = Capsule::table('tbladmins as a')
        ->leftJoin(M365SSO_TABLE . ' as l', 'l.admin_id', '=', 'a.id')
        ->select('a.id', 'a.username', 'a.firstname', 'a.lastname', 'a.email', 'a.disabled',
            'l.email as ms_email', 'l.display_name as ms_name', 'l.last_login_at')
        ->orderBy('a.username')
        ->get();

    $e = function ($v) {
        return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
    };

    echo $message;

    if (!$configured) {
        echo '<div class="alert alert-warning">Enter the tenant ID, client ID and client secret under '
            . 'System Settings &gt; Addon Modules before linking accounts.</div>';
    }

    echo '<div class="panel panel-default"><div class="panel-heading"><strong>App registration</strong></div><div class="panel-body">';
    echo '<p>Add this as a <strong>Web</strong> redirect URI on the Entra ID app registration. '
        . 'It is also the URL admins open to sign in:</p>';
    echo '<p><code>' . $e($loginUrl) . '</code></p>';
    echo '</div></div>';

    if ($configured) {
        echo '<p><a class="btn btn-primary" href="' . $e($linkUrl) . '">Link my Microsoft account</a></p>';
    }

    echo '<table class="table table-striped"><thead><tr>'
        . '<th>Admin</th><th>WHMCS email</th><th>Microsoft account</th><th>Last Microsoft login</th><th></th>'
        . '</tr></thead><tbody>';

    foreach ($admins as $admin) {
        $name = trim($admin->firstname . ' ' . $admin->lastname);
        echo '<tr>';
        echo '<td>' . $e($admin->username) . ($name ? ' <span class="text-muted">(' . $e($name) . ')</span>' : '')
            . ($admin->disabled ? ' <span class="label label-default">disabled</span>' : '')
            . ((int) $admin->id === $currentAdmin ? ' <span class="label label-info">you</span>' : '') . '</td>';
        echo '<td>' . $e($admin->email) . '</td>';
        if ($admin->ms_email !== null) {
            echo '<td>' . $e($admin->ms_name) . '<br><small>' . $e($admin->ms_email) . '</small></td>';
            echo '<td>' . $e($admin->last_login_at ?: 'Never') . '</td>';
            echo '<td><form method="post" action="' . $e($modulelink) . '" onsubmit="return confirm(\'Unlink this Microsoft account?\');">'
                . generate_token('form')
                . '<input type="hidden" name="m365action" value="unlink">'
                . '<input type="hidden" name="admin_id" value="' . (int) $admin->id . '">'
                . '<button class="btn btn-xs btn-danger" type="submit">Unlink</button></form></td>';
        } else {
            echo '<td colspan="3" class="text-muted">Not linked</td>';
        }
        echo '</tr>';
    }

    echo '</tbody></table>';
}
