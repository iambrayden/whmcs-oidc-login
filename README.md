# WHMCS Microsoft 365 Admin Login

WHMCS addon module that lets administrators sign in to the admin area with their Microsoft 365 (Entra ID) account using OpenID Connect.

- Authorization code flow with PKCE, state and nonce
- ID token signature checked against Microsoft's published keys, plus issuer, audience, tenant, expiry and nonce
- Locked to a single tenant
- Admins are matched by their immutable Entra object ID, not by email
- Optional restriction to specific groups or app roles
- Every sign-in and failure is written to the WHMCS activity log

Requires WHMCS 8.x and PHP 7.4+ with the curl and openssl extensions.

## Installation

1. Copy `modules/addons/m365sso` into your WHMCS install so it lives at `<whmcs>/modules/addons/m365sso`.
2. In WHMCS go to **System Settings > Addon Modules**, activate **Microsoft 365 Admin Login** and give your admin role access to it.

## Entra ID app registration

1. In the [Entra admin center](https://entra.microsoft.com) go to **App registrations > New registration**.
2. Supported account types: **Accounts in this organizational directory only**.
3. Redirect URI: platform **Web**, value `https://your-whmcs-domain/modules/addons/m365sso/login.php` (the exact URL is shown on the addon page).
4. Under **Certificates & secrets**, create a client secret and copy its **value**.
5. Under **API permissions**, the default `User.Read` delegated permission is enough. `openid`, `profile` and `email` are requested at sign-in.
6. Copy the **Directory (tenant) ID** and **Application (client) ID** from the overview page.

To limit who can sign in, either:

- Set **Assignment required** to Yes on the enterprise application and assign users or groups to it, or
- Add app roles to the registration, assign them, and put the role values in **Required groups / app roles**, or
- Add a groups claim under **Token configuration** and put the group object IDs in **Required groups / app roles**. If users are in more than 200 groups the claim is omitted, so use "Groups assigned to the application" or app roles instead.

## Configuration

Fill in the module settings under **System Settings > Addon Modules > Microsoft 365 Admin Login > Configure**:

| Setting | Description |
| --- | --- |
| Directory (tenant) ID | Tenant GUID. Only accounts from this tenant are accepted. |
| Application (client) ID | From the app registration. |
| Client secret | The secret value. |
| Required groups / app roles | Optional, comma separated. |
| Auto-link by email | Links a Microsoft account to the WHMCS admin with the same email on first sign-in. |
| Always show account picker | Shows the Microsoft account picker on every sign-in. |

## Linking admins

Each WHMCS admin must be linked to a Microsoft account before they can sign in with it.

- **Manual (recommended):** the admin signs in with their WHMCS password, opens **Addons > Microsoft 365 Admin Login** and clicks **Link my Microsoft account**.
- **Automatic:** turn on **Auto-link by email**. The first Microsoft sign-in is linked to the WHMCS admin whose email matches the `email` claim (falling back to `preferred_username`). Only use this if the email addresses on your WHMCS admins are trusted.

Links can be removed from the addon page.

## Signing in

Admins open `https://your-whmcs-domain/modules/addons/m365sso/login.php`. To add a button to the admin login page, put this in your admin login template (`<admin>/templates/login.tpl`, re-apply after WHMCS updates):

```html
<a href="../modules/addons/m365sso/login.php" class="btn btn-default btn-block">Sign in with Microsoft 365</a>
```

## Security notes

- Signing in with Microsoft skips WHMCS two-factor authentication. Enforce MFA in Entra ID with Conditional Access instead.
- Password login stays available, so you keep a way in if Entra ID is unavailable.
- Deactivating the module drops the account link table.
