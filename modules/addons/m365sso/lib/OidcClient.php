<?php

namespace M365Sso;

class OidcClient
{
    private $tenantId;
    private $clientId;
    private $clientSecret;
    private $redirectUri;

    public function __construct($tenantId, $clientId, $clientSecret, $redirectUri)
    {
        $this->tenantId = $tenantId;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
    }

    private function base()
    {
        return 'https://login.microsoftonline.com/' . rawurlencode($this->tenantId);
    }

    public function authorizationUrl($state, $nonce, $codeVerifier, $prompt = '', $loginHint = '')
    {
        $params = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'response_mode' => 'query',
            'scope' => 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::pkceChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];
        if ($prompt !== '') {
            $params['prompt'] = $prompt;
        }
        if ($loginHint !== '') {
            $params['login_hint'] = $loginHint;
        }

        return $this->base() . '/oauth2/v2.0/authorize?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    public function exchangeCode($code, $codeVerifier)
    {
        $response = $this->request('POST', $this->base() . '/oauth2/v2.0/token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
            'scope' => 'openid profile email',
        ]);

        if (!empty($response['error'])) {
            throw new \RuntimeException('Token endpoint error: ' . $response['error']
                . (isset($response['error_description']) ? ' - ' . strtok($response['error_description'], "\r\n") : ''));
        }
        if (empty($response['id_token'])) {
            throw new \RuntimeException('Token response did not include an ID token.');
        }

        return $response;
    }

    public function jwks()
    {
        $keys = $this->request('GET', $this->base() . '/discovery/v2.0/keys');
        if (empty($keys['keys'])) {
            throw new \RuntimeException('Could not load Microsoft signing keys.');
        }
        return $keys;
    }

    private function request($method, $url, array $form = null)
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
        }

        $body = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new \RuntimeException('HTTP request to Microsoft failed: ' . $err);
        }
        $json = json_decode($body, true);
        if (!is_array($json)) {
            throw new \RuntimeException('Unexpected response from Microsoft.');
        }
        return $json;
    }

    public static function randomToken($bytes = 32)
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public static function pkceChallenge($verifier)
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
