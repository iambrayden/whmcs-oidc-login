<?php

namespace M365Sso;

class IdTokenValidator
{
    private $tenantId;
    private $clientId;
    private $leeway = 300;

    public function __construct($tenantId, $clientId)
    {
        $this->tenantId = $tenantId;
        $this->clientId = $clientId;
    }

    public function validate($jwt, array $jwks, $expectedNonce)
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Malformed ID token.');
        }

        $header = json_decode(self::b64url($parts[0]), true);
        $claims = json_decode(self::b64url($parts[1]), true);
        $signature = self::b64url($parts[2]);

        if (!is_array($header) || !is_array($claims)) {
            throw new \RuntimeException('ID token could not be decoded.');
        }
        if (($header['alg'] ?? '') !== 'RS256') {
            throw new \RuntimeException('Unexpected ID token algorithm.');
        }

        $key = $this->findKey($jwks, $header['kid'] ?? '');
        $ok = openssl_verify($parts[0] . '.' . $parts[1], $signature, $key, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new \RuntimeException('ID token signature is invalid.');
        }

        $now = time();
        $issuer = 'https://login.microsoftonline.com/' . $this->tenantId . '/v2.0';

        if (($claims['iss'] ?? '') !== $issuer) {
            throw new \RuntimeException('ID token issuer does not match the configured tenant.');
        }
        if (($claims['tid'] ?? '') !== $this->tenantId) {
            throw new \RuntimeException('ID token tenant does not match the configured tenant.');
        }
        $aud = $claims['aud'] ?? null;
        if ($aud !== $this->clientId && !(is_array($aud) && in_array($this->clientId, $aud, true))) {
            throw new \RuntimeException('ID token audience does not match the client ID.');
        }
        if (!isset($claims['exp']) || $claims['exp'] + $this->leeway < $now) {
            throw new \RuntimeException('ID token has expired.');
        }
        if (isset($claims['nbf']) && $claims['nbf'] - $this->leeway > $now) {
            throw new \RuntimeException('ID token is not valid yet.');
        }
        if (!isset($claims['iat']) || $claims['iat'] - $this->leeway > $now) {
            throw new \RuntimeException('ID token issue time is invalid.');
        }
        if (!is_string($expectedNonce) || !hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            throw new \RuntimeException('ID token nonce mismatch.');
        }
        if (empty($claims['oid'])) {
            throw new \RuntimeException('ID token is missing the oid claim.');
        }

        return $claims;
    }

    private function findKey(array $jwks, $kid)
    {
        foreach ($jwks['keys'] ?? [] as $jwk) {
            if (($jwk['kid'] ?? null) !== $kid || ($jwk['kty'] ?? '') !== 'RSA') {
                continue;
            }
            if (!empty($jwk['x5c'][0])) {
                $pem = "-----BEGIN CERTIFICATE-----\n"
                    . chunk_split($jwk['x5c'][0], 64, "\n")
                    . "-----END CERTIFICATE-----\n";
                $key = openssl_pkey_get_public($pem);
            } else {
                $key = openssl_pkey_get_public(self::rsaPem($jwk['n'], $jwk['e']));
            }
            if ($key === false) {
                throw new \RuntimeException('Signing key could not be loaded.');
            }
            return $key;
        }

        throw new \RuntimeException('No signing key found for kid ' . $kid . '.');
    }

    public static function b64url($data)
    {
        $data = strtr($data, '-_', '+/');
        $pad = strlen($data) % 4;
        if ($pad) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($data, true);
        if ($out === false) {
            throw new \RuntimeException('Invalid base64url data.');
        }
        return $out;
    }

    private static function rsaPem($n, $e)
    {
        $int = function ($bytes) {
            if (ord($bytes[0]) > 0x7f) {
                $bytes = "\x00" . $bytes;
            }
            return "\x02" . self::derLength(strlen($bytes)) . $bytes;
        };

        $seq = $int(self::b64url($n)) . $int(self::b64url($e));
        $rsaKey = "\x30" . self::derLength(strlen($seq)) . $seq;
        $bitString = "\x03" . self::derLength(strlen($rsaKey) + 1) . "\x00" . $rsaKey;
        $algo = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $spki = $algo . $bitString;
        $der = "\x30" . self::derLength(strlen($spki)) . $spki;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derLength($len)
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
