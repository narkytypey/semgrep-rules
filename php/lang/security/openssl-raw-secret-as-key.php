<?php

final class SessionCrypto
{
    public const ALGO_LEGACY = 'aes-128-gcm';
    public const ALGO = 'aes-256-gcm';

    public function __construct(private string $cookieSecret)
    {
    }

    public function decryptLegacy(string $data, string $iv, string $tag): string|false
    {
        $secret = $this->cookieSecret;
        // ruleid: openssl-raw-secret-as-key
        return openssl_decrypt($data, self::ALGO_LEGACY, $secret, 0, $iv, $tag);
    }

    public function encryptLegacy(string $data, string $iv, &$tag): string|false
    {
        // ruleid: openssl-raw-secret-as-key
        return openssl_encrypt($data, 'aes-128-gcm', $this->cookieSecret, 0, $iv, $tag);
    }

    public function encryptWithPassword(string $data, string $password, string $iv): string|false
    {
        // ruleid: openssl-raw-secret-as-key
        return openssl_encrypt($data, 'AES-256-CBC', $password, OPENSSL_RAW_DATA, $iv);
    }

    public function decrypt(string $data, string $iv, string $tag): string|false
    {
        $key = hash_hkdf('sha256', $this->cookieSecret, 32, 'session-encryption');
        // ok: openssl-raw-secret-as-key
        return openssl_decrypt($data, self::ALGO, $key, 0, $iv, $tag);
    }

    public function encrypt(string $data, string $iv, &$tag): string|false
    {
        // ok: openssl-raw-secret-as-key
        return openssl_encrypt($data, self::ALGO, hash_hkdf('sha256', $this->cookieSecret, 32), 0, $iv, $tag);
    }

    public function encryptWithRandomKey(string $data, string $iv, &$tag): string|false
    {
        $encryptionKey = random_bytes(32);
        // ok: openssl-raw-secret-as-key
        return openssl_encrypt($data, 'aes-256-gcm', $encryptionKey, 0, $iv, $tag);
    }
}
