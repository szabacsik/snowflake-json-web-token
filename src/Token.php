<?php
declare(strict_types=1);

namespace Szabacsik\SnowflakeJsonWebToken;

use Firebase\JWT\JWT;
use JetBrains\PhpStorm\ArrayShape;
use OpenSSLAsymmetricKey;
use function preg_replace;

class Token
{
    private string $username;
    private string $account;
    private int $issuedAt;
    private int $expirationTime;
    private ?string $privateKeyPath = null;
    private ?string $privateKeyPassphrase = null;
    private ?OpenSSLAsymmetricKey $privateKey = null;

    public function __construct()
    {
        $this->issuedAt = time();
        $this->expirationTime = $this->issuedAt + 3600;
    }

    public function __toString(): string
    {
        return $this->generate();
    }

    public function generate(): string
    {
        return JWT::encode($this->getPayload(), $this->getPrivateKey(), 'RS256');
    }

    public function setUsername(string $username): Token
    {
        $this->username = $username;
        return $this;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setAccount(string $account): Token
    {
        $this->account = $account;
        return $this;
    }

    public function getAccount(): string
    {
        return $this->account;
    }

    public function setIssuedAt(int $issuedAt): Token
    {
        $this->issuedAt = $issuedAt;
        return $this;
    }

    public function getIssuedAt(): int
    {
        return $this->issuedAt;
    }

    public function setExpirationTime(int $expirationTime): Token
    {
        $this->expirationTime = $expirationTime;
        return $this;
    }

    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    public function getPayload(): array
    {
        return [
            "iss" => $this->getIssuer(),
            "sub" => $this->getSubject(),
            "iat" => $this->issuedAt,
            "exp" => $this->expirationTime
        ];
    }

    public function getIssuer(): string
    {
        return
            mb_strtoupper($this->account) . '.' .
            mb_strtoupper($this->username) .
            '.SHA256:' . self::getPublicKeyFingerprint($this->getPublicKey());
    }

    public function getSubject(): string
    {
        return mb_strtoupper($this->account) . '.' . mb_strtoupper($this->username);
    }

    public function setPrivateKeyPath(string $privateKeyPath): Token
    {
        if ($this->privateKeyPath != $privateKeyPath) {
            $this->privateKeyPath = $privateKeyPath;
            $this->privateKey = null;
        }
        return $this;
    }

    public function getPrivateKeyPath(): string
    {
        return $this->privateKeyPath;
    }

    public function setPrivateKeyPassphrase(string $privateKeyPassphrase): Token
    {
        $this->privateKeyPassphrase = strlen($privateKeyPassphrase) > 0 ? $privateKeyPassphrase : null;
        return $this;
    }

    public function getPrivateKeyPassphrase(): string
    {
        return $this->privateKeyPassphrase;
    }

    public function getPrivateKey(): OpenSSLAsymmetricKey
    {
        if (!is_null($this->privateKey)) {
            return $this->privateKey;
        }
        if (!file_exists($this->privateKeyPath)) {
            throw new \RuntimeException('File `' . $this->privateKeyPath . '` not found.');
        }
        if (!is_readable($this->privateKeyPath)) {
            throw new \RuntimeException('File `' . $this->privateKeyPath . '` is not readable.');
        }
        $privateKey = openssl_pkey_get_private(
            file_get_contents($this->privateKeyPath),
            $this->privateKeyPassphrase
        );
        if (false === $privateKey) {
            throw new \RuntimeException("Can't get private key from `" . $this->privateKeyPath . '` file. Wrong passphrase?');
        }
        $this->privateKey = $privateKey;
        return $this->privateKey;
    }

    public function getPublicKey(): string
    {
        return openssl_pkey_get_details($this->getPrivateKey())['key'];
    }

    public static function getPublicKeyFingerprint(string $pemEncodedPublicKey, string $algo = 'sha256'): string
    {
        $keyWithoutPemWrapper = preg_replace(
            '/^-----BEGIN (?:[A-Z]+ )?PUBLIC KEY-----([A-Za-z\d\\/+\\s=]+)-----END (?:[A-Z]+ )?PUBLIC KEY-----$/m',
            '\\1',
            $pemEncodedPublicKey
        );
        $keyDataWithoutSpaces = preg_replace('/\\s+/', '', $keyWithoutPemWrapper);
        $binaryKey = \base64_decode($keyDataWithoutSpaces);
        return base64_encode(\hash($algo, $binaryKey, true));
    }

}