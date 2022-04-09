<?php
declare(strict_types=1);

namespace Szabacsik\SnowflakeJsonWebToken\Test;

use PHPUnit\Framework\TestCase;
use Szabacsik\SnowflakeJsonWebToken\Token;

class TokenTest extends TestCase
{

    /**
     * @dataProvider dataProvider
     */
    function testToken($data, $expected): void
    {
        $token = new Token;
        $token
            ->setAccount($data['account'])
            ->setUsername($data['username'])
            ->setPrivateKeyPath($data['privateKeyPath'])
            ->setPrivateKeyPassphrase($data['privateKeyPassphrase'])
            ->setIssuedAt($data['issuedAt'])
            ->setExpirationTime($data['expirationTime']);
        $this->assertEqualsCanonicalizing($expected['payload'], $token->getPayload());
        $this->assertEquals($expected['publicKey'], $token->getPublicKey());
        $this->assertEquals($expected['fingerprint'], $token::getPublicKeyFingerprint($token->getPublicKey()));
        $this->assertEquals($expected['token'], $token->generate());
    }

    function testGetPrivateKey(): void
    {
        $privateKeyPath = '/path/to/key/non_existing_rsa_key.p8';
        $token = new Token;
        $token->setPrivateKeyPath($privateKeyPath);
        $this->expectExceptionMessage("File `$privateKeyPath` not found.");
        $token->getPrivateKey();
    }

    public function dataProvider(): array
    {
        $rootDirectory = realpath(__DIR__);
        return [
            "Encrypted Key" =>
                [
                    [
                        'account' => 'fx04724',
                        'username' => 'szabacsik',
                        'privateKeyPath' => $rootDirectory . DIRECTORY_SEPARATOR . 'rsa_key_encrypted.p8',
                        'privateKeyPassphrase' => 'PASSWORD',
                        'issuedAt' => 1649487453,
                        'expirationTime' => 1649491067
                    ],
                    [
                        'payload' => [
                            "iss" => "FX04724.SZABACSIK.SHA256:vg/40EjBAgXO1cRjEvi0eiIWkpaInYrTmvwNgV5awUI=",
                            "sub" => "FX04724.SZABACSIK",
                            "iat" => 1649487453,
                            "exp" => 1649491067
                        ],
                        'publicKey' => <<<ASCII
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3cEh0ciQC9zMIv14iVlT
6cY56FUY3El7hKxdZwGYYRfxAYFRpdeXFvS/CdT4LG1hI7j0Th0OffRwmi9Buuv7
CzuCg4ef3nTWN1S3XUXQQKJ0gx0Cg8nhutU3lC71Gj/O47dG7q70pxXx5cyC1hxo
iPHGe7RHnBO2IGt1jz9D2TsjbD2tJt0D91PPJiQJavFkN91M62irMnLd0chBUJMV
wI2hjkBtnvBrUiH0VEtC52SdBrQAMsI5IB8wbUP2dmpKeAf62rV3VgYBQm/s8k/7
fdBsUOvdWomr0aG6I2rNDZUgtPnKwY2wY2+KqKFth9dRdvlqp4oZRWRxlDuuqIqO
KwIDAQAB
-----END PUBLIC KEY-----

ASCII,
                        'fingerprint' => 'vg/40EjBAgXO1cRjEvi0eiIWkpaInYrTmvwNgV5awUI=',
                        'token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJGWDA0NzI0LlNaQUJBQ1NJSy5TSEEyNTY6dmcvNDBFakJBZ1hPMWNSakV2aTBlaUlXa3BhSW5ZclRtdndOZ1Y1YXdVST0iLCJzdWIiOiJGWDA0NzI0LlNaQUJBQ1NJSyIsImlhdCI6MTY0OTQ4NzQ1MywiZXhwIjoxNjQ5NDkxMDY3fQ.p9cB-TNLBSBbOuJ0_FhfAAI3HLWiVaLkCHB5s1PXWoypqLCoxWt8dAWEQgV2erBGm2eR71OLYxG2wf6XL0gYBGJjyb0Y3MjSznJ5mcRpRS8owwiHdkQ0fPxdJPehMcP3kLlkT5TtgtxuSNbzsF1OgjZzctUabkWCeFHn4i3V5n7kxaiT5WGlBZRvmNdU-OBbRZjj1Xi52fThgjMGwmADnTq2GUbRdLdoV4bfJBynmEoX6MY49w5w0C_ooUchBEqSkmrPXGX54YSIHZ1KEw8ilIXTGc8x5EcykPzI0zByMZKof8GMy5xqZwcttEFmJckx8NLbvs6ojKC4DkRwc0nH2w'
                    ]
                ],
            "Unencrypted Key" =>
                [
                    [
                        'account' => 'fx04724',
                        'username' => 'szabacsik',
                        'privateKeyPath' => $rootDirectory . DIRECTORY_SEPARATOR . 'rsa_key_unencrypted.p8',
                        'privateKeyPassphrase' => '',
                        'issuedAt' => 1649487453,
                        'expirationTime' => 1649491067
                    ],
                    [
                        'payload' => [
                            "iss" => "FX04724.SZABACSIK.SHA256:+pnNKYbK6cd6So1dpAjvyVJQ1q22LxyHqPQ9zafK/78=",
                            "sub" => "FX04724.SZABACSIK",
                            "iat" => 1649487453,
                            "exp" => 1649491067
                        ],
                        'publicKey' => <<<ASCII
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHzFb5pQkj1IqfVCwWd6
F9+EAbel23BeGYZrZZ2wPUzYSfMwkDczOgAYuZg/fGuVKfOczpCHbHoJNq8e3N6v
hkFaM2+/noNLpt4DPm5brKJnftaXiTxvqyPAWTie/8eElLAFOG5R2Z1FOq06mdod
SPYkstmyXhtkrvtgvQE5vlKhk7nPbhsQ1C0F+wMu9jsDWGJYnHdI+tGjB7l1E/OY
ox/dtI2fkAsGXn2o+fwt6hxEECn7gUtPExcbxf0dZ3/sNWzYESH5W7y4Wl1ZuGRQ
C2FUAPW32q2qG1J8jSef6jL1mqEApuArTYTPbXID0zO0b8oldw6jYkx4+xPtO0Xm
0QIDAQAB
-----END PUBLIC KEY-----

ASCII,
                        'fingerprint' => '+pnNKYbK6cd6So1dpAjvyVJQ1q22LxyHqPQ9zafK/78=',
                        'token' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJGWDA0NzI0LlNaQUJBQ1NJSy5TSEEyNTY6K3BuTktZYks2Y2Q2U28xZHBBanZ5VkpRMXEyMkx4eUhxUFE5emFmSy83OD0iLCJzdWIiOiJGWDA0NzI0LlNaQUJBQ1NJSyIsImlhdCI6MTY0OTQ4NzQ1MywiZXhwIjoxNjQ5NDkxMDY3fQ.ZqfK_xy2s5DlztvqssYcD0f5J-KDpjqbI0E3NL7mvmE8hGSZpLtmTl-lyHWg3en29tZfSnOcBGlSScTI6u9w-kAXMZvmFAm3osJ801znElLUQ6bAw-BwmE6FBvgw-g7-6D9QfYmSRt2WZvbMy-O7WIP_LZhmVeV1DwETPw2Sf-3J_BiRHpjt7yMm1JbrsjBlOMDl4dBoNSF0DSIn1kmGu6cfYjDnynbKJzLHzzNPN_9e8LSu9EYTFLL5jA-1WT56oOaW9qtmW8BFOQrOyng_TxVdBK1ThJK4Qx4g9e5Lbk5VI8bCajC45Crv1dmtUDLeHe2ykpDRCRtIsdwH0F7iEw'
                    ]
                ],
        ];
    }
}