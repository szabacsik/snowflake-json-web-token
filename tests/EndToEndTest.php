<?php

namespace Szabacsik\SnowflakeJsonWebToken\Test;

use PHPUnit\Framework\TestCase;
use Szabacsik\SnowflakeJsonWebToken\Token;

class EndToEndTest extends TestCase
{
    public function testQuery(): void
    {
        $username = '{{YOUR_USERNAME}}'; //johndoe
        $account = '{{YOUR_ACCOUNT}}'; //bz12345
        $region = '{{YOUR_REGION}}'; //eu-central-1
        $privateKeyPassphrase = '{{YOUR_PASSPHRASE}}';
        $privateKeyPath = __DIR__ . '/../snowflake_rsa_private_key.p8';
        $accountIdentifier = $account . '.' . $region;
        $token = new Token();
        $token
            ->setAccount($account)
            ->setUsername($username)
            ->setPrivateKeyPath($privateKeyPath)
            ->setPrivateKeyPassphrase($privateKeyPassphrase)
            ->setIssuedAt(time())
            ->setExpirationTime(time() + 3600);
        $this->assertIsString($token->generate());
        $endpoint = "https://$accountIdentifier.snowflakecomputing.com/api/v2/statements";
        $statement = "select convert_timezone('UTC', 'Europe/Budapest', sysdate()) as NOW;";
        $data = [
            'statement' => $statement,
            "timeout" => 60,
            "database" => "TEST_DATABASE",
            "schema" => "TEST_SCHEMA",
            "warehouse" => "TEST_WAREHOUSE",
        ];
        $options = [
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", [
                    'Content-Type: application/json',
                    'Accept: application/json',
                    'User-Agent: PHP/1.0',
                    'X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT',
                    "Authorization: Bearer {$token->generate()}",
                ]),
                'content' => json_encode($data)
            ]
        ];
        $context = stream_context_create($options);
        $result = file_get_contents($endpoint, false, $context);
        $this->assertIsString($result);
        $response = json_decode($result);
        $this->assertObjectHasAttribute('resultSetMetaData', $response);
        $this->assertObjectHasAttribute('data', $response);
        $this->assertEquals('Statement executed successfully.', $response->message);
        $epoc = $response->data[0][0];
        $now = \DateTimeImmutable::createFromFormat('U.u', number_format((float)$epoc, 6, '.', ''));
        echo $now->format('Y-m-d H:i:s.u');
    }
}
