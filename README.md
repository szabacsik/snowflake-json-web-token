# Snowflake JSON Web Token

## Usage

```shell
composer require szabacsik/snowflake-json-web-token
```

```php
    $token = new \Szabacsik\SnowflakeJsonWebToken\Token();
    $token
        ->setAccount('account')
        ->setUsername('username')
        ->setPrivateKeyPath('/path/to/your/private_key.p8')
        ->setPrivateKeyPassphrase('password')
        ->setIssuedAt(time())
        ->setExpirationTime(time() + 3600);
    echo $token->generate();
```

## Links

<https://docs.snowflake.com/en/developer-guide/sql-api/index.html>
<https://api.developers.snowflake.com/>
<https://docs.snowflake.com/en/developer-guide/sql-api/authenticating.html#label-sql-api-authenticating-key-pair>
<https://datatracker.ietf.org/doc/html/rfc7519>
