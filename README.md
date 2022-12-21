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

## Create private key
```shell
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -out snowflake_rsa_private_key.p8
```

## Create public key
```shell
openssl rsa -in snowflake_rsa_private_key.p8 -pubout -out snowflake_rsa_public_key.pub
```

## Set your public key to your snowflake user
```shell
alter user {{YOUR_USERNAME}} set rsa_public_key='from snowflake_rsa_public_key.pub MIIBIjANBgkqhkiG...';
```

## Submitting a test request to execute SQL statement
```shell
./tests/EndToEndTest.php
```

## Links

<https://docs.snowflake.com/en/developer-guide/sql-api/index.html>  
<https://api.developers.snowflake.com/>  
<https://docs.snowflake.com/en/developer-guide/sql-api/authenticating.html#label-sql-api-authenticating-key-pair>  
<https://datatracker.ietf.org/doc/html/rfc7519>  
<https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests.html>  
<https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests.html#example-of-a-request>  
<https://docs.snowflake.com/en/developer-guide/sql-api/authenticating.html#using-key-pair-authentication>  
<https://streamsets.com/blog/snowflake-key-pair-authentication/>  

