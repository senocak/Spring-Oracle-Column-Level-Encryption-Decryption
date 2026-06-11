# Spring Oracle Column Level Encryption Decryption
This project demonstrates how to implement column-level encryption and decryption in a Spring application using Oracle Database. It provides a simple example of how to encrypt sensitive data before storing it in the database and decrypt it when retrieving the data.

DBMS_CRYPTO is a built-in package in Oracle Database that provides cryptographic functions for encryption and decryption. In this project, we will use DBMS_CRYPTO to perform column-level encryption and decryption.

Grant access to DBMS_CRYPTO:
```sql
GRANT EXECUTE ON DBMS_CRYPTO TO your_schema;
-- GRANT EXECUTE ON DBMS_CRYPTO TO SYSTEM;
```

Encryption and decryption function should be created in the database to handle the encryption and decryption logic. For example:

```sql
CREATE OR REPLACE FUNCTION encrypt_text(p_text VARCHAR2)
    RETURN RAW
AS
BEGIN
    RETURN DBMS_CRYPTO.ENCRYPT(
            src => UTL_RAW.CAST_TO_RAW(p_text),
            typ => DBMS_CRYPTO.ENCRYPT_AES128
                + DBMS_CRYPTO.CHAIN_CBC
                + DBMS_CRYPTO.PAD_PKCS5,
            key => UTL_RAW.CAST_TO_RAW('1234567890123456')
           );
END;
```
```sql
CREATE OR REPLACE FUNCTION decrypt_text(p_raw RAW)
    RETURN VARCHAR2
AS
BEGIN
    RETURN UTL_RAW.CAST_TO_VARCHAR2(
            DBMS_CRYPTO.DECRYPT(
                    src => p_raw,
                    typ => DBMS_CRYPTO.ENCRYPT_AES128
                        + DBMS_CRYPTO.CHAIN_CBC
                        + DBMS_CRYPTO.PAD_PKCS5,
                    key => UTL_RAW.CAST_TO_RAW('1234567890123456')
            )
           );
END;
```

Db level demo;
```sql
SELECT encrypt_text('hello') FROM dual; -- EBB7C703E675DB3DA397038B4C17823C
SELECT decrypt_text('EBB7C703E675DB3DA397038B4C17823C') FROM dual; -- hello
```

In the Spring application, we will create a service that interacts with the database to perform encryption and decryption operations. The service will use JDBC to call the DBMS_CRYPTO functions.