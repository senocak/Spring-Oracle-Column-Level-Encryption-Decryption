# Spring Kotlin — Column-Level Encryption / Decryption with Oracle `DBMS_CRYPTO`

This project shows how to push column-level encryption *into the database* while keeping the application code free of any awareness of it. The Spring/Kotlin/JPA layer reads and writes plain Kotlin `String` values; ciphertext lives only inside the database column, and the encryption/decryption hop happens inside a pair of SQL functions that the database invokes on every read and write.

| Component        | Choice                                         |
|------------------|------------------------------------------------|
| Database         | Oracle Free 23                                 |
| Crypto provider  | `DBMS_CRYPTO` (AES-128 / CBC / PKCS5)          |
| Column type      | `RAW(2000)`                                    |
| ORM hook         | Hibernate `@ColumnTransformer`                 |

The entity declares an `encrypt_text(text)` / `decrypt_text(raw)` function pair and wires them into the column via `@ColumnTransformer`. Hibernate then rewrites every generated query to call those functions automatically.

## Core idea

Hibernate's `@ColumnTransformer` lets you inject a SQL expression around a column on read and on write. Anywhere Hibernate would emit `SELECT firstname FROM users` it instead emits `SELECT decrypt_text(firstname) FROM users`, and anywhere it would emit `INSERT ... VALUES (?)` it emits `INSERT ... VALUES (encrypt_text(?))`. Critically, this applies to **every** Hibernate-generated query — including JPA Criteria queries used for filtering — so a `LIKE '%anıl%'` on `firstname` becomes a `LIKE` on the *decrypted* value, transparently.

The entity declaration is the whole contract:

```kotlin
@Entity
@Table(name = "users")
class User(
    @Column(name = "firstname", nullable = false, columnDefinition = "RAW(2000)")
    @ColumnTransformer(
        read  = "decrypt_text(firstname)",
        write = "encrypt_text(?)"
    )
    var firstname: String,

    @Column(name = "lastname", nullable = false, columnDefinition = "RAW(2000)")
    @ColumnTransformer(
        read  = "decrypt_text(lastname)",
        write = "encrypt_text(?)"
    )
    var lastname: String
) : BaseDomain()
```

From this point on, the rest of the application (`UserRepository`, the `/users` controller, the JPA `Specification` that builds `LIKE` predicates) is written as if `firstname` and `lastname` were ordinary `VARCHAR` columns.

## How a request flows end-to-end

`GET /users?firstname=Anıl3&lastname=Senocak3` triggers the following:

1. **Controller** builds a JPA `Specification` containing two `LIKE` predicates against `root.get("firstname")` and `root.get("lastname")`.
2. **Hibernate** plans the query. Because of `@ColumnTransformer(read = ...)`, the projected columns and the predicate columns are rewritten to wrap the raw column in `decrypt_text(...)`. The resulting SQL looks like:
   ```sql
   SELECT decrypt_text(firstname), decrypt_text(lastname), id, created_at
   FROM   users
   WHERE  LOWER(decrypt_text(firstname)) LIKE ?
     AND  LOWER(decrypt_text(lastname))  LIKE ?
   ```
3. **Database** executes `decrypt_text` per row, compares the result to the bind parameter, returns plaintext over the wire.
4. **JPA** hydrates `User` instances with the decrypted strings; Jackson serializes them to JSON.

Inserts work in mirror image. The init block in `CryptoApplication`:

```kotlin
userRepository.save(User(firstname = "Anıl1", lastname = "Senocak1"))
```

results in:

```sql
INSERT INTO users (firstname, lastname, created_at, id)
VALUES (encrypt_text(?), encrypt_text(?), ?, ?)
```

The plaintext never lands in the column. At rest, `SELECT firstname FROM users` returns ciphertext bytes.

## `DBMS_CRYPTO` setup

`DBMS_CRYPTO` is a built-in Oracle package that exposes primitive cipher operations. Access has to be granted explicitly to the working schema:

```sql
GRANT EXECUTE ON DBMS_CRYPTO TO your_schema;
-- e.g. GRANT EXECUTE ON DBMS_CRYPTO TO SYSTEM;
```

Then define the two wrapper functions the entity expects. AES-128 in CBC mode with PKCS#5 padding is a sane symmetric default. **The 16-byte key below is for demo only** — see [Key management](#key-management) for what a real deployment needs.

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

Quick sanity check at the SQL prompt:

```sql
SELECT encrypt_text('hello') FROM dual; -- → EBB7C703E675DB3DA397038B4C17823C
SELECT decrypt_text('EBB7C703E675DB3DA397038B4C17823C') FROM dual; -- → hello
```

The column type is `RAW(2000)` (declared via `columnDefinition` on the entity) because `DBMS_CRYPTO.ENCRYPT` returns `RAW` and the ciphertext is binary, not text. `2000` is the maximum inline `RAW` length in Oracle; for larger payloads, switch to `BLOB` and adjust the function signatures to `BLOB` in/out.

### Cipher choice cheat sheet

`DBMS_CRYPTO.ENCRYPT` takes a `typ` argument that is the bitwise sum of three constants — algorithm + chaining mode + padding. The combination above is:

| Part     | Constant        | Meaning                                                               |
|----------|-----------------|-----------------------------------------------------------------------|
| Algorithm| `ENCRYPT_AES128`| AES with a 16-byte key. `ENCRYPT_AES192` / `ENCRYPT_AES256` if longer.|
| Chaining | `CHAIN_CBC`     | CBC mode. The IV defaults to all zeros — see *Key management* below.  |
| Padding  | `PAD_PKCS5`     | PKCS#5/7 padding so arbitrary-length plaintexts encrypt cleanly.      |

## Key management

The 16-byte literal in `encrypt_text` (`'1234567890123456'`) is a **placeholder for the demo**. For anything real:

- Keys should not live in `CREATE FUNCTION` source. Use Oracle Wallet / Key Vault, or fetch from a secret manager at session start and stash in a context variable that the functions read from.
- AES-128 CBC with a static key *and* a static IV (the default-all-zeros IV used here, since no `iv` argument is passed) produces **deterministic ciphertext** — the same plaintext encrypts to the same bytes — which leaks equality and enables frequency analysis. If equality search isn't a requirement, pass a random IV per encryption and store it alongside the ciphertext, or switch to `ENCRYPT_AES_GCM` for authenticated encryption.
- Rotate keys by re-encrypting columns with a versioned key tag — keep the version byte in the stored ciphertext so `decrypt_text` can dispatch to the right key.

## What the integration test verifies

`CryptoApplicationTests` is a `@SpringBootTest` that drives the live app against a real database and asserts two properties:

**1. Round-trip correctness through JPA.** Save three `User` rows, read them back via `userRepository.findAll()`, confirm the strings come back identical to what was written.

**2. Ciphertext at rest.** Bypass Hibernate, issue raw JDBC against the `users` table, and confirm that the bytes physically stored in the `firstname`/`lastname` columns are **not equal to** the bytes of the plaintext and are **longer** than the plaintext (because of the cipher block padding). This is the check that proves the encryption is real, rather than a no-op stub.

A third test exercises the Criteria-based `/users?firstname=...&lastname=...` filter end-to-end, including case-insensitive matching on the *decrypted* values, proving the `read = "decrypt_text(...)"` rewrite kicks in for Hibernate-built predicates and not just for fetched columns.

## Running locally

- **Start Oracle Free** (one-time): `docker compose up -d`. Listens on `localhost:1522`, service `FREEPDB1`, `system` / `testpassword`. See the comments inside `docker-compose.yml` for the in-container steps to set the password and create a working schema if you don't want to use `SYSTEM`.
```yaml
version: '3.7'
services:
  oracle-free2:
    image: container-registry.oracle.com/database/free:23.9.0.0
    restart: unless-stopped
    ports:
      - "1522:1521"
    environment:
      - ORACLE_PWD=testpassword
```
- Connect oracle as sys dba and run:
```db
jdbc:oracle:thin:sys/testpassword@//localhost:1522/FREEPDB1?internal_logon=sysdba
```
then execute this to grant the crypto permissions to the SYSTEM user (or your chosen schema):
```sql
GRANT EXECUTE ON DBMS_CRYPTO TO SYSTEM;
```
- **Create the crypto functions** (one-time): run the `CREATE OR REPLACE FUNCTION` blocks from the *`DBMS_CRYPTO` setup* section above in the same schema that your app connects to (e.g. `SYSTEM`). These only need to be created once per database, not per app run.
- **Create the crypto functions** in your target schema (the SQL block under *`DBMS_CRYPTO` setup* above). The entity's `@ColumnTransformer` calls these by unqualified name, so they must be reachable from the connecting user's default search path.
-  **Run the app**: `./gradlew bootRun`. `ddl-auto=create-drop` will (re)create the `users` table with `firstname`/`lastname` as `RAW(2000)`. `ApplicationReadyEvent` seeds three rows. Server binds on `:8082`.
-  **Hit the endpoint**: `GET http://localhost:8082/users?firstname=Anıl3&lastname=Senocak3` (see `src/main/resources/requests.http`).

Override datasource defaults with the `ORACLE_URL` / `ORACLE_USERNAME` / `ORACLE_PASSWORD` env vars.

## Caveats and tradeoffs

- **Indexes on encrypted columns are useless** unless you also store a deterministic blind index (e.g. HMAC of the lowercased plaintext) in a sibling column and query against that. The current setup forces a full-table decrypt for every `LIKE` — fine for the demo, not fine at scale.
- **CPU cost is per-row**. Every selected row incurs a `DBMS_CRYPTO.DECRYPT` call. Watch query plans on hot tables; a function-based index on `decrypt_text(col)` would defeat the whole purpose of encrypting at rest.
- **`ddl-auto=create-drop`** in `application.yml` is convenient for a demo but obviously not what you want in production — switch to `validate` and manage schema with explicit migrations (Flyway / Liquibase). The `encrypt_text` / `decrypt_text` functions must be deployed via the same migration tooling, ahead of any column DDL that references them.
- **The `RAW(2000)` ceiling** means plaintexts whose ciphertext would exceed ~2000 bytes need a `BLOB` column and the corresponding `BLOB`-returning function signatures.
- **`NULL` handling**: the wrappers above treat `NULL` plaintext the same as Oracle's `NULL` arithmetic — `encrypt_text(NULL)` returns `NULL` (no row encrypted), and `decrypt_text(NULL)` returns `NULL`. The `nullable = false` on the JPA columns is the layer that actually enforces non-null.
