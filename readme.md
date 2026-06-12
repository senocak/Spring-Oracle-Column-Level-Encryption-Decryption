# Spring Kotlin — Column-Level Encryption / Decryption with Oracle `DBMS_CRYPTO`

Most "the database is encrypted" stories stop at **Transparent Data Encryption (TDE)** — the datafiles, redo logs, and backups are encrypted on disk, so an attacker who steals the raw `.dbf` files or a tape backup gets ciphertext. That's necessary but not sufficient. Once anyone — a DBA, an analyst with read-only access, an attacker who phished a service account, an unauthorized tool that landed a `SELECT *` query — opens a *connection* to the database, TDE has already decrypted everything for them. The whole "encryption" boundary lives at the storage layer, not at the column.

For regulated data (national-ID numbers, phone numbers, addresses under KVKK/GDPR; cardholder data under PCI-DSS; PHI under HIPAA), this gap matters: a leak through a legitimate DB connection is the most common breach path, not raw disk theft. The mitigation is **column-level encryption** — the bytes physically stored in the `firstname` / `lastname` columns are ciphertext, and decryption only happens when the right key is presented. A DBA running `SELECT firstname FROM users` sees `HEXTORAW('A8C1...')`, not `Anıl`.

The naive way to do this is to encrypt in the *application* — call a `crypto.encrypt(...)` helper before every `repository.save()` and a `crypto.decrypt(...)` after every `findBy*()`. This works for trivial CRUD but falls apart fast:

- **Every query path has to remember.** Native queries, reporting jobs, batch importers, JdbcTemplate one-offs, raw `EntityManager.createQuery` calls — each one is an opportunity to forget the wrapper and either store plaintext or read ciphertext as garbage.
- **`WHERE` / `LIKE` / `ORDER BY` break.** The database can only compare what it can see. If the column is ciphertext, a `LIKE '%anıl%'` predicate matches nothing — you either have to pull every row to the app and filter in memory, or build an awkward "encrypt the search term and compare ciphertext" path that only works for exact equality with a deterministic cipher.
- **Migrations and ad-hoc fixes hurt.** Anyone running a Flyway script or a one-off `UPDATE` has to know the encryption convention and apply it manually.
- **The leak surface is wide.** Every Kotlin call site, every test fixture, every seed data loader has to be reviewed. Miss one, and that column ends up half-encrypted forever.

**What this project solves:** the encryption boundary is pushed *down* into the database — into a pair of SQL functions (`encrypt_text` / `decrypt_text`) that are the only point at which plaintext and ciphertext meet. Hibernate's `@ColumnTransformer` then makes the application **physically unable** to bypass them: every query Hibernate generates — including JPA Criteria predicates used for `LIKE` filtering — is rewritten at the ORM level to call those functions. Application code reads and writes Kotlin `String` values exactly as if the column were unencrypted; `WHERE firstname LIKE '%anıl%'` works against the *decrypted* value because the SQL Hibernate sends is `WHERE LOWER(decrypt_text(firstname)) LIKE ?`. Backups, exports, replicas, and `SELECT *` from a DBA's IDE all see ciphertext. The only way to read plaintext is to be a session that holds the key, and the key never appears in application code at all.

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
   ```oracle-sql
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
```oracle-sql
GRANT EXECUTE ON DBMS_CRYPTO TO SYSTEM;
```
- Connect as `SYSTEM` (or your chosen schema) and test it:
```db
jdbc:oracle:thin:system/testpassword@//localhost:1522/FREEPDB1
```
```oracle-sql
SELECT encrypt_text('hello') FROM dual; -- → EBB7C703E675DB3DA397038B4C17823C
SELECT decrypt_text('EBB7C703E675DB3DA397038B4C17823C') FROM dual; -- → hello
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
