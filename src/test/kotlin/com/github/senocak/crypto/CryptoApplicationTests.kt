package com.github.senocak.crypto

import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import java.sql.Statement
import java.util.Properties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.oracle.OracleContainer

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
class CryptoApplicationTests {
    @Autowired private lateinit var application: PgcryptoApplication
    @Autowired private lateinit var userRepository: UserRepository
    @Autowired private lateinit var jdbcTemplate: JdbcTemplate

    @Test
    fun `users are decrypted through JPA while raw columns stay encrypted`() {
        val users: List<User> = userRepository.findAll().sortedBy { it.firstname }

        assertThat(users.map { it.firstname }).containsExactly("Anıl1", "Anıl2", "Anıl3")
        assertThat(users.map { it.lastname }).containsExactly("Senocak1", "Senocak2", "Senocak3")

        val encryptedFirstnames: List<EncryptedColumnRow> = encryptedRows(tableName = "users", columnName = "firstname")
        assertThat(encryptedFirstnames.map { it.decrypted }).containsExactly("Anıl1", "Anıl2", "Anıl3")
        assertThat(encryptedFirstnames).allSatisfy { row: EncryptedColumnRow ->
            assertThat(row.encryptedHex).isNotEqualTo(row.plainTextHex)
            assertThat(row.encryptedHex.length).isGreaterThan(row.plainTextHex.length)
        }

        val encryptedLastnames: List<EncryptedColumnRow> = encryptedRows(tableName = "users", columnName = "lastname")
        assertThat(encryptedLastnames.map { it.decrypted }).containsExactly("Senocak1", "Senocak2", "Senocak3")
        assertThat(encryptedLastnames).allSatisfy { row: EncryptedColumnRow ->
            assertThat(row.encryptedHex).isNotEqualTo(row.plainTextHex)
            assertThat(row.encryptedHex.length).isGreaterThan(row.plainTextHex.length)
        }
    }

    @Test
    fun `user search matches encrypted firstname and lastname columns`() {
        val matchByFirstname: List<User> = application.getAllUsers(firstname = "Anıl2", lastname = null)
        val matchByLastname: List<User> = application.getAllUsers(firstname = null, lastname = "Senocak3")
        val matchByBoth: List<User> = application.getAllUsers(firstname = "anıl1", lastname = "senocak1")
        val matchEverything: List<User> = application.getAllUsers(firstname = null, lastname = null)
        val noMatch: List<User> = application.getAllUsers(firstname = "missing", lastname = null)

        assertThat(matchByFirstname.map { it.firstname }).containsExactly("Anıl2")
        assertThat(matchByLastname.map { it.lastname }).containsExactly("Senocak3")
        assertThat(matchByBoth.map { it.firstname }).containsExactly("Anıl1")
        assertThat(matchEverything.map { it.firstname }).containsExactlyInAnyOrder("Anıl1", "Anıl2", "Anıl3")
        assertThat(noMatch).isEmpty()
    }

    private fun encryptedRows(tableName: String, columnName: String): List<EncryptedColumnRow> =
        jdbcTemplate.query(
            """
                select
                    decrypt_text($columnName) as decrypted,
                    rawtohex($columnName) as encrypted_hex,
                    rawtohex(utl_raw.cast_to_raw(decrypt_text($columnName))) as plain_text_hex
                from $tableName
                order by decrypted
            """.trimIndent()
        ) { rs: ResultSet, _: Int ->
            EncryptedColumnRow(
                decrypted = rs.getString("decrypted"),
                encryptedHex = rs.getString("encrypted_hex"),
                plainTextHex = rs.getString("plain_text_hex")
            )
        }

    private data class EncryptedColumnRow(
        val decrypted: String,
        val encryptedHex: String,
        val plainTextHex: String
    )

    companion object {
        @Container
        @JvmField
        val oracle: OracleContainer = OracleContainer("gvenzl/oracle-free:23-slim-faststart")
            .withUsername("test")
            .withPassword("test")

        @JvmStatic
        @DynamicPropertySource
        fun oracleProperties(registry: DynamicPropertyRegistry) {
            bootstrapCrypto()
            registry.add("spring.datasource.url", oracle::getJdbcUrl)
            registry.add("spring.datasource.username", oracle::getUsername)
            registry.add("spring.datasource.password", oracle::getPassword)
            registry.add("spring.jpa.hibernate.ddl-auto") { "create" }
            registry.add("spring.jpa.properties.hibernate.default_schema") { "TEST" }
        }

        // gvenzl/oracle-free sets ORACLE_PASSWORD (used by SYS/SYSTEM) to the same value
        // we passed via withPassword(...). SYSTEM in the PDB lacks visibility on
        // SYS.DBMS_CRYPTO, so we grant as SYS AS SYSDBA, then create the encrypt_text /
        // decrypt_text wrappers in the app user's own schema so the unqualified calls
        // emitted by @ColumnTransformer resolve correctly.
        private fun bootstrapCrypto() {
            val sysProps: Properties = Properties().apply {
                put("user", "sys")
                put("password", oracle.password)
                put("internal_logon", "sysdba")
            }
            DriverManager.getConnection(oracle.jdbcUrl, sysProps).use { conn: Connection ->
                conn.createStatement().use { stmt: Statement ->
                    stmt.execute("GRANT EXECUTE ON SYS.DBMS_CRYPTO TO ${oracle.username}")
                }
            }
            DriverManager.getConnection(oracle.jdbcUrl, oracle.username, oracle.password).use { conn: Connection ->
                conn.createStatement().use { stmt: Statement ->
                    stmt.execute(
                        """
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
                        """.trimIndent()
                    )
                    stmt.execute(
                        """
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
                        """.trimIndent()
                    )
                }
            }
        }
    }
}
