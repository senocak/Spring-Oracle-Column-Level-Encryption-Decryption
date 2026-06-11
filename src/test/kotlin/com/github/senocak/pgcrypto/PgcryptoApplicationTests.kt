package com.github.senocak.pgcrypto

import java.sql.ResultSet
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.postgresql.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
class PgcryptoApplicationTests {
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
        assertThat(encryptedLastnames).allSatisfy { row ->
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
                    pgp_sym_decrypt($columnName, 'pswd') as decrypted,
                    encode($columnName, 'hex') as encrypted_hex,
                    encode(convert_to(pgp_sym_decrypt($columnName, 'pswd'), 'UTF8'), 'hex') as plain_text_hex
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
        val postgres: PostgreSQLContainer = PostgreSQLContainer("postgres:14").apply {
            withDatabaseName("pgcrypto")
            withUsername("postgres")
            withPassword("postgres")
            withInitScript("init-pgcrypto.sql")
        }

        @JvmStatic
        @DynamicPropertySource
        fun postgresProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("spring.jpa.hibernate.ddl-auto") { "create" }
        }
    }
}
