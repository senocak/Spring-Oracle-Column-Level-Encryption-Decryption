package com.github.senocak.pgcrypto

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.MappedSuperclass
import jakarta.persistence.Table
import java.io.Serializable
import java.util.Date
import org.hibernate.annotations.ColumnTransformer
import org.hibernate.annotations.UuidGenerator
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor

@MappedSuperclass
class BaseDomain(
    @Id
    @UuidGenerator(style = UuidGenerator.Style.RANDOM)
    @Column(name = "id", updatable = false, nullable = false)
    var id: String? = null,

    @Column(name = "created_at")
    var createdAt: Date = Date()
) : Serializable

@Entity
@Table(name = "users")
class User(
    @Column(name = "firstname", nullable = false, columnDefinition = "RAW(2000)")
    @ColumnTransformer(
        read = "decrypt_text(firstname)",
        write = "encrypt_text(?)"
    )
    var firstname: String,

    @Column(name = "lastname", nullable = false, columnDefinition = "RAW(2000)")
    @ColumnTransformer(
        read = "decrypt_text(lastname)",
        write = "encrypt_text(?)"
    )
    var lastname: String
) : BaseDomain()

interface UserRepository: JpaRepository<User, String>, JpaSpecificationExecutor<User>