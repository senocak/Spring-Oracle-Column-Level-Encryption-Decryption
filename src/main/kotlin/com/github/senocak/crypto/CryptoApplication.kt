package com.github.senocak.crypto

import jakarta.persistence.criteria.CriteriaBuilder
import jakarta.persistence.criteria.CriteriaQuery
import jakarta.persistence.criteria.Predicate
import jakarta.persistence.criteria.Root
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.boot.runApplication
import org.springframework.context.event.EventListener
import org.springframework.data.jpa.domain.Specification
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

fun main(args: Array<String>) {
    runApplication<PgcryptoApplication>(*args)
}

@SpringBootApplication
@RestController
class PgcryptoApplication(
    private val userRepository: UserRepository
) {
    @EventListener(value = [ApplicationReadyEvent::class])
    fun init(event: ApplicationReadyEvent) {
        userRepository.deleteAll()
        userRepository.save(User(firstname = "Anıl1", lastname = "Senocak1"))
        userRepository.save(User(firstname = "Anıl2", lastname = "Senocak2"))
        userRepository.save(User(firstname = "Anıl3", lastname = "Senocak3"))
    }

    @GetMapping(value = ["/users"])
    fun getAllUsers(@RequestParam firstname: String?, @RequestParam lastname: String?): MutableList<User> {
        val specification = Specification { root: Root<User>, query: CriteriaQuery<*>, builder: CriteriaBuilder ->
            val predicates: MutableList<Predicate> = ArrayList()
            if (!firstname.isNullOrEmpty()) {
                predicates.add(builder.like(builder.lower(root.get("firstname")), "%${firstname.lowercase()}%"))
            }
            if (!lastname.isNullOrEmpty()) {
                predicates.add(builder.like(builder.lower(root.get("lastname")), "%${lastname.lowercase()}%"))
            }
            query.where(*predicates.toTypedArray()).distinct(true).restriction
        }
        return userRepository.findAll(specification)
    }
}


//    @Bean
//    public SecurityFilterChain configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.
//                jdbcAuthentication()
//                .usersByUsernameQuery("select email as principal, password as credentials, true from user where email=?")
//                .authoritiesByUsernameQuery("select u.email as principal, r.role as role from user u inner join user_role ur on(u.user_id=ur.user_id) inner join role r on(ur.role_id=r.role_id) where u.email=?")
//                .dataSource(dataSource)
//                .passwordEncoder(bCryptPasswordEncoder)
//                .rolePrefix("ROLE_");
//    }