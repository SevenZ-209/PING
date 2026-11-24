
package com.ping.backend.repository.impl;

import com.ping.backend.entity.EmailVerificationToken;
import com.ping.backend.repository.EmailVerificationTokenQueries;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.springframework.stereotype.Repository;
import java.util.UUID;
import java.util.Optional;

@Repository
public class EmailVerificationTokenQueriesImpl
        implements EmailVerificationTokenQueries {

    private final EntityManager entityManager;

    public EmailVerificationTokenQueriesImpl(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<EmailVerificationToken> findByTokenHashForUpdate(
            String tokenHash
    ) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        CriteriaQuery<EmailVerificationToken> query =
                cb.createQuery(EmailVerificationToken.class);

        Root<EmailVerificationToken> token =
                query.from(EmailVerificationToken.class);

        query.select(token)
                .where(cb.equal(token.get("tokenHash"), tokenHash));

        return entityManager.createQuery(query)
                .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                .getResultStream()
                .findFirst();
    }


    @Override
    public Optional<UUID> findUserIdByTokenHash(String tokenHash) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        CriteriaQuery<UUID> query =
                cb.createQuery(UUID.class);

        Root<EmailVerificationToken> token =
                query.from(EmailVerificationToken.class);

        query.select(token.<UUID>get("userId"))
                .where(cb.equal(token.get("tokenHash"), tokenHash));

        return entityManager.createQuery(query)
                .getResultList()
                .stream()
                .findFirst();
    }

}
