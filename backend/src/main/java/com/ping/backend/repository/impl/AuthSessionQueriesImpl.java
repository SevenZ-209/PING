package com.ping.backend.repository.impl;

import com.ping.backend.entity.AuthSession;
import com.ping.backend.repository.AuthSessionQueries;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.springframework.stereotype.Repository;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Repository
public class AuthSessionQueriesImpl
        implements AuthSessionQueries {

    private final EntityManager entityManager;

    public AuthSessionQueriesImpl(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<AuthSession> findByIdForUpdate(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId is required");

        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        CriteriaQuery<AuthSession> query =
                cb.createQuery(AuthSession.class);

        Root<AuthSession> session =
                query.from(AuthSession.class);

        query.select(session)
                .where(cb.equal(session.get("id"), sessionId));

        return Optional.ofNullable(
                entityManager.createQuery(query)
                        .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                        .getSingleResultOrNull()
        );
    }
}