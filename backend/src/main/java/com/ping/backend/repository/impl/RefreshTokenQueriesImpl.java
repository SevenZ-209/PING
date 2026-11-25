package com.ping.backend.repository.impl;

import com.ping.backend.entity.RefreshToken;
import com.ping.backend.repository.RefreshTokenQueries;
import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.springframework.stereotype.Repository;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Repository
public class RefreshTokenQueriesImpl
        implements RefreshTokenQueries {

    private final EntityManager entityManager;

    public RefreshTokenQueriesImpl(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Optional<UUID> findSessionIdByTokenHash(String tokenHash) {
        Objects.requireNonNull(tokenHash, "tokenHash is required");

        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        CriteriaQuery<UUID> query =
                cb.createQuery(UUID.class);

        Root<RefreshToken> token =
                query.from(RefreshToken.class);

        query.select(token.<UUID>get("sessionId"))
                .where(cb.equal(token.get("tokenHash"), tokenHash));

        return Optional.ofNullable(
                entityManager.createQuery(query)
                        .getSingleResultOrNull()
        );
    }

    @Override
    public Optional<RefreshToken> findByTokenHash(String tokenHash) {
        Objects.requireNonNull(tokenHash, "tokenHash is required");

        CriteriaBuilder cb = entityManager.getCriteriaBuilder();

        CriteriaQuery<RefreshToken> query =
                cb.createQuery(RefreshToken.class);

        Root<RefreshToken> token =
                query.from(RefreshToken.class);

        query.select(token)
                .where(cb.equal(token.get("tokenHash"), tokenHash));

        return Optional.ofNullable(
                entityManager.createQuery(query)
                        .getSingleResultOrNull()
        );
    }
}