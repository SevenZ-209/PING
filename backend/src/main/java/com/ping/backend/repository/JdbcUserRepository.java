
package com.ping.backend.user;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

@Repository
public class JdbcUserRepository implements UserRepository {

    private final JdbcClient jdbcClient;

    public JdbcUserRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }


    @Override
    public Optional<User> findByEmail(String email) {
        String sql = """
            SELECT id, email, password_hash, display_name,
                   created_at, updated_at, email_verified_at
            FROM users
            WHERE email = :email
            """;

        return jdbcClient.sql(sql)
                .param("email", email)
                .query((rs, rowNum) -> new User(
                        rs.getObject("id", java.util.UUID.class),
                        rs.getString("email"),
                        rs.getString("password_hash"),
                        rs.getString("display_name"),
                        rs.getTimestamp("created_at").toInstant(),
                        rs.getTimestamp("updated_at").toInstant(),
                        rs.getTimestamp("email_verified_at") == null
                                ? null
                                : rs.getTimestamp("email_verified_at").toInstant()
                ))
                .optional();
    }


    @Override
    public void save(User user) {
        String sql = """
            INSERT INTO users (
                id,
                email,
                password_hash,
                display_name,
                created_at,
                updated_at,
                email_verified_at
            )
            VALUES (
                :id,
                :email,
                :passwordHash,
                :displayName,
                :createdAt,
                :updatedAt,
                :emailVerifiedAt
            )
            """;

        jdbcClient.sql(sql)
                .param("id", user.getId())
                .param("email", user.getEmail())
                .param("passwordHash", user.getPasswordHash())
                .param("displayName", user.getDisplayName())
                .param("createdAt",
                        user.getCreatedAt().atOffset(ZoneOffset.UTC))
                .param("updatedAt",
                        user.getUpdatedAt().atOffset(ZoneOffset.UTC))
                .param("emailVerifiedAt",
                        user.getEmailVerifiedAt() == null
                                ? null
                                : user.getEmailVerifiedAt().atOffset(ZoneOffset.UTC)).update();
    }

}
