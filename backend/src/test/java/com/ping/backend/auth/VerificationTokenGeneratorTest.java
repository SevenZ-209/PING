
package com.ping.backend.auth;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationTokenGeneratorTest {

    private final VerificationTokenGenerator generator =
            new VerificationTokenGenerator();

    @Test
    void generate_shouldReturn64HexCharacters() {
        String token = generator.generate();

        assertThat(token)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void generate_shouldProduceDifferentTokens() {
        Set<String> tokens = new HashSet<>();

        for (int i = 0; i < 100; i++) {
            tokens.add(generator.generate());
        }

        assertThat(tokens).hasSize(100);
    }

    @Test
    void hash_shouldReturn64HexCharacters() {
        String hash = generator.hash("test-token");

        assertThat(hash)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void hash_shouldBeDeterministic() {
        String first = generator.hash("same-token");
        String second = generator.hash("same-token");

        assertThat(first).isEqualTo(second);
    }

    @Test
    void hash_shouldNotExposeRawToken() {
        String token = generator.generate();
        String hash = generator.hash(token);

        assertThat(hash).isNotEqualTo(token);
    }

    @Test
    void differentTokens_shouldProduceDifferentHashes() {
        String first = generator.hash("token-one");
        String second = generator.hash("token-two");

        assertThat(first).isNotEqualTo(second);
    }
}
