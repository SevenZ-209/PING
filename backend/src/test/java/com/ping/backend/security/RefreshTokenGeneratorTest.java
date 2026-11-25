package com.ping.backend.security;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenGeneratorTest {

    private final RefreshTokenGenerator generator =
            new RefreshTokenGenerator();


    @Test
    void generate_returnsNonNullToken() {
        String token = generator.generate();

        assertThat(token).isNotNull();
    }

    @Test
    void generate_returnsTokenWithExpectedLength() {
        String token = generator.generate();

        assertThat(token).hasSize(43);
    }

    @Test
    void generate_returnsOnlyBase64UrlCharacters() {
        String token = generator.generate();

        assertThat(token).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void generate_decodesToExpectedByteLength() {
        String token = generator.generate();

        byte[] decoded = Base64.getUrlDecoder().decode(token);

        assertThat(decoded).hasSize(32);
    }

    @Test
    void generate_returnsCanonicalBase64UrlToken() {
        String token = generator.generate();

        byte[] decoded = Base64.getUrlDecoder().decode(token);

        String encoded = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(decoded);

        assertThat(encoded).isEqualTo(token);
    }

    @Test
    void generate_multipleInvocations_returnsDistinctTokens() {
        Set<String> tokens = new HashSet<>();

        for (int i = 0; i < 1000; i++) {
            tokens.add(generator.generate());
        }

        assertThat(tokens).hasSize(1000);
    }


    @Test
    void hash_knownInput_returnsExpectedSha256() {
        String hash = generator.hash("abc");

        assertThat(hash).isEqualTo(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    @Test
    void hash_returnsExpectedLength() {
        String hash = generator.hash("test-token");

        assertThat(hash).hasSize(64);
    }

    @Test
    void hash_returnsLowercaseHex() {
        String hash = generator.hash("test-token");

        assertThat(hash).matches("[0-9a-f]{64}");
    }

    @Test
    void hash_sameInput_returnsSameHash() {
        String first = generator.hash("test-token");
        String second = generator.hash("test-token");

        assertThat(first).isEqualTo(second);
    }

    @Test
    void hash_differentInputs_returnDifferentHashes() {
        String first = generator.hash("token-one");
        String second = generator.hash("token-two");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void hash_isCaseSensitive() {
        String first = generator.hash("Token");
        String second = generator.hash("token");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void hash_doesNotTrimInput() {
        String first = generator.hash(" token ");
        String second = generator.hash("token");

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void hash_nullInput_throwsNullPointerException() {
        assertThatThrownBy(() -> generator.hash(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("rawToken is required");
    }


    @Test
    void generateAndHash_concurrentInvocations_areThreadSafe() throws Exception {
        int threadCount = 8;
        int tokensPerThread = 100;

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch start = new CountDownLatch(1);

        try {
            List<Future<Set<String>>> futures = new ArrayList<>();

            for (int i = 0; i < threadCount; i++) {
                futures.add(executor.submit(() -> {
                    start.await();

                    Set<String> tokens = new HashSet<>();

                    for (int j = 0; j < tokensPerThread; j++) {
                        String token = generator.generate();
                        String hash = generator.hash(token);

                        assertThat(token).hasSize(43);
                        assertThat(hash).matches("[0-9a-f]{64}");
                        assertThat(generator.hash(token)).isEqualTo(hash);

                        tokens.add(token);
                    }

                    return tokens;
                }));
            }

            start.countDown();

            Set<String> allTokens = new HashSet<>();

            for (Future<Set<String>> future : futures) {
                allTokens.addAll(future.get(30, TimeUnit.SECONDS));
            }

            assertThat(allTokens).hasSize(threadCount * tokensPerThread);
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }


}