package com.sschakraborty.poc.crypto.core.hash;

import com.sschakraborty.poc.crypto.core.Transformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class HashingTransformationFactoryTest {
    private final SecureRandom secureRandom = new SecureRandom();
    private final HashingTransformationFactory factory = new HashingTransformationFactory();

    @Test
    public void testHashing() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        for (HashingTransformationFactory.Algorithm algorithm : HashingTransformationFactory.Algorithm.values()) {
            final Transformation transformation = factory.create(algorithm, provider, getRandomKey(200));
            for (String payload : payloads) {
                final String hashed = transformation.hash(payload, StandardCharsets.UTF_8);
                for (int i = 0; i < 5; i++) {
                    assertEquals(hashed, transformation.hash(payload, StandardCharsets.UTF_8));
                }
            }
        }
    }

    private List<String> createPayloads(int size) {
        List<String> payloads = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            payloads.add(createRandomString(i));
        }
        return payloads;
    }

    private String createRandomString(int i) {
        Random random = new Random();
        byte[] bytes = new byte[i];
        random.nextBytes(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] getRandomKey(int length) {
        final byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}