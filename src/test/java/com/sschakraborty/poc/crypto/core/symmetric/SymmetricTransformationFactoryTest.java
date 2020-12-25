package com.sschakraborty.poc.crypto.core.symmetric;

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

public class SymmetricTransformationFactoryTest {
    private final SecureRandom secureRandom = new SecureRandom();
    private final SymmetricTransformationFactory factory = new SymmetricTransformationFactory();

    @Test
    public void createPredefined() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        for (SymmetricTransformationFactory.Algorithm algorithm : SymmetricTransformationFactory.Algorithm.values()) {
            final Transformation transformation = factory.create(algorithm, provider, getRandomKey(algorithm), new byte[8]);
            for (String payload : payloads) {
                final String encrypted = transformation.encrypt(payload, StandardCharsets.UTF_8);
                assertEquals(payload, transformation.decrypt(encrypted, StandardCharsets.UTF_8));
            }
        }
    }

    @Test
    public void createGenericWithIV() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        final Transformation transformation = factory.create("AES/CBC/PKCS5Padding", "AES", provider, new byte[16], new byte[16]);
        for (String payload : payloads) {
            final String encrypted = transformation.encrypt(payload, StandardCharsets.UTF_8);
            assertEquals(payload, transformation.decrypt(encrypted, StandardCharsets.UTF_8));
        }
    }

    @Test
    public void createGenericWithoutIV() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        final Transformation transformation = factory.create("AES/ECB/PKCS5Padding", "AES", provider, new byte[16]);
        for (String payload : payloads) {
            final String encrypted = transformation.encrypt(payload, StandardCharsets.UTF_8);
            assertEquals(payload, transformation.decrypt(encrypted, StandardCharsets.UTF_8));
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

    private byte[] getRandomKey(SymmetricTransformationFactory.Algorithm algorithm) {
        int length = 16;
        if (SymmetricTransformationFactory.Algorithm.DES == algorithm)
            length = 8;
        final byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}