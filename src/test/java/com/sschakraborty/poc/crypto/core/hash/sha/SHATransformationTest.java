package com.sschakraborty.poc.crypto.core.hash.sha;

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

public class SHATransformationTest {
    private final SecureRandom secureRandom = new SecureRandom();

    @Test
    public void testSHA256() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        final Transformation transformation = new SHA256Transformation(provider, getRandomKey(125));
        for (String payload : payloads) {
            final String hashedOne = transformation.hash(payload, StandardCharsets.UTF_8);
            final String hashedTwo = transformation.hash(payload, StandardCharsets.UTF_8);
            assertEquals(hashedOne, hashedTwo);
        }
    }

    @Test
    public void testSHA384() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        final Transformation transformation = new SHA384Transformation(provider, getRandomKey(128));
        for (String payload : payloads) {
            final String hashedOne = transformation.hash(payload, StandardCharsets.UTF_8);
            final String hashedTwo = transformation.hash(payload, StandardCharsets.UTF_8);
            assertEquals(hashedOne, hashedTwo);
        }
    }

    @Test
    public void testSHA512() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final List<String> payloads = createPayloads(2000);
        final Transformation transformation = new SHA512Transformation(provider, getRandomKey(64));
        for (String payload : payloads) {
            final String hashedOne = transformation.hash(payload, StandardCharsets.UTF_8);
            final String hashedTwo = transformation.hash(payload, StandardCharsets.UTF_8);
            assertEquals(hashedOne, hashedTwo);
        }
    }

    @Test
    public void testSHA512Random() throws CryptoException {
        final Provider provider = new BouncyCastleProvider();
        final String randomString = createRandomString(400);
        for (int i = 1; i < 500; i++) {
            final Transformation transformation = new SHA512Transformation(provider, getRandomKey(i));
            final String hashedOne = transformation.hash(randomString, StandardCharsets.UTF_8);
            final String hashedTwo = transformation.hash(randomString, StandardCharsets.UTF_8);
            assertEquals(hashedOne, hashedTwo);
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