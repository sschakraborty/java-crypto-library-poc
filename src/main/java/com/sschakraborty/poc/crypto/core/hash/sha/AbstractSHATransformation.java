package com.sschakraborty.poc.crypto.core.hash.sha;

import com.sschakraborty.poc.crypto.core.hash.AbstractHashingTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Base64;

public abstract class AbstractSHATransformation extends AbstractHashingTransformation {
    private final byte[] saltKey;
    private final MessageDigest messageDigest;

    public AbstractSHATransformation(String hashName, Provider provider, byte[] secretKey) throws CryptoException {
        super(provider);
        try {
            messageDigest = MessageDigest.getInstance(hashName, provider);
            saltKey = secretKey;
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    e, "Could not instantiate digest mechanism with", hashName, "hash name and", provider.getName(), "provider!"
            );
        }
    }

    @Override
    public byte[] hash(byte[] plainBytes) throws CryptoException {
        if (plainBytes == null) {
            throw new CryptoException("Payload cannot be null!");
        }
        byte[] digest;
        synchronized (messageDigest) {
            messageDigest.reset();
            digest = messageDigest.digest(scramble(plainBytes, saltKey));
        }
        return Base64.getEncoder().withoutPadding().encode(digest);
    }

    private byte[] scramble(byte[] plainBytes, byte[] saltKey) {
        final int pbl = plainBytes.length;
        final int skl = saltKey.length;
        final int totalLength = pbl + (pbl / skl) * skl + (pbl % skl);
        final byte[] result = new byte[totalLength];
        int masterIndex = 0;
        int saltIndex = 0;
        for (byte aByte : plainBytes) {
            result[masterIndex++] = aByte;
            result[masterIndex++] = saltKey[saltIndex++];
            saltIndex = saltIndex % skl;
        }
        return result;
    }
}