package com.sschakraborty.poc.crypto.core.hash.hmac;

import com.sschakraborty.poc.crypto.core.hash.AbstractHashingTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Base64;

public abstract class AbstractHMACSHATransformation extends AbstractHashingTransformation {
    private final Mac hsMac;

    public AbstractHMACSHATransformation(String hashName, Provider provider, byte[] secretKey) throws CryptoException {
        super(provider);
        try {
            hsMac = Mac.getInstance(hashName, provider);
            hsMac.init(new SecretKeySpec(secretKey, hashName));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
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
        final byte[] hashedBytes = hsMac.doFinal(plainBytes);
        return Base64.getEncoder().withoutPadding().encode(hashedBytes);
    }
}