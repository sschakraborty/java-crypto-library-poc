package com.sschakraborty.poc.crypto.core.hash;

import com.sschakraborty.poc.crypto.core.Transformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;
import java.security.Security;

public abstract class AbstractHashingTransformation implements Transformation {
    public AbstractHashingTransformation(Provider provider) {
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
    }

    @Override
    public byte[] encrypt(byte[] plainBytes) throws CryptoException {
        throw new CryptoException("Encrypt operation not supported with hashing digest mechanism!");
    }

    @Override
    public byte[] decrypt(byte[] cipherBytes) throws CryptoException {
        throw new CryptoException("Decrypt operation not supported with hashing digest mechanism!");
    }
}