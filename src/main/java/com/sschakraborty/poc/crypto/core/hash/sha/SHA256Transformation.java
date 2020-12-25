package com.sschakraborty.poc.crypto.core.hash.sha;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class SHA256Transformation extends AbstractSHATransformation {
    private static final String HASH_NAME = "SHA-256";

    public SHA256Transformation(Provider provider, byte[] secretKey) throws CryptoException {
        super(HASH_NAME, provider, secretKey);
    }
}