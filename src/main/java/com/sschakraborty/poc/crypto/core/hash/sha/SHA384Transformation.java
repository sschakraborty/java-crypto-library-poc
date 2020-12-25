package com.sschakraborty.poc.crypto.core.hash.sha;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class SHA384Transformation extends AbstractSHATransformation {
    private static final String HASH_NAME = "SHA-384";

    public SHA384Transformation(Provider provider, byte[] secretKey) throws CryptoException {
        super(HASH_NAME, provider, secretKey);
    }
}