package com.sschakraborty.poc.crypto.core.hash.hmac;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class HMACSHA384Transformation extends AbstractHMACSHATransformation {
    private static final String HASH_NAME = "HmacSHA384";

    public HMACSHA384Transformation(Provider provider, byte[] secretKey) throws CryptoException {
        super(HASH_NAME, provider, secretKey);
    }
}