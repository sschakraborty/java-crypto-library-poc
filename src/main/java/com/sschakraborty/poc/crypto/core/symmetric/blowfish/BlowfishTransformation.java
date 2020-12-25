package com.sschakraborty.poc.crypto.core.symmetric.blowfish;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class BlowfishTransformation extends AbstractBlowfishTransformation {
    private static final String OPERATION_MODE = "CBC";
    private static final String PADDING_TYPE = "PKCS5Padding";

    public BlowfishTransformation(Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(OPERATION_MODE, PADDING_TYPE, provider, symmetricKey, initializationVector);
    }
}