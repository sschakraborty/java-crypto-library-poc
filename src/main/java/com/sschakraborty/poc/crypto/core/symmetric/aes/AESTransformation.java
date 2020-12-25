package com.sschakraborty.poc.crypto.core.symmetric.aes;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class AESTransformation extends AbstractSymmetricAESTransformation {
    private static final String OPERATION_MODE = "GCM";
    private static final String PADDING_TYPE = "NoPadding";

    public AESTransformation(Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(OPERATION_MODE, PADDING_TYPE, provider, symmetricKey, initializationVector);
    }
}