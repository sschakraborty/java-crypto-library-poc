package com.sschakraborty.poc.crypto.core.symmetric.des;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class DESTransformation extends AbstractSymmetricDESTransformation {
    private static final String DES_ALGORITHM_NAME = "DES";
    private static final String OPERATION_MODE = "CBC";
    private static final String PADDING_TYPE = "PKCS5Padding";

    public DESTransformation(Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(DES_ALGORITHM_NAME, OPERATION_MODE, PADDING_TYPE, provider, symmetricKey, initializationVector);
    }
}