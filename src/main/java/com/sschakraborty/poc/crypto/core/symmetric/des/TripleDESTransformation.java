package com.sschakraborty.poc.crypto.core.symmetric.des;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class TripleDESTransformation extends AbstractSymmetricDESTransformation {
    private static final String TRIPLE_DES_ALGORITHM_NAME = "DESede";
    private static final String OPERATION_MODE = "CBC";
    private static final String PADDING_TYPE = "PKCS5Padding";

    public TripleDESTransformation(Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(TRIPLE_DES_ALGORITHM_NAME, OPERATION_MODE, PADDING_TYPE, provider, symmetricKey, initializationVector);
    }
}