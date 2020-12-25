package com.sschakraborty.poc.crypto.core.symmetric.aes;

import com.sschakraborty.poc.crypto.core.symmetric.AbstractSymmetricTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public abstract class AbstractSymmetricAESTransformation extends AbstractSymmetricTransformation {
    private static final String AES_ALGORITHM_NAME = "AES";

    public AbstractSymmetricAESTransformation(String operationMode, String paddingType, Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(AES_ALGORITHM_NAME + "/" + operationMode + "/" + paddingType, AES_ALGORITHM_NAME, provider, symmetricKey, initializationVector);
    }
}