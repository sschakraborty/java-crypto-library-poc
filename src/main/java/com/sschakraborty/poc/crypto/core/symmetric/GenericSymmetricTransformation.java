package com.sschakraborty.poc.crypto.core.symmetric;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public class GenericSymmetricTransformation extends AbstractSymmetricTransformation {
    public GenericSymmetricTransformation(String cipherName, String algorithmName, Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(cipherName, algorithmName, provider, symmetricKey, initializationVector);
    }
}