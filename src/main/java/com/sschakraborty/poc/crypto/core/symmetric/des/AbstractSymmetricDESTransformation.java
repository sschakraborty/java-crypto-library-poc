package com.sschakraborty.poc.crypto.core.symmetric.des;

import com.sschakraborty.poc.crypto.core.symmetric.AbstractSymmetricTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public abstract class AbstractSymmetricDESTransformation extends AbstractSymmetricTransformation {
    public AbstractSymmetricDESTransformation(String algorithmName, String operationMode, String paddingType, Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(algorithmName + "/" + operationMode + "/" + paddingType, algorithmName, provider, symmetricKey, initializationVector);
    }
}