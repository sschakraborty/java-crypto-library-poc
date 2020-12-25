package com.sschakraborty.poc.crypto.core.symmetric.blowfish;

import com.sschakraborty.poc.crypto.core.symmetric.AbstractSymmetricTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.security.Provider;

public abstract class AbstractBlowfishTransformation extends AbstractSymmetricTransformation {
    private static final String BLOWFISH_ALGORITHM_NAME = "Blowfish";

    public AbstractBlowfishTransformation(String operationMode, String paddingType, Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        super(BLOWFISH_ALGORITHM_NAME + "/" + operationMode + "/" + paddingType, BLOWFISH_ALGORITHM_NAME, provider, symmetricKey, initializationVector);
    }
}