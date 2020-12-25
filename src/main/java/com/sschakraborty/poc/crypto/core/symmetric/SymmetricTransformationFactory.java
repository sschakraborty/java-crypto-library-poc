package com.sschakraborty.poc.crypto.core.symmetric;

import com.sschakraborty.poc.crypto.core.Transformation;
import com.sschakraborty.poc.crypto.core.symmetric.aes.AESTransformation;
import com.sschakraborty.poc.crypto.core.symmetric.blowfish.BlowfishTransformation;
import com.sschakraborty.poc.crypto.core.symmetric.des.DESTransformation;
import com.sschakraborty.poc.crypto.core.symmetric.des.TripleDESTransformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.util.Objects;

public class SymmetricTransformationFactory {
    public enum Algorithm {
        TRIPLE_DES(TripleDESTransformation.class),
        DES(DESTransformation.class),
        BLOWFISH(BlowfishTransformation.class),
        AES(AESTransformation.class);

        private final Class<? extends Transformation> clazz;

        Algorithm(Class<? extends Transformation> clazz) {
            this.clazz = clazz;
        }

        public Class<? extends Transformation> getClazz() {
            return clazz;
        }
    }

    public Transformation create(Algorithm algorithm, Provider provider, byte[] secretKey, byte[] initializationVector) throws CryptoException {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null!");
        Objects.requireNonNull(provider, "Provider cannot be null!");
        Objects.requireNonNull(secretKey, "Secret symmetric key cannot be null!");
        Objects.requireNonNull(initializationVector, "Initialization vector cannot be null!");
        try {
            final Class<? extends Transformation> clazz = algorithm.getClazz();
            final Constructor<? extends Transformation> constructor = clazz.getConstructor(Provider.class, byte[].class, byte[].class);
            return constructor.newInstance(provider, secretKey, initializationVector);
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new CryptoException(e, "Transformation", algorithm.name(), "could not be instantiated!");
        }
    }

    public Transformation create(String cipherName, String algorithmName, Provider provider, byte[] secretKey) throws CryptoException {
        return create(cipherName, algorithmName, provider, secretKey, null);
    }

    public Transformation create(String cipherName, String algorithmName, Provider provider, byte[] secretKey, byte[] initializationVector) throws CryptoException {
        Objects.requireNonNull(cipherName, "Cipher name cannot be null!");
        Objects.requireNonNull(algorithmName, "Algorithm name cannot be null!");
        Objects.requireNonNull(provider, "Provider cannot be null!");
        Objects.requireNonNull(secretKey, "Secret symmetric key cannot be null!");
        return new GenericSymmetricTransformation(cipherName, algorithmName, provider, secretKey, initializationVector);
    }
}