package com.sschakraborty.poc.crypto.core.hash;

import com.sschakraborty.poc.crypto.core.Transformation;
import com.sschakraborty.poc.crypto.core.hash.hmac.HMACSHA256Transformation;
import com.sschakraborty.poc.crypto.core.hash.hmac.HMACSHA384Transformation;
import com.sschakraborty.poc.crypto.core.hash.hmac.HMACSHA512Transformation;
import com.sschakraborty.poc.crypto.core.hash.sha.SHA256Transformation;
import com.sschakraborty.poc.crypto.core.hash.sha.SHA384Transformation;
import com.sschakraborty.poc.crypto.core.hash.sha.SHA512Transformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.util.Objects;

public class HashingTransformationFactory {
    public Transformation create(Algorithm algorithm, Provider provider, byte[] secretKey) throws CryptoException {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null!");
        Objects.requireNonNull(provider, "Provider cannot be null!");
        Objects.requireNonNull(secretKey, "Secret key cannot be null!");
        try {
            final Class<? extends Transformation> clazz = algorithm.getClazz();
            final Constructor<? extends Transformation> constructor = clazz.getConstructor(Provider.class, byte[].class);
            return constructor.newInstance(provider, secretKey);
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new CryptoException(e, "Transformation", algorithm.name(), "could not be instantiated!");
        }
    }

    public enum Algorithm {
        SHA_256(SHA256Transformation.class),
        SHA_384(SHA384Transformation.class),
        SHA_512(SHA512Transformation.class),
        HMAC_SHA_256(HMACSHA256Transformation.class),
        HMAC_SHA_384(HMACSHA384Transformation.class),
        HMAC_SHA_512(HMACSHA512Transformation.class);

        private final Class<? extends Transformation> clazz;

        Algorithm(Class<? extends Transformation> clazz) {
            this.clazz = clazz;
        }

        public Class<? extends Transformation> getClazz() {
            return clazz;
        }
    }
}