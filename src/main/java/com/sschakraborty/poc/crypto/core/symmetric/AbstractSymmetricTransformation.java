package com.sschakraborty.poc.crypto.core.symmetric;

import com.sschakraborty.poc.crypto.core.Transformation;
import com.sschakraborty.poc.crypto.exception.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public abstract class AbstractSymmetricTransformation implements Transformation {
    private final Cipher encryptCipher;
    private final Cipher decryptCipher;

    public AbstractSymmetricTransformation(String cipherName, String algorithmName, Provider provider, byte[] symmetricKey, byte[] initializationVector) throws CryptoException {
        try {
            if (Security.getProvider(provider.getName()) == null) {
                Security.addProvider(provider);
            }
            encryptCipher = Cipher.getInstance(cipherName, provider);
            decryptCipher = Cipher.getInstance(cipherName, provider);
            initCipher(encryptCipher, Cipher.ENCRYPT_MODE, buildKey(symmetricKey, algorithmName), buildParameterSpec(initializationVector));
            initCipher(decryptCipher, Cipher.DECRYPT_MODE, buildKey(symmetricKey, algorithmName), buildParameterSpec(initializationVector));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CryptoException(e, "Could not build instance of", cipherName, "with provider", provider.getName());
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new CryptoException(e, "Could not initialize", cipherName, "with provider", provider.getName());
        }
    }

    private void initCipher(Cipher cipher, int mode, Key key, AlgorithmParameterSpec parameterSpec) throws InvalidAlgorithmParameterException, InvalidKeyException {
        if (parameterSpec == null) {
            cipher.init(mode, key);
        } else {
            cipher.init(mode, key, parameterSpec);
        }
    }

    private Key buildKey(byte[] symmetricKey, String algorithmName) {
        return new SecretKeySpec(symmetricKey, algorithmName);
    }

    private AlgorithmParameterSpec buildParameterSpec(byte[] initializationVector) {
        if (initializationVector == null || initializationVector.length == 0) return null;
        return new IvParameterSpec(initializationVector);
    }

    @Override
    public byte[] encrypt(byte[] plainBytes) throws CryptoException {
        checkNull(plainBytes);
        try {
            return encryptCipher.doFinal(plainBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(e, "Error occurred while encrypting data!");
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherBytes) throws CryptoException {
        checkNull(cipherBytes);
        try {
            return decryptCipher.doFinal(cipherBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException(e, "Error occurred while decrypting data!");
        }
    }

    @Override
    public byte[] hash(byte[] plainBytes) throws CryptoException {
        throw new CryptoException("Hash operation not supported using symmetric cipher algorithm!");
    }

    private void checkNull(Object payload) throws CryptoException {
        if (payload == null) {
            throw new CryptoException("Payload cannot be null!");
        }
    }
}