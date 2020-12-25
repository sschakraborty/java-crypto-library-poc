package com.sschakraborty.poc.crypto.core;

import com.sschakraborty.poc.crypto.exception.CryptoException;

import java.nio.charset.Charset;
import java.util.Base64;

public interface Transformation {
    byte[] encrypt(byte[] plainBytes) throws CryptoException;

    byte[] decrypt(byte[] cipherBytes) throws CryptoException;

    byte[] hash(byte[] plainBytes) throws CryptoException;

    default String encrypt(String plainText, Charset charset) throws CryptoException {
        final byte[] plainBytes = (plainText == null) ? null : plainText.getBytes(charset);
        final byte[] encryptedBytes = encrypt(plainBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    default String decrypt(String cipherText, Charset charset) throws CryptoException {
        final byte[] encryptedBytes = (cipherText == null) ? null : Base64.getDecoder().decode(cipherText);
        final byte[] plainBytes = decrypt(encryptedBytes);
        return new String(plainBytes, charset);
    }

    default String hash(String message, Charset charset) throws CryptoException {
        final byte[] plainBytes = (message == null) ? null : message.getBytes(charset);
        final byte[] hashedBytes = hash(plainBytes);
        return new String(hashedBytes, charset);
    }
}