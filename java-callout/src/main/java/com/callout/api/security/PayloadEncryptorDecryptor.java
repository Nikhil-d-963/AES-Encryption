package com.callout.api.security;

import com.callout.api.security.exception.EncryptionDecryptionException;

public interface PayloadEncryptorDecryptor {
    String encrypt(String encKey, String initVector, String plainText) throws EncryptionDecryptionException;

    String decrypt(String encKey, String initVector, String encryptedText) throws EncryptionDecryptionException;
}
