package com.callout.api.security.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.exception.EncryptionDecryptionException;

public class DefaultPayloadEncryptorDecryptor implements PayloadEncryptorDecryptor {
    private static final int GCM_TAG_LENGTH = 16;
    private byte[] keyBytes;
    private byte[] ivBytes;

    public static void main(String[] args) throws EncryptionDecryptionException {
        PayloadEncryptorDecryptor encryptorDecryptor = new DefaultPayloadEncryptorDecryptor();
        String encryptedMessage = encryptorDecryptor.encrypt("W3tqkLf6mQLOwW7OX1FNKnGBdL+4kFOTvWyjEDwmNGo=",
                "Fz3+9GZV/YmSNT4g", "Test Message");
        System.out.println(encryptedMessage);
        String plainText = encryptorDecryptor.decrypt("W3tqkLf6mQLOwW7OX1FNKnGBdL+4kFOTvWyjEDwmNGo=",
                "Fz3+9GZV/YmSNT4g", "vqx1jvjpFWT3LfKoXqJalAy+PnE8g/9lTPGR/w==");
        if (plainText.equals("Test Message")) {
            System.out.println("Decryption works");
            System.out.println(plainText);
        }
    }

    public void setKeyAndIvInBytes(String encKey, String initVector) throws EncryptionDecryptionException {
        this.keyBytes = Base64.getDecoder().decode(encKey);
        this.ivBytes = Base64.getDecoder().decode(initVector);

        // Validate key and IV sizes
        if (keyBytes.length != 16 && keyBytes.length != 32) {
            String errorMessage = String.format("Invalid key size: %d bytes. Expected 16 or 32 bytes.",
                    keyBytes.length);
            throw new EncryptionDecryptionException(errorMessage);
        }
        if (ivBytes.length != 12) {
            String errorMessage = String.format("Invalid IV size: %d bytes. Expected 12 bytes.", ivBytes.length);
            throw new EncryptionDecryptionException(errorMessage);
        }
    }

    @Override
    public String encrypt(String encKey, String initVector, String plainText) throws EncryptionDecryptionException {
        setKeyAndIvInBytes(encKey, initVector);
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException
                | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionDecryptionException(e);
        }
    }

    @Override
    public String decrypt(String encKey, String initVector, String encryptedText) throws EncryptionDecryptionException {
        setKeyAndIvInBytes(encKey, initVector);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        try {
            Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpecD = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec gcmParameterSpecD = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes);
            cipherD.init(Cipher.DECRYPT_MODE, keySpecD, gcmParameterSpecD);
            byte[] plainBytesD = cipherD.doFinal(encryptedBytes);
            return new String(plainBytesD, StandardCharsets.UTF_8);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionDecryptionException(e);
        }
    }

}
