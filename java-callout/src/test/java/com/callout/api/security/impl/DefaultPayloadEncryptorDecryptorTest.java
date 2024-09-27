package com.callout.api.security.impl;

import org.junit.Assert;
import org.junit.Test;

import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.exception.EncryptionDecryptionException;

public class DefaultPayloadEncryptorDecryptorTest {

    private PayloadEncryptorDecryptor encryptorDecryptor;
    private String encKey;
    private String initVector;
    private String plainText;
    private String encryptedText;
    private String invalidEncKey;
    private String invalidInitVector;
    private String invalidEncryptedText;

    public DefaultPayloadEncryptorDecryptorTest() {
        this.encryptorDecryptor = new DefaultPayloadEncryptorDecryptor();
        this.plainText = "Test Message";
        this.encKey = "W3tqkLf6mQLOwW7OX1FNKnGBdL+4kFOTvWyjEDwmNGo=";
        this.initVector = "Fz3+9GZV/YmSNT4g";
        this.encryptedText = "vqx1jvjpFWT3LfKoXqJalAy+PnE8g/9lTPGR/w==";
        this.invalidEncKey = "xyz";
        this.invalidInitVector = "abcd";
        this.invalidEncryptedText = "PnE8g/9lTPGR/w==";
    }

    @Test
    public void testEncryptionSuccess() throws EncryptionDecryptionException {
        String encryptedText = encryptorDecryptor.encrypt(encKey, initVector, plainText);
        Assert.assertNotNull("Should return encrypted message", encryptedText);
        Assert.assertEquals("Should match the expected encrypted message", encryptedText, encryptedText);
    }

    @Test
    public void testEncryptionFailureInvalidKey() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when Encryption Key is invalid",
                EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.encrypt(this.invalidEncKey, this.initVector, this.plainText);
                });
    }

    @Test
    public void testEncryptionFailureInvalidIV() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when IV is invalid", EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.encrypt(this.encKey, this.invalidInitVector, this.plainText);
                });
    }

    @Test
    public void testEncryptionFailureInvalidKeyAndIV() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when both Key and IV is invalid",
                EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.encrypt(this.invalidEncKey, this.invalidInitVector, this.plainText);
                });
    }

    @Test
    public void testDecryptionSuccess() throws EncryptionDecryptionException {
        String decryptedText = encryptorDecryptor.decrypt(this.encKey, this.initVector, this.encryptedText);
        Assert.assertNotNull("Should return decrypted plain text", decryptedText);
        Assert.assertEquals("Should match the original message", this.plainText, decryptedText);
    }

    @Test
    public void testDecryptionFailureInvalidEncryptedText() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when encrypted message is invalid",
                EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.decrypt(this.invalidEncKey, this.initVector, this.invalidEncryptedText);
                });
    }

    @Test
    public void testDecryptionFailureInvalidKey() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when Encryption Key is invalid",
                EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.decrypt(this.invalidEncKey, this.initVector, this.encryptedText);
                });
    }

    @Test
    public void testDecryptionFailureInvalidIV() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when IV is invalid", EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.decrypt(this.encKey, this.invalidInitVector, this.encryptedText);
                });
    }

    @Test
    public void testDecryptionFailureInvalidKeyAndIV() throws EncryptionDecryptionException {
        Assert.assertThrows("Should throw exception when both Key and IV is invalid",
                EncryptionDecryptionException.class,
                () -> {
                    encryptorDecryptor.decrypt(this.invalidEncKey, this.invalidInitVector, this.encryptedText);
                });
    }
}
