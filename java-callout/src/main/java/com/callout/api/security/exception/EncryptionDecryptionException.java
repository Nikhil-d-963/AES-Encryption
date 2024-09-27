package com.callout.api.security.exception;

public class EncryptionDecryptionException extends Exception {
    public EncryptionDecryptionException(String message) {
        super(message);
    }

    public EncryptionDecryptionException(Throwable e) {
        super(e);
    }

    public EncryptionDecryptionException(String message, Throwable e) {
        super(message, e);
    }
}
