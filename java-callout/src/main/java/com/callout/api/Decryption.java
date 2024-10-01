package com.callout.api;

import java.util.Map;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.exception.EncryptionDecryptionException;
import com.callout.api.security.impl.DefaultPayloadEncryptorDecryptor;

public class Decryption implements Execution {

    PayloadEncryptorDecryptor payloadEncryptorDecryptor = new DefaultPayloadEncryptorDecryptor();

    private Map<String, String> properties; // read-only

    public Decryption(Map<String, String> properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            // Retrieve values from messageContext or properties
            String key = messageContext.getVariable(this.properties.get("key"));
            String iv = messageContext.getVariable(this.properties.get("iv"));
            String encryptedMessage = messageContext.getVariable(this.properties.get("encryptedMessage"));

            // Validate and retrieve values
            if (key == null || key.trim().isEmpty()) {
                key = this.properties.get("key");
                messageContext.setVariable("warning", "Variable 'key' not found, taking static value: " + key);
                if (key == null || key.trim().isEmpty()) {
                    messageContext.setVariable("error", "Key cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }
            if (iv == null || iv.trim().isEmpty()) {
                iv = this.properties.get("iv");
                messageContext.setVariable("warning", "Variable 'iv' not found, taking static value: " + iv);
                if (iv == null || iv.trim().isEmpty()) {
                    messageContext.setVariable("error", "IV cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }
            if (encryptedMessage == null || encryptedMessage.trim().isEmpty()) {
                encryptedMessage = this.properties.get("encryptedMessage");
                messageContext.setVariable("warning", "Variable 'encryptedMessage' not found, taking static value");
                if (encryptedMessage == null || encryptedMessage.trim().isEmpty()) {
                    messageContext.setVariable("error", "Encrypted message cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }



            // Use DefaultPayloadEncryptorDecryptor to set key and IV
            try {
                ((DefaultPayloadEncryptorDecryptor) payloadEncryptorDecryptor).setKeyAndIvInBytes(key, iv);
            } catch (EncryptionDecryptionException e) {
                messageContext.setVariable("error", e.getMessage());
                return ExecutionResult.ABORT;
            }

            // Call the decrypt method
            String decryptedBytes = payloadEncryptorDecryptor.decrypt(key, iv, encryptedMessage);
            messageContext.setVariable("decrypted_payload", decryptedBytes);
            return ExecutionResult.SUCCESS;
        } catch (IllegalArgumentException e) {
            messageContext.setVariable("error", "Invalid input: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (Exception e) {
            messageContext.setVariable("error", "Decryption failed: " + e.getMessage());
            return ExecutionResult.ABORT;
        }
    }
}
