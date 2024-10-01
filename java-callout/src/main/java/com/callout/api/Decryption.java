package com.callout.api;

import java.util.Base64;
import java.util.Map;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.callout.api.security.PayloadEncryptorDecryptor;
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

            // Decode Base64 encoded strings
            byte[] keyBytes = Base64.getDecoder().decode(key);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] encryptedBytesForDecryption = Base64.getDecoder().decode(encryptedMessage);

            // Validate key and IV sizes
            if (keyBytes.length != 16 && keyBytes.length != 32) {
                messageContext.setVariable("error", "Invalid key size: " + keyBytes.length + " bytes. Expected 16 or 32 bytes.");
                return ExecutionResult.ABORT;
            }
            if (ivBytes.length != 12) {
                messageContext.setVariable("error", "Invalid IV size: " + ivBytes.length + " bytes. Expected 12 bytes.");
                return ExecutionResult.ABORT;
            }

            // Call the decrypt method
            String decryptedBytes = payloadEncryptorDecryptor.decrypt(Base64.getEncoder().encodeToString(keyBytes), Base64.getEncoder().encodeToString(ivBytes), Base64.getEncoder().encodeToString(encryptedBytesForDecryption));
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
