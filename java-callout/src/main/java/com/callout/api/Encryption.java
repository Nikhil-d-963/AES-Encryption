package com.callout.api;

import java.util.Base64;
import java.util.Map;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.exception.EncryptionDecryptionException;
import com.callout.api.security.impl.DefaultPayloadEncryptorDecryptor;

public class Encryption implements Execution {

    PayloadEncryptorDecryptor payloadEncryptorDecryptor = new DefaultPayloadEncryptorDecryptor();
    private Map<String, String> properties; // read-only

    public Encryption(Map<String, String> properties) {
        this.properties = properties;
    }

    @Override
    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            // Retrieve and validate input message
            String msg = messageContext.getVariable(this.properties.get("msg"));
            if (msg == null || msg.trim().isEmpty()) {
                msg = this.properties.get("msg");
                messageContext.setVariable("warning", "Variable 'msg' not found, taking static value");
                if (msg == null || msg.trim().isEmpty()) {
                    messageContext.setVariable("error", "Message cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }

            // Retrieve and validate key
            String key = messageContext.getVariable(this.properties.get("key"));
            if (key == null || key.trim().isEmpty()) {
                key = this.properties.get("key");
                messageContext.setVariable("warning", "Variable 'key' not found, taking static value");
                if (key == null || key.trim().isEmpty()) {
                    messageContext.setVariable("error", "Key cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }

            // Retrieve and validate IV (Initialization Vector)
            String iv = messageContext.getVariable(this.properties.get("iv"));
            if (iv == null || iv.trim().isEmpty()) {
                iv = this.properties.get("iv");
                messageContext.setVariable("warning", "Variable 'iv' not found, taking static value");
                if (iv == null || iv.trim().isEmpty()) {
                    messageContext.setVariable("error", "IV cannot be null or empty");
                    return ExecutionResult.ABORT;
                }
            }

            byte[] keyByte = Base64.getDecoder().decode(key);
            byte[] ivByte = Base64.getDecoder().decode(iv);

            // Validate key and IV sizes
            if (keyByte.length != 16 && keyByte.length != 32) {
                messageContext.setVariable("error", "Invalid key size: " + keyByte.length + " bytes. Expected 16 or 32 bytes.");
                return ExecutionResult.ABORT;
            }
            if (ivByte.length != 12) {
                messageContext.setVariable("error", "Invalid IV size: " + ivByte.length + " bytes. Expected 12 bytes.");
                return ExecutionResult.ABORT;
            }

            String encryptedBytes = payloadEncryptorDecryptor.encrypt(key, iv, msg);
            messageContext.setVariable("enc_payload", encryptedBytes);
            return ExecutionResult.SUCCESS;

        } catch (IllegalArgumentException e) {
            messageContext.setVariable("error", "IllegalArgumentException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (EncryptionDecryptionException e) {
            messageContext.setVariable("error", "EncryptionDecryptionException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (Exception e) {
            messageContext.setVariable("error", "Encryption failed: " + e.getMessage());
            return ExecutionResult.ABORT;
        }
    }
}
