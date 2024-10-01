package com.callout.api;

import java.util.Map;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.impl.DefaultPayloadEncryptorDecryptor;
import com.callout.api.utils.VariableRetriever;

public class Decryption implements Execution {
    private Map<String, String> properties;
    private PayloadEncryptorDecryptor payloadEncryptorDecryptor;
    private VariableRetriever variableRetriever;

    public Decryption(Map<String, String> properties) {
        this.properties = properties;
        this.payloadEncryptorDecryptor = new DefaultPayloadEncryptorDecryptor();
        this.variableRetriever = new VariableRetriever(properties); // Instantiate here
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            // Retrieve values from messageContext or properties
            String key = variableRetriever.retrieveVariable(messageContext, "key");
            String iv = variableRetriever.retrieveVariable(messageContext, "iv");
            String encryptedMessage = variableRetriever.retrieveVariable(messageContext, "encryptedMessage");

            String decryptedBytes = payloadEncryptorDecryptor.decrypt(key, iv, encryptedMessage);
            messageContext.setVariable("decrypted_payload", decryptedBytes);
            return ExecutionResult.SUCCESS;
        } catch (Exception e) {
            messageContext.setVariable("error", "Decryption failed: " + e.getMessage());
            return ExecutionResult.ABORT;
        }
    }
}
