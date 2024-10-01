package com.callout.api;

import java.util.Map;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.callout.api.security.PayloadEncryptorDecryptor;
import com.callout.api.security.impl.DefaultPayloadEncryptorDecryptor;
import com.callout.api.utils.VariableRetriever;

public class Encryption implements Execution {
    private Map<String, String> properties; // read-only
    private PayloadEncryptorDecryptor payloadEncryptorDecryptor;
    private VariableRetriever variableRetriever;

    public Encryption(Map<String, String> properties) {
        this.properties = properties;
        this.payloadEncryptorDecryptor = new DefaultPayloadEncryptorDecryptor();
        this.variableRetriever = new VariableRetriever(properties); // Instantiate here
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            // Retrieve and validate input message
            String msg = variableRetriever.retrieveVariable(messageContext, "msg");
            String key = variableRetriever.retrieveVariable(messageContext, "key");
            String iv = variableRetriever.retrieveVariable(messageContext, "iv");

            String encryptedString = payloadEncryptorDecryptor.encrypt(key, iv, msg);
            messageContext.setVariable("enc_payload", encryptedString);
            return ExecutionResult.SUCCESS;
        } catch (Exception e) {
            messageContext.setVariable("error", e.getMessage());
            return ExecutionResult.ABORT;
        }
    }
}
