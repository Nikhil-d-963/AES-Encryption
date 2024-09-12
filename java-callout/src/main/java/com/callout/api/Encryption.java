package com.callout.api;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

public class Encryption implements Execution {
    private Map<String, String> properties; // read-only

    public Encryption(Map<String, String> properties) {
        this.properties = properties;
    }
    
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

            String encryptedString;
            byte[] plainBytes = msg.getBytes(StandardCharsets.UTF_8);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, ivByte);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plainBytes);
            encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            messageContext.setVariable("enc_payload", encryptedString);
            return ExecutionResult.SUCCESS;
        } catch (IllegalArgumentException e) {
            messageContext.setVariable("error", "IllegalArgumentException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (java.security.InvalidKeyException e) {
            messageContext.setVariable("error", "InvalidKeyException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (javax.crypto.BadPaddingException e) {
            messageContext.setVariable("error", "BadPaddingException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (javax.crypto.IllegalBlockSizeException e) {
            messageContext.setVariable("error", "IllegalBlockSizeException: " + e.getMessage());
            return ExecutionResult.ABORT;
        } catch (Exception e) {
            messageContext.setVariable("error", "Encryption failed: " + e.getMessage());
            return ExecutionResult.ABORT;
        }
    }
}
