package com.callout.api.utils;

import java.util.Map;
import java.util.Objects;

import com.apigee.flow.message.MessageContext;

public class VariableRetriever {
    private Map<String, String> properties;

    public VariableRetriever(Map<String, String> properties) {
        this.properties = properties;
    }

    // Public method to retrieve the variable
    public String retrieveVariable(MessageContext messageContext, String varName) throws Exception {
        return getVariable(messageContext, varName);
    }

    // Private method that contains the logic
    private String getVariable(MessageContext messageContext, String varName) throws Exception {
        String variable = messageContext.getVariable(this.properties.get(varName));
        if (Objects.nonNull(variable)) {
            return variable;
        }
        messageContext.setVariable("warning", String.format("Variable '%s' not found, taking static value", varName));
        variable = this.properties.get(varName);
        if (Objects.isNull(variable) || variable.isEmpty()) {
            throw new Exception(String.format("%s cannot be null or empty", varName));
        }
        return variable;
    }
}
