package com.sschakraborty.poc.crypto.exception;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class CryptoException extends Exception {
    private final String exceptionMessage;
    private final Map<String, Object> propertyMap;

    public CryptoException(Throwable targetException, Object... objects) {
        this(objects);
        Objects.requireNonNull(targetException, "Target exception passed while creating CryptoException cannot be null!");
        initCause(targetException);
    }

    public CryptoException(Object... objects) {
        Objects.requireNonNull(objects, "Objects passed while creating CryptoException cannot be null!");
        final StringBuilder stringBuilder = new StringBuilder();
        for (final Object object : objects) {
            Objects.requireNonNull(object, "Object passed while creating CryptoException cannot be null!");
            stringBuilder.append(object.toString()).append(" ");
        }
        exceptionMessage = (stringBuilder.length() > 0) ? stringBuilder.substring(0, stringBuilder.length() - 1) : "";
        propertyMap = new HashMap<>();
    }

    public Object getProperty(String key) throws CryptoException {
        if (!propertyMap.containsKey(key)) {
            throw new CryptoException("Invalid property key", key);
        }
        return propertyMap.get(key);
    }

    public void addProperty(String key, Object property) {
        Objects.requireNonNull(key, "Key for a property cannot be null!");
        Objects.requireNonNull(property, "Property object cannot be nul!");
        propertyMap.put(key, property);
    }

    public void addAllProperties(Map<String, Object> map) {
        Objects.requireNonNull(map, "Property map passed into CryptoException object cannot be null!");
        propertyMap.putAll(map);
    }

    public void deleteProperty(String key) {
        Objects.requireNonNull(key, "Key for a property cannot be null!");
        propertyMap.remove(key);
    }

    @Override
    public String toString() {
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(String.format("%s { %s }", this.getClass().getSimpleName(), exceptionMessage)).append("\n");
        final Throwable cause = this.getCause();
        if (cause != null) {
            stringBuilder.append(String.format("%s { %s }", cause.getClass().getSimpleName(), cause.getMessage())).append("\n");
            for (final StackTraceElement stackTraceElement : cause.getStackTrace()) {
                stringBuilder.append(
                        String.format(
                                ">>> { file: %s, class: %s, method: %s, lineNo: %d }",
                                stackTraceElement.getFileName(),
                                stackTraceElement.getClassName(),
                                stackTraceElement.getMethodName(),
                                stackTraceElement.getLineNumber()
                        )
                );
            }
        }
        return stringBuilder.toString();
    }
}