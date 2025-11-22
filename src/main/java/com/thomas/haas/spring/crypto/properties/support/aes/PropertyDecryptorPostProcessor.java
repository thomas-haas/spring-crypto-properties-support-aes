/*
 * Copyright 2025 Thomas Haas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.thomas.haas.spring.crypto.properties.support.aes;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * {@code PropertyDecryptorPostProcessor} automatically decrypts encrypted property values
 * in a Spring Boot application during startup.
 *
 * <p>
 * It looks for properties formatted as {@code SECURE(encryptedText|salt)} and decrypts them
 * using a password provided via the {@code encrypt.password} property.
 * </p>
 *
 * <p>
 * This ensures that encrypted values in {@code application.properties}, {@code application.yml},
 * or environment variables are transparently available in plaintext within the Spring context.
 * </p>
 *
 * <p>
 * The decryption uses Spring Security Crypto's {@link Encryptors#delux(String, String)} method
 * with AES-256 encryption and HMAC-SHA512 integrity verification.
 * </p>
 *
 * <p>
 * If decryption fails, the application startup will be aborted with an {@link IllegalStateException}.
 * </p>
 *
 * @author Thomas Haas
 */
public class PropertyDecryptorPostProcessor  implements EnvironmentPostProcessor, Ordered {

    private static final Pattern SECURE_PATTERN = Pattern.compile("^SECURE\\(([^|]+)\\|(.+)\\)$");

    /**
     * Processes the {@link ConfigurableEnvironment} to decrypt any property values
     * that match the {@code SECURE(encryptedText|salt)} format.
     *
     * @param environment the Spring environment to process
     * @param application the Spring application instance
     */
    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String password = environment.getProperty("encrypt.password");

        if (password == null) {
            return;
        }

        Map<String, Object> decryptedProperties = new HashMap<>();

        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            if (propertySource instanceof MapPropertySource mapPropertySource) {
                Map<String, Object> source = mapPropertySource.getSource();
                for (Map.Entry<String, Object> entry : source.entrySet()) {
                    Object value = entry.getValue();
                    if (value instanceof CharSequence charSequence) {
                        Matcher matcher = SECURE_PATTERN.matcher(charSequence);
                        if (matcher.matches()) {
                            String encryptedText = matcher.group(1);
                            String salt = matcher.group(2);
                            String decrypted = decrypt(password, salt, encryptedText);
                            decryptedProperties.put(entry.getKey(), decrypted);
                        }
                    }
                }
            }
        }

        if (!decryptedProperties.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("decryptedProperties", decryptedProperties));
        }
    }


    /**
     * Decrypts a given encrypted text using the provided password and salt.
     *
     * @param password      the password used for decryption
     * @param salt          the salt used during encryption
     * @param encryptedText the encrypted text to decrypt
     * @return the decrypted plaintext
     * @throws IllegalStateException if decryption fails
     */
    private String decrypt(String password, String salt, String encryptedText) {
        try {
            TextEncryptor encryptor = Encryptors.delux(password, salt);
            return encryptor.decrypt(encryptedText);
        } catch (Exception e) {
            throw new IllegalStateException("Could not decrypt property", e);
        }
    }

    /**
     * Specifies the order in which this post-processor should run.
     * This processor runs at the highest precedence to ensure decryption happens early.
     *
     * @return {@link Ordered#HIGHEST_PRECEDENCE}
     */
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
