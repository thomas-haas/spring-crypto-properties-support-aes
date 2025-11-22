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
package me.thomas.haas.spring.crypto.properties.support.aes;


import java.io.IOException;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.help.HelpFormatter;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;

/**
 * {@code EncryptCommand} provides a simple command-line interface (CLI) to encrypt,
 * decrypt, and generate keys for secure property management in Spring Boot applications.
 *
 * <p>
 * This utility supports three modes of operation:
 * </p>
 * <ul>
 *   <li><b>encrypt</b> - Encrypts a plaintext input with a provided password, outputs in {@code SECURE(encrypted|salt)} format.</li>
 *   <li><b>decrypt</b> - Decrypts a {@code SECURE(encrypted|salt)} formatted string using the provided password.</li>
 *   <li><b>generate</b> - Generates a random 32-byte hexadecimal salt string for use in encryption.</li>
 * </ul>
 *
 * <p>
 * The encryption uses Spring Security Crypto's {@link Encryptors#delux(String, String)} method
 * (AES-256 encryption with HMAC-SHA512 integrity).
 * </p>
 *
 * <p><b>Usage Examples:</b></p>
 * <pre>{@code
 * # Encrypt a value
 * java -jar encrypt-command.jar --mode encrypt --input "mySecret" --password "mypassword"
 *
 * # Decrypt a value
 * java -jar encrypt-command.jar --mode decrypt --input "SECURE(...)" --password "mypassword"
 *
 * # Generate a random salt key
 * java -jar encrypt-command.jar --mode generate
 * }</pre>
 *
 * <p>If an error occurs during argument parsing or decryption, the program will terminate with an error code.</p>
 *
 * @author Thomas Haas
 */
public class EncryptCommand {

    /**
     * Entry point of the CLI application.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        // Check if arguments are provided
        if (args != null && args.length > 0) {
        	Options options = new Options();
	
	        Option mode = new Option("m", "mode", true, "Mode of operation (encrypt/decrypt/generate)");
	        mode.setRequired(true);
	        options.addOption(mode);
	
	        Option input = new Option("i", "input", true, "Text to process (only for encrypt/decrypt)");
	        input.setRequired(false);
	        options.addOption(input);
	
	        Option password = new Option("p", "password", true, "Password for encryption/decryption");
	        password.setRequired(false);
	        options.addOption(password);
	
	        CommandLineParser parser = new DefaultParser();
	        HelpFormatter formatter = HelpFormatter.builder().get();
	        CommandLine cmd;
	
	        try {
	            cmd = parser.parse(options, args);
	
	            String modeValue = cmd.getOptionValue("mode");
	
	            if ("encrypt".equalsIgnoreCase(modeValue)) {
	                require(cmd, "input");
	                require(cmd, "password");
	                encryptText(cmd.getOptionValue("input"), cmd.getOptionValue("password"));
	                System.exit(0);
	            } else if ("decrypt".equalsIgnoreCase(modeValue)) {
	                require(cmd, "input");
	                require(cmd, "password");
	                decryptText(cmd.getOptionValue("input"), cmd.getOptionValue("password"));
	                System.exit(0);
	            } else if ("generate".equalsIgnoreCase(modeValue)) {
	                generateKey();
	                System.exit(0);
	            } else {
	                System.err.println("Invalid mode. Use 'encrypt', 'decrypt' or 'generate'.");
	                printHelp(formatter, options);
	                System.exit(1);
	            }
	
	        } catch (org.apache.commons.cli.ParseException e) {
	            System.err.println("Error parsing arguments: " + e.getMessage());
	            printHelp(formatter, options);
	            System.exit(1);
	        }
        }
    }
    
    /***
     * Prints a manual how to use the CLI
     * @param formatter
     * @param options
     */
    private static void printHelp(HelpFormatter formatter, Options options) {
        try {
            formatter.printHelp("EncryptCommand", null, options, null, true);
        } catch (IOException e) {
            throw new RuntimeException("Could not print help", e);
        }
    }


    /**
     * Encrypts the given plaintext with the specified password and outputs
     * a {@code SECURE(encryptedText|salt)} formatted string.
     *
     * @param plaintext      the text to encrypt
     * @param passwordValue  the password to use for encryption
     */
    private static void encryptText(String plaintext, String passwordValue) {
        String salt = generateSalt(32);
        TextEncryptor encryptor = Encryptors.delux(passwordValue, salt);
        String encrypted = encryptor.encrypt(plaintext);
        System.out.println("SECURE(" + encrypted + "|" + salt + ")");
    }

    /**
     * Decrypts the provided {@code SECURE(encryptedText|salt)} formatted string using
     * the given password and prints the plaintext.
     *
     * @param encryptedText  the encrypted text to decrypt
     * @param passwordValue  the password to use for decryption
     */
    private static void decryptText(String encryptedText, String passwordValue) {
        if (!encryptedText.startsWith("SECURE(") || !encryptedText.endsWith(")")) {
            System.err.println("Input must be in format: SECURE(encryptedText|salt)");
            System.exit(2);
        }

        String[] parts = encryptedText.substring(7, encryptedText.length() - 1).split("\\|");
        if (parts.length != 2) {
            System.err.println("Invalid SECURE format: should contain ciphertext and salt.");
            System.exit(3);
        }

        String encrypted = parts[0];
        String salt = parts[1];

        TextEncryptor decryptor = Encryptors.delux(passwordValue, salt);
        String decrypted = decryptor.decrypt(encrypted);
        System.out.println(decrypted);
    }

    /**
     * Generates and prints a random 32-byte hexadecimal salt string.
     */
    private static void generateKey() {
        String key = generateSalt(32);
        System.out.println("Generated Key (32 bytes hex): " + key);
    }

    /**
     * Generates a random salt string of the specified byte length, formatted as a hexadecimal string.
     *
     * @param length number of bytes to generate
     * @return a hexadecimal-encoded salt string
     */
    private static String generateSalt(int length) {
        byte[] saltBytes = new byte[length];
        new SecureRandom().nextBytes(saltBytes);
        return HexFormat.of().formatHex(saltBytes);
    }

    /**
     * Validates that the specified required command-line option is present.
     * Exits the program if the option is missing.
     *
     * @param cmd    the parsed command-line arguments
     * @param option the option name to check
     */
    private static void require(CommandLine cmd, String option) {
        if (!cmd.hasOption(option)) {
            System.err.println("Missing required option: --" + option);
            System.exit(1);
        }
    }
}
