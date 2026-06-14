package me.thomas.haas.spring.crypto.properties.support.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class EncryptCommandTest {

    @Test
    void generatesA32ByteHexKey() {
        CommandResult result = run("-m", "generate");

        assertEquals(0, result.exitCode());
        assertTrue(result.standardOutput()
                .matches("Generated Key \\(32 bytes hex\\): [0-9a-f]{64}\\R?"));
        assertEquals("", result.errorOutput());
    }

    @Test
    void encryptsAndDecryptsText() {
        String password = "unit-test-password";
        String plaintext = "secret value";

        CommandResult encrypted = run(
                "-m", "encrypt",
                "--password", password,
                "--input", plaintext);

        assertEquals(0, encrypted.exitCode());
        assertTrue(encrypted.standardOutput().trim()
                .matches("SECURE\\([0-9a-f]+\\|[0-9a-f]{64}\\)"));

        CommandResult decrypted = run(
                "-m", "decrypt",
                "--password", password,
                "--input", encrypted.standardOutput().trim());

        assertEquals(0, decrypted.exitCode());
        assertEquals(plaintext, decrypted.standardOutput().trim());
        assertEquals("", decrypted.errorOutput());
    }

    @Test
    void rejectsMissingRequiredInput() {
        CommandResult result = run("-m", "encrypt", "--password", "password");

        assertEquals(1, result.exitCode());
        assertEquals("Missing required option: --input", result.errorOutput().trim());
    }

    @Test
    void rejectsInvalidSecureWrapper() {
        CommandResult result = run(
                "-m", "decrypt",
                "--password", "password",
                "--input", "not-secure");

        assertEquals(2, result.exitCode());
        assertEquals(
                "Input must be in format: SECURE(encryptedText|salt)",
                result.errorOutput().trim());
    }

    @Test
    void rejectsSecureValueWithoutSaltSeparator() {
        CommandResult result = run(
                "-m", "decrypt",
                "--password", "password",
                "--input", "SECURE(ciphertext)");

        assertEquals(3, result.exitCode());
        assertEquals(
                "Invalid SECURE format: should contain ciphertext and salt.",
                result.errorOutput().trim());
    }

    @Test
    void rejectsUnknownModeAndPrintsHelp() {
        CommandResult result = run("-m", "unknown");

        assertEquals(1, result.exitCode());
        assertTrue(result.errorOutput().contains("Invalid mode"));
        assertTrue(result.standardOutput().contains("EncryptCommand"));
    }

    @Test
    void acceptsEmptyArgumentsWithoutOutput() {
        CommandResult result = run();

        assertEquals(0, result.exitCode());
        assertEquals("", result.standardOutput());
        assertEquals("", result.errorOutput());
    }

    private CommandResult run(String... args) {
        ByteArrayOutputStream standardOutput = new ByteArrayOutputStream();
        ByteArrayOutputStream errorOutput = new ByteArrayOutputStream();

        int exitCode;
        try (PrintStream out = new PrintStream(standardOutput, true, StandardCharsets.UTF_8);
                PrintStream err = new PrintStream(errorOutput, true, StandardCharsets.UTF_8)) {
            exitCode = EncryptCommand.run(args, out, err);
        }

        return new CommandResult(
                exitCode,
                standardOutput.toString(StandardCharsets.UTF_8),
                errorOutput.toString(StandardCharsets.UTF_8));
    }

    private record CommandResult(int exitCode, String standardOutput, String errorOutput) {
    }
}
