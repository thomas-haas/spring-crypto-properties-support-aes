package me.thomas.haas.spring.crypto.properties.support.aes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.crypto.encrypt.Encryptors;

class PropertyDecryptorPostProcessorTest {

    private static final String PASSWORD = "unit-test-password";
    private static final String SALT =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    private final PropertyDecryptorPostProcessor postProcessor =
            new PropertyDecryptorPostProcessor();

    @Test
    void decryptsSecurePropertiesAndLeavesOtherValuesUntouched() {
        String plaintext = "database-password";
        String encrypted = Encryptors.delux(PASSWORD, SALT).encrypt(plaintext);
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("encrypt.password", PASSWORD);
        properties.put("database.password", "SECURE(" + encrypted + "|" + SALT + ")");
        properties.put("database.user", "application");
        properties.put("database.port", 5432);
        StandardEnvironment environment = environment(properties);

        postProcessor.postProcessEnvironment(environment, null);

        assertEquals(plaintext, environment.getProperty("database.password"));
        assertEquals("application", environment.getProperty("database.user"));
        assertEquals("5432", environment.getProperty("database.port"));
        assertEquals(
                "decryptedProperties",
                environment.getPropertySources().iterator().next().getName());
    }

    @Test
    void doesNothingWhenPasswordIsMissing() {
        StandardEnvironment environment = environment(Map.of(
                "database.password", "SECURE(ciphertext|" + SALT + ")"));

        postProcessor.postProcessEnvironment(environment, null);

        assertEquals(
                "SECURE(ciphertext|" + SALT + ")",
                environment.getProperty("database.password"));
        assertFalse(environment.getPropertySources().contains("decryptedProperties"));
    }

    @Test
    void ignoresValuesThatDoNotMatchSecureFormat() {
        StandardEnvironment environment = environment(Map.of(
                "encrypt.password", PASSWORD,
                "database.password", "SECURE(incomplete)"));

        postProcessor.postProcessEnvironment(environment, null);

        assertEquals("SECURE(incomplete)", environment.getProperty("database.password"));
        assertFalse(environment.getPropertySources().contains("decryptedProperties"));
    }

    @Test
    void failsFastWhenEncryptedValueCannotBeDecrypted() {
        StandardEnvironment environment = environment(Map.of(
                "encrypt.password", PASSWORD,
                "database.password", "SECURE(not-valid-ciphertext|" + SALT + ")"));

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> postProcessor.postProcessEnvironment(environment, null));

        assertEquals("Could not decrypt property", exception.getMessage());
    }

    @Test
    void runsAtLowestPrecedence() {
        assertEquals(Ordered.LOWEST_PRECEDENCE, postProcessor.getOrder());
    }

    @Test
    void isDiscoveredAndDecryptsPropertiesDuringSpringBootStartup() {
        String plaintext = "resolved-during-startup";
        String encrypted = Encryptors.delux(PASSWORD, SALT).encrypt(plaintext);
        SpringApplication application = new SpringApplication(TestApplication.class);
        application.setBannerMode(Banner.Mode.OFF);
        application.setLogStartupInfo(false);
        application.setDefaultProperties(Map.of(
                "encrypt.password", PASSWORD,
                "application.secret", "SECURE(" + encrypted + "|" + SALT + ")"));

        try (ConfigurableApplicationContext context = application.run()) {
            assertEquals(
                    plaintext,
                    context.getEnvironment().getProperty("application.secret"));
        }
    }

    private StandardEnvironment environment(Map<String, Object> properties) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
        return environment;
    }

    @Configuration(proxyBeanMethods = false)
    static class TestApplication {
    }
}
