# Spring Security Crypto CLI

> Library for encrypting and decrypting properties in a Spring Boot application. This project is not affiliated with the Spring Boot project. Currently compatible with Java 25, Spring Boot 4.1.0, and Spring Security Crypto 7.1.0.

---

## Features

- Encrypt and decrypt text with Spring Security Crypto.
- Decrypt properties from `application.properties` or `application.yml` on Spring Boot startup.
- Use the `SECURE(encryptedText|salt)` value format.
- Use the same compact JAR as an executable CLI and as a Spring Boot dependency.

The executable JAR bundles only the CLI and cryptography implementation under
internal package names. Spring Boot is supplied by the consuming application, so
the JAR does not include Spring Web, an embedded server, or its own Spring Boot
runtime.

---

## CLI Usage

After building the project, you will get an executable `.jar` file through the Maven Shade Plugin.

```bash
# Encrypt
java -jar spring-crypto-properties-support-aes-1.2.6.jar -m encrypt --password <password> --input <plainText>

# Decrypt
java -jar spring-crypto-properties-support-aes-1.2.6.jar -m decrypt --password <password> --input <SECURE(ciphertext|salt)>

# Generate a 32-byte secure random key
java -jar spring-crypto-properties-support-aes-1.2.6.jar -m generate
```

### Example: Encrypt Text

```bash
$ java -jar spring-crypto-properties-support-aes-1.2.6.jar -m encrypt --input "mySecretPassword123" --password "c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51"
```

Output:

```text
SECURE(f8e413c12b1653c833e9deda383671cf89686253990ac69ca7a2f26c4b34d49a44f8d61912a306497b0bbc97c7156226eeda9f|a0bd827b7eb0c6318fdcaaed195a594ebed69dcb2b81d6a908a22023ded4b4b1)
```

- `f8e413c12b1653c833e...` is the encrypted text.
- `a0bd827b7eb0c6...` is the salt used during encryption.

---

### Example: Decrypt Text

```bash
$ java -jar spring-crypto-properties-support-aes-1.2.6.jar -m decrypt --input "SECURE(f8e413c12b1653c833e9deda383671cf89686253990ac69ca7a2f26c4b34d49a44f8d61912a306497b0bbc97c7156226eeda9f|a0bd827b7eb0c6318fdcaaed195a594ebed69dcb2b81d6a908a22023ded4b4b1)" --password "c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51"
```

Output:

```text
mySecretPassword123
```

---

### Example: Generate Key

```bash
$ java -jar spring-crypto-properties-support-aes-1.2.6.jar -m generate
```

Output:

```text
Generated Key (32 bytes hex): c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51
```

---

## Usage in `application.properties`

To use an encrypted property in your Spring Boot app:

```properties
myapp.datasource.password=SECURE(3f8a9bc2d7c1d...|6c7e9d2b63e88d7d)

# Also define the decryption password:
encrypt.password=${PASSWORD_IN_ENV_VARIABLE:Defaultpassword}
```

- `encrypt.password` must be configured in plain text or set via an environment variable.
- The salt is included in the encrypted value, so no separate salt configuration is needed.

---

## How it Works

- On startup, an `EnvironmentPostProcessor` scans all properties.
- Any values matching `SECURE(encryptedText|salt)` are automatically decrypted.
- Spring Boot receives the plaintext values without application code changes.

---

## Build

```bash
mvn clean package
```

This generates the executable jar in:

```bash
target/spring-crypto-properties-support-aes-1.2.6.jar
```
