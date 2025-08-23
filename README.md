# Spring Security Crypto CLI

> Library for encrypting and decrypting properties in a Spring Boot Application. This project has no legal affiliation with the Spring Boot project.

---

## ✨ Features

- **Encrypt** and **decrypt** texts with Spring Security Crypto.
- **Property Decryption** in `application.properties` or `application.yml` on Spring Boot startup.
- **Custom Format**: `SECURE(encryptedText|salt)`.

---

## 🚀 CLI Usage

After building the project, you will get a `.jar` file (using the Maven Shade Plugin).  
You can then work directly on the console:

```bash
# Encrypt
java -jar spring-crypto-properties-support-aes-1.0.3.jar -m encrypt --password <password> --input <plainText>

# Decrypt
java -jar spring-crypto-properties-support-aes-1.0.3.jar -m decrypt --password <password> --input <SECURE(ciphertext|salt)>

# Generate a 32-byte secure random key
java -jar spring-crypto-properties-support-aes-1.0.3.jar -m generate
```

### 🔵 Example: Encrypt Text

```bash
$ java -jar spring-crypto-properties-support-aes-1.0.3.jar -m encrypt --input "mySecretPassword123" --password "c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51"
```

Output:

```text
SECURE(f8e413c12b1653c833e9deda383671cf89686253990ac69ca7a2f26c4b34d49a44f8d61912a306497b0bbc97c7156226eeda9f|a0bd827b7eb0c6318fdcaaed195a594ebed69dcb2b81d6a908a22023ded4b4b1)
```

- `f8e413c12b1653c833e...` → The encrypted text.
- `a0bd827b7eb0c6` → The salt used (automatically generated).

---

### 🟣 Example: Decrypt Text

```bash
$ java -jar spring-crypto-properties-support-aes-1.0.3.jar -m decrypt --input "SECURE(f8e413c12b1653c833e9deda383671cf89686253990ac69ca7a2f26c4b34d49a44f8d61912a306497b0bbc97c7156226eeda9f|a0bd827b7eb0c6318fdcaaed195a594ebed69dcb2b81d6a908a22023ded4b4b1)" --password "c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51"
```

Output:

```text
mySecretPassword123
```

---

### 🟣 Example: Generate Key

```bash
$ java -jar spring-crypto-properties-support-aes-1.0.3.jar -m generate
```

Output:

```text
Generated Key (32 bytes hex): c7595f6f88cee46c8602f59dda757db2451a22eb18aec49ee862576e65628c51
```

---

## 🛠 Usage in `application.properties`

To use an encrypted property in your Spring Boot app:

```properties
myapp.datasource.password=SECURE(3f8a9bc2d7c1d...|6c7e9d2b63e88d7d)

# Also define the necessary decryption values:
encrypt.password=${PASSWORD_IN_ENV_VARIABLE:Defaultpassword}
```

- **`encrypt.password`** must be configured in plain text or set via environment variables.
- Salt is included in the encrypted value → no separate configuration is needed.

---

## ⚙️ How it Works

- On startup, an `EnvironmentPostProcessor` scans all properties.
- Any values starting with **`SECURE(`** are automatically decrypted.
- Result: Spring Boot receives the plaintext values without any code changes.

---

## 📦 Build

```bash
mvn clean package
```

This will generate the executable jar in:

```bash
target/spring-security-crypto-cli-1.0.0.jar
```
