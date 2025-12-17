package com.armandoboaca17.encryptedmess;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class SecurityUtils {
    private static final int SALT_LENGTH = 32;
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATIONS = 65536;
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    // ========== PASSWORD HASHING ==========
    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(String password, String salt) {
        try {
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes,
                    ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // ========== AES ENCRYPTION/DECRYPTION ==========
    public static String[] encryptAES(String plaintext, String password) throws Exception {
        // Generate random salt for key derivation
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        // Generate key from password and salt
        SecretKey key = generateAESKey(password, salt);

        // Generate IV
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new String[]{
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(salt) // Return salt too
        };
    }

    public static String decryptAES(String ciphertext, String password, String ivString, String saltString) throws Exception {
        byte[] salt = Base64.getDecoder().decode(saltString);
        SecretKey key = generateAESKey(password, salt);

        byte[] iv = Base64.getDecoder().decode(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    private static SecretKey generateAESKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    // ========== RSA ENCRYPTION/DECRYPTION ==========
    public static String[] generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        return new String[]{publicKey, privateKey};
    }

    public static String encryptRSA(String plaintext, String publicKeyStr) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        if (plaintextBytes.length > 190) {
            throw new IllegalArgumentException("Plaintext too long for RSA encryption. Max is 190 bytes.");
        }

        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public static String decryptRSA(String ciphertext, String privateKeyStr) throws Exception {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);

        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // ========== HYBRID ENCRYPTION (RSA + AES) ==========
    public static String[] encryptHybrid(String message, String publicKeyStr) throws Exception {
        // Generate random AES key
        String aesKey = generateRandomAESKey();

        // Encrypt AES key with RSA
        String encryptedAESKey = encryptRSA(aesKey, publicKeyStr);

        // Encrypt message with AES using the key directly (not password-based)
        String[] aesResult = encryptWithAESKey(message, aesKey);
        String encryptedMessage = aesResult[0];
        String iv = aesResult[1];

        return new String[]{encryptedMessage, encryptedAESKey, iv};
    }

    public static String decryptHybrid(String encryptedMessage, String encryptedAESKey,
                                       String iv, String privateKeyStr) throws Exception {
        // Decrypt AES key with RSA
        String aesKey = decryptRSA(encryptedAESKey, privateKeyStr);

        // Decrypt message with AES key
        return decryptWithAESKey(encryptedMessage, aesKey, iv);
    }

    // ========== AES WITH DIRECT KEY ==========
    private static String generateRandomAESKey() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[32]; // 256 bits
        random.nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    private static String[] encryptWithAESKey(String plaintext, String aesKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(aesKeyBase64);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new String[]{
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(iv)
        };
    }

    private static String decryptWithAESKey(String ciphertext, String aesKeyBase64, String ivString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(aesKeyBase64);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = Base64.getDecoder().decode(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // ========== PASSWORD-BASED ENCRYPTION ==========
    public static String encryptWithPassword(String data, String password) throws Exception {
        // Generate salt and IV
        byte[] salt = new byte[16];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        // Generate key from password and salt
        SecretKey key = generateAESKey(password, salt);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        // Combine salt, iv, and ciphertext
        byte[] combined = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(iv, 0, combined, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, combined, salt.length + iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptWithPassword(String encryptedData, String password) throws Exception {
        // Decode combined data
        byte[] combined = Base64.getDecoder().decode(encryptedData);

        // Extract salt (first 16 bytes), iv (next 16 bytes), and ciphertext (rest)
        byte[] salt = new byte[16];
        byte[] iv = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[combined.length - salt.length - iv.length];

        System.arraycopy(combined, 0, salt, 0, salt.length);
        System.arraycopy(combined, salt.length, iv, 0, iv.length);
        System.arraycopy(combined, salt.length + iv.length, ciphertext, 0, ciphertext.length);

        // Generate key and decrypt
        SecretKey key = generateAESKey(password, salt);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // ========== SIMPLE ENCRYPTION FOR TESTING ==========
    public static String[] encryptSimple(String plaintext, String sharedSecret) throws Exception {
        // Use fixed salt for shared secret
        byte[] salt = "SimpleChatSalt12345".getBytes(StandardCharsets.UTF_8);

        // Generate key from shared secret
        SecretKey key = generateAESKey(sharedSecret, salt);

        // Generate IV
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new String[]{
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(iv)
        };
    }

    public static String decryptSimple(String ciphertext, String sharedSecret, String ivString) throws Exception {
        // Use same fixed salt
        byte[] salt = "SimpleChatSalt12345".getBytes(StandardCharsets.UTF_8);

        // Generate key from shared secret
        SecretKey key = generateAESKey(sharedSecret, salt);

        // Decrypt
        byte[] iv = Base64.getDecoder().decode(ivString);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plaintextBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    // ========== UTILITY METHODS ==========
    public static String generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return Base64.getEncoder().encodeToString(iv);
    }

    public static String generateMessageId() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Test method
    public static void testEncryption() {
        try {
            System.out.println("=== Testing Encryption ===");

            // Test AES encryption
            String testMessage = "Hello, World!";
            String password = "test123";
            String[] aesResult = encryptAES(testMessage, password);
            String decrypted = decryptAES(aesResult[0], password, aesResult[1], aesResult[2]);
            System.out.println("AES Test: " + (testMessage.equals(decrypted) ? "PASSED" : "FAILED"));

            // Test RSA encryption
            String[] rsaKeys = generateRSAKeyPair();
            String rsaEncrypted = encryptRSA(testMessage, rsaKeys[0]);
            String rsaDecrypted = decryptRSA(rsaEncrypted, rsaKeys[1]);
            System.out.println("RSA Test: " + (testMessage.equals(rsaDecrypted) ? "PASSED" : "FAILED"));

            // Test Hybrid encryption
            String[] hybridResult = encryptHybrid(testMessage, rsaKeys[0]);
            String hybridDecrypted = decryptHybrid(hybridResult[0], hybridResult[1], hybridResult[2], rsaKeys[1]);
            System.out.println("Hybrid Test: " + (testMessage.equals(hybridDecrypted) ? "PASSED" : "FAILED"));

            // Test Simple encryption
            String[] simpleResult = encryptSimple(testMessage, "shared_secret");
            String simpleDecrypted = decryptSimple(simpleResult[0], "shared_secret", simpleResult[1]);
            System.out.println("Simple Test: " + (testMessage.equals(simpleDecrypted) ? "PASSED" : "FAILED"));

            System.out.println("=== All Tests Completed ===");

        } catch (Exception e) {
            System.err.println("Encryption test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        testEncryption();
    }
}