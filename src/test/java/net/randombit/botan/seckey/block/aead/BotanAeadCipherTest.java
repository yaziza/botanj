/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.block.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import net.randombit.botan.spec.AeadParameterSpec;
import net.randombit.botan.util.PaddingAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@DisplayName("Botan AEAD ciphers modes tests")
public class BotanAeadCipherTest {

    private static final Logger LOG = LogManager.getLogger(BotanAeadCipherTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        // Add Bouncy Castle provider if available
        try {
            Security.addProvider((java.security.Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance());
            LOG.info("Bouncy Castle provider added successfully");
        } catch (Exception e) {
            LOG.warn("Bouncy Castle provider not available: {}", e.getMessage());
        }
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/aead/ccm_no_padding.csv", "/seckey/block/aead/eax_no_padding.csv",
            "/seckey/block/aead/gcm_no_padding.csv", "/seckey/block/aead/ocb_no_padding.csv",
            "/seckey/block/aead/siv_no_padding.csv", "/seckey/block/aead/chacha20poly1305_no_padding.csv",
            "/seckey/block/aead/xchacha20poly1305_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test cipher block size")
    public void testCipherBlockSize(String algorithm, String key) throws GeneralSecurityException {
        LOG.info("=== Test: Cipher block size for {} ===", algorithm);
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyInBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);

        LOG.info("Key size: {} bytes", HexUtils.decode(key).length);
        cipher.init(Cipher.ENCRYPT_MODE, keyInBytes);

        LOG.info("Block size: {} bytes", cipher.getBlockSize());

        // ChaCha20-Poly1305 and XChaCha20-Poly1305 have 64-byte block size
        int expectedBlockSize = (algorithm.contains("ChaCha20")) ? 64 : 16;
        assertEquals(expectedBlockSize, cipher.getBlockSize(),
                "Cipher block size mismatch for algorithm: " + algorithm);
        LOG.info("SUCCESS: Block size is {} bytes for {}", expectedBlockSize, algorithm);
    }

    @Test
    @DisplayName("Test unsupported padding algorithm")
    public void testUnsupportedPaddingAlgorithm() {
        LOG.info("=== Test: Unsupported padding algorithm for AEAD ===");
        final String padding = PaddingAlgorithm.PKCS5_PADDING.getName();
        LOG.info("Attempting to use {} padding with AES/GCM", padding);

        final Exception exception = assertThrows(NoSuchPaddingException.class, () ->
                Cipher.getInstance("AES/GCM/" + padding, BotanProvider.NAME)
        );

        assertEquals("Padding algorithm PKCS5 not allowed for mode GCM", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected padding for AEAD mode");
    }

    @Test
    @DisplayName("Test calling cipher update before initialization")
    public void testCipherUpdateWithoutInitialization() throws GeneralSecurityException {
        LOG.info("=== Test: Cipher update without initialization ===");
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);

        LOG.info("Attempting update without initialization...");
        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.update(new byte[128]));

        assertEquals("Cipher not initialized", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected uninitialized update");
    }

    @Test
    @DisplayName("Test calling cipher doFinal before initialization")
    public void testCipherDoFinalWithoutInitialization() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/aead/ccm_no_padding.csv", "/seckey/block/aead/eax_no_padding.csv",
            "/seckey/block/aead/gcm_no_padding.csv", "/seckey/block/aead/ocb_no_padding.csv",
            "/seckey/block/aead/siv_no_padding.csv", "/seckey/block/aead/chacha20poly1305_no_padding.csv",
            "/seckey/block/aead/xchacha20poly1305_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal without input (No Padding)")
    public void testCipherDoFinalWithoutInputNoPadding(String algorithm, String key, String nonce)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec nonceBytes = new IvParameterSpec(HexUtils.decode(nonce));

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, nonceBytes);
        cipher.updateAAD("adfn".getBytes());
        final byte[] output = cipher.doFinal();

        assertEquals(16, output.length, "doFinal without input should produce TAG");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/aead/ccm_no_padding.csv", "/seckey/block/aead/eax_no_padding.csv",
            "/seckey/block/aead/gcm_no_padding.csv", "/seckey/block/aead/ocb_no_padding.csv",
            "/seckey/block/aead/siv_no_padding.csv", "/seckey/block/aead/chacha20poly1305_no_padding.csv",
            "/seckey/block/aead/xchacha20poly1305_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test encrypt then decrypt")
    public void testEncryptThenDecrypt(String algorithm, String key, String nonce, String ad) throws GeneralSecurityException {
        LOG.info("=== Test: Encrypt then decrypt for {} ===", algorithm);
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final GCMParameterSpec nonceBytes = new GCMParameterSpec(128, HexUtils.decode(nonce));

        final byte[] expected = "some plain text to be encrypted.".getBytes();
        LOG.info("Plaintext: {} bytes", expected.length);
        LOG.info("Additional data: {} bytes", HexUtils.decode(ad).length);

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, nonceBytes);
        cipher.updateAAD(HexUtils.decode(ad));
        final byte[] cipherText = cipher.doFinal(expected);
        LOG.info("Ciphertext: {} bytes (includes tag)", cipherText.length);

        cipher.init(Cipher.DECRYPT_MODE, keyBytes, nonceBytes);
        cipher.updateAAD(HexUtils.decode(ad));
        final byte[] plainText = cipher.doFinal(cipherText);
        LOG.info("Decrypted: {} bytes", plainText.length);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
        LOG.info("SUCCESS: Round-trip encrypt/decrypt successful for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/aead/ccm_no_padding.csv", "/seckey/block/aead/eax_no_padding.csv",
            "/seckey/block/aead/gcm_no_padding.csv", "/seckey/block/aead/ocb_no_padding.csv",
            "/seckey/block/aead/siv_no_padding.csv", "/seckey/block/aead/chacha20poly1305_no_padding.csv",
            "/seckey/block/aead/xchacha20poly1305_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test AEAD cipher encryption with test vectors")
    public void testCipherWithTestVectors(String algorithm, String key, String nonce, String ad, String in, String out)
            throws GeneralSecurityException {
        LOG.info("=== Test: {} with test vector ===", algorithm);
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final GCMParameterSpec ivBytes = new GCMParameterSpec(128, HexUtils.decode(nonce));

        LOG.info("Key: {} bytes", HexUtils.decode(key).length);
        LOG.info("Nonce: {} bytes", HexUtils.decode(nonce).length);
        LOG.info("AAD: {} bytes", HexUtils.decode(ad).length);
        LOG.info("Input: {} bytes", HexUtils.decode(in).length);

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, ivBytes);
        cipher.updateAAD(HexUtils.decode(ad));

        byte[] cipherText = cipher.doFinal(HexUtils.decode(in));
        LOG.info("Expected output: {} bytes", HexUtils.decode(out).length);
        LOG.info("Actual output: {} bytes", cipherText.length);

        assertArrayEquals(HexUtils.decode(out), cipherText, "Encryption mismatch with test vector");
        LOG.info("SUCCESS: {} matches test vector", algorithm);
    }

    @Test
    @DisplayName("Test GCM with invalid tag length")
    public void testGcmInvalidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: GCM with invalid tag length ===");
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test invalid tag length (64 bits - not supported by GCM)
        LOG.info("Testing invalid tag length: 64 bits");
        final GCMParameterSpec invalidParams = new GCMParameterSpec(64, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length");
        LOG.info("SUCCESS: Properly rejected invalid GCM tag length");
    }

    @Test
    @DisplayName("Test GCM with valid tag lengths")
    public void testGcmValidTagLengths() throws GeneralSecurityException {
        LOG.info("=== Test: GCM with valid tag lengths ===");
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test all valid GCM tag lengths: 96, 104, 112, 120, 128
        int[] validTagLengths = {96, 104, 112, 120, 128};
        LOG.info("Testing valid GCM tag lengths: {}", validTagLengths);

        for (int tagLen : validTagLengths) {
            LOG.info("  Testing tag length: {} bits", tagLen);
            final GCMParameterSpec params = new GCMParameterSpec(tagLen, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            // If we get here without exception, the tag length is accepted
        }
        LOG.info("SUCCESS: All valid GCM tag lengths accepted");
    }

    @Test
    @DisplayName("Test CCM with invalid tag length")
    public void testCcmInvalidTagLength() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test invalid tag length (100 bits - not a multiple of 16)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(100, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length");
    }

    @Test
    @DisplayName("Test CCM with valid tag lengths")
    public void testCcmValidTagLengths() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test all valid CCM tag lengths: 32, 48, 64, 80, 96, 112, 128 (multiples of 16)
        int[] validTagLengths = {32, 48, 64, 80, 96, 112, 128};

        for (int tagLen : validTagLengths) {
            final GCMParameterSpec params = new GCMParameterSpec(tagLen, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            // If we get here without exception, the tag length is accepted
        }
    }

    @Test
    @DisplayName("Test OCB with invalid tag length")
    public void testOcbInvalidTagLength() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test invalid tag length (80 bits - OCB only supports 64, 96, 128)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(80, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length for OCB");
    }

    @Test
    @DisplayName("Test OCB with valid tag lengths")
    public void testOcbValidTagLengths() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test all valid OCB tag lengths: 64, 96, 128
        int[] validTagLengths = {64, 96, 128};

        for (int tagLen : validTagLengths) {
            final GCMParameterSpec params = new GCMParameterSpec(tagLen, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            // If we get here without exception, the tag length is accepted
        }
    }

    @Test
    @DisplayName("Test EAX with invalid tag length")
    public void testEaxInvalidTagLength() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];

        // Test invalid tag length (140 bits - exceeds maximum of 128)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(140, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject tag length exceeding 128 bits for EAX");
    }

    @Test
    @DisplayName("Test EAX with invalid tag length not multiple of 8")
    public void testEaxInvalidTagLengthNotMultipleOf8() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];

        // Test invalid tag length (65 bits - not a multiple of 8)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(65, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject tag length not multiple of 8 for EAX");
    }

    @Test
    @DisplayName("Test EAX with valid tag lengths")
    public void testEaxValidTagLengths() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];

        // Test valid EAX tag lengths: multiples of 8 from 8 to 128
        int[] validTagLengths = {8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128};

        for (int tagLen : validTagLengths) {
            final GCMParameterSpec params = new GCMParameterSpec(tagLen, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            // If we get here without exception, the tag length is accepted
        }
    }

    @Test
    @DisplayName("Test nonce reuse vulnerability with multiple doFinal calls")
    public void testNonceReuseWithMultipleDoFinal() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt same plaintext twice without re-init
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);

        assertThrows(IllegalStateException.class, () -> {
            cipher.doFinal(plaintext);
        }, "Should reject doFinal() with nonce reuse without re-initialization");
    }

    @Test
    @DisplayName("Test nonce reuse vulnerability with multiple doFinal calls")
    public void testNonceReuseWithUpdateAfterDoFinal() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt same plaintext twice without re-init
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);

        assertThrows(IllegalStateException.class, () -> {
            cipher.update(plaintext);
        }, "Should reject doFinal() with nonce reuse without re-initialization");
    }

    @Test
    @DisplayName("Test nonce reuse vulnerability with multiple doFinal calls during decryption")
    public void testNonceReuseWithMultipleDoFinalDecryption() throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // First, encrypt two different plaintexts to get two ciphertexts
        byte[] plaintext1 = "First message".getBytes();
        byte[] plaintext2 = "Second message".getBytes();

        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext1 = encryptCipher.doFinal(plaintext1);

        encryptCipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        // Re-initialize with same nonce for second encryption (simulating nonce reuse)
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext2 = encryptCipher.doFinal(plaintext2);

        // Now attempt to decrypt both ciphertexts without re-initializing the decryption cipher
        decryptCipher.init(Cipher.DECRYPT_MODE, key, params);

        // First decryption should succeed
        byte[] decrypted1 = decryptCipher.doFinal(ciphertext1);
        assertArrayEquals(plaintext1, decrypted1, "First decryption should succeed");

        // Second decryption should succeed
        byte[] decrypted2 = decryptCipher.doFinal(ciphertext2);
        assertArrayEquals(plaintext2, decrypted2, "second decryption should succeed");
    }

    @Test
    @DisplayName("Test CCM nonce reuse with multiple doFinal calls")
    public void testCcmNonceReuseWithMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: CCM nonce reuse with multiple doFinal calls ===");
        final Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[11];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        LOG.info("Initialized CCM cipher for encryption");

        // Encrypt first plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt second doFinal without re-initialization
        LOG.info("Attempting second doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.doFinal(plaintext);
        }, "Should reject doFinal() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: CCM properly rejected nonce reuse");
    }

    @Test
    @DisplayName("Test CCM nonce reuse with update after doFinal")
    public void testCcmNonceReuseWithUpdateAfterDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: CCM nonce reuse with update after doFinal ===");
        final Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[11];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt update after doFinal without re-initialization
        LOG.info("Attempting update() after doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.update(plaintext);
        }, "Should reject update() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: CCM properly rejected update after doFinal");
    }

    @Test
    @DisplayName("Test CCM decryption allows multiple doFinal calls")
    public void testCcmDecryptionMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: CCM decryption allows multiple doFinal calls ===");
        Cipher encryptCipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final Cipher decryptCipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[11];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Encrypt two different plaintexts
        byte[] plaintext1 = "First message".getBytes();
        byte[] plaintext2 = "Second message".getBytes();

        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext1 = encryptCipher.doFinal(plaintext1);
        LOG.info("Encrypted first message");

        encryptCipher = Cipher.getInstance("AES/CCM/NoPadding", BotanProvider.NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext2 = encryptCipher.doFinal(plaintext2);
        LOG.info("Encrypted second message");

        // Decrypt both without re-initializing (should succeed in decrypt mode)
        decryptCipher.init(Cipher.DECRYPT_MODE, key, params);

        byte[] decrypted1 = decryptCipher.doFinal(ciphertext1);
        assertArrayEquals(plaintext1, decrypted1, "First decryption should succeed");
        LOG.info("First decryption succeeded");

        byte[] decrypted2 = decryptCipher.doFinal(ciphertext2);
        assertArrayEquals(plaintext2, decrypted2, "Second decryption should succeed");
        LOG.info("SUCCESS: CCM allows multiple decryptions");
    }

    @Test
    @DisplayName("Test EAX nonce reuse with multiple doFinal calls")
    public void testEaxNonceReuseWithMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: EAX nonce reuse with multiple doFinal calls ===");
        final Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        LOG.info("Initialized EAX cipher for encryption");

        // Encrypt first plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt second doFinal without re-initialization
        LOG.info("Attempting second doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.doFinal(plaintext);
        }, "Should reject doFinal() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: EAX properly rejected nonce reuse");
    }

    @Test
    @DisplayName("Test EAX nonce reuse with update after doFinal")
    public void testEaxNonceReuseWithUpdateAfterDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: EAX nonce reuse with update after doFinal ===");
        final Cipher cipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt update after doFinal without re-initialization
        LOG.info("Attempting update() after doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.update(plaintext);
        }, "Should reject update() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: EAX properly rejected update after doFinal");
    }

    @Test
    @DisplayName("Test EAX decryption allows multiple doFinal calls")
    public void testEaxDecryptionMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: EAX decryption allows multiple doFinal calls ===");
        Cipher encryptCipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final Cipher decryptCipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[16];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Encrypt two different plaintexts
        byte[] plaintext1 = "First message".getBytes();
        byte[] plaintext2 = "Second message".getBytes();

        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext1 = encryptCipher.doFinal(plaintext1);
        LOG.info("Encrypted first message");

        encryptCipher = Cipher.getInstance("AES/EAX/NoPadding", BotanProvider.NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext2 = encryptCipher.doFinal(plaintext2);
        LOG.info("Encrypted second message");

        // Decrypt both without re-initializing (should succeed in decrypt mode)
        decryptCipher.init(Cipher.DECRYPT_MODE, key, params);

        byte[] decrypted1 = decryptCipher.doFinal(ciphertext1);
        assertArrayEquals(plaintext1, decrypted1, "First decryption should succeed");
        LOG.info("First decryption succeeded");

        byte[] decrypted2 = decryptCipher.doFinal(ciphertext2);
        assertArrayEquals(plaintext2, decrypted2, "Second decryption should succeed");
        LOG.info("SUCCESS: EAX allows multiple decryptions");
    }

    @Test
    @DisplayName("Test OCB nonce reuse with multiple doFinal calls")
    public void testOcbNonceReuseWithMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: OCB nonce reuse with multiple doFinal calls ===");
        final Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        LOG.info("Initialized OCB cipher for encryption");

        // Encrypt first plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt second doFinal without re-initialization
        LOG.info("Attempting second doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.doFinal(plaintext);
        }, "Should reject doFinal() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: OCB properly rejected nonce reuse");
    }

    @Test
    @DisplayName("Test OCB nonce reuse with update after doFinal")
    public void testOcbNonceReuseWithUpdateAfterDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: OCB nonce reuse with update after doFinal ===");
        final Cipher cipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Initialize once
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt plaintext
        byte[] plaintext = "Hello World!".getBytes();
        cipher.doFinal(plaintext);
        LOG.info("First doFinal() succeeded");

        // Attempt update after doFinal without re-initialization
        LOG.info("Attempting update() after doFinal() without re-initialization...");
        assertThrows(IllegalStateException.class, () -> {
            cipher.update(plaintext);
        }, "Should reject update() with nonce reuse without re-initialization");
        LOG.info("SUCCESS: OCB properly rejected update after doFinal");
    }

    @Test
    @DisplayName("Test OCB decryption allows multiple doFinal calls")
    public void testOcbDecryptionMultipleDoFinal() throws GeneralSecurityException {
        LOG.info("=== Test: OCB decryption allows multiple doFinal calls ===");
        Cipher encryptCipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final Cipher decryptCipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        java.util.Arrays.fill(nonce, (byte) 1);

        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        // Encrypt two different plaintexts
        byte[] plaintext1 = "First message".getBytes();
        byte[] plaintext2 = "Second message".getBytes();

        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext1 = encryptCipher.doFinal(plaintext1);
        LOG.info("Encrypted first message");

        encryptCipher = Cipher.getInstance("AES/OCB/NoPadding", BotanProvider.NAME);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] ciphertext2 = encryptCipher.doFinal(plaintext2);
        LOG.info("Encrypted second message");

        // Decrypt both without re-initializing (should succeed in decrypt mode)
        decryptCipher.init(Cipher.DECRYPT_MODE, key, params);

        byte[] decrypted1 = decryptCipher.doFinal(ciphertext1);
        assertArrayEquals(plaintext1, decrypted1, "First decryption should succeed");
        LOG.info("First decryption succeeded");

        byte[] decrypted2 = decryptCipher.doFinal(ciphertext2);
        assertArrayEquals(plaintext2, decrypted2, "Second decryption should succeed");
        LOG.info("SUCCESS: OCB allows multiple decryptions");
    }

    @Test
    @DisplayName("Test SIV with invalid tag length below 128")
    public void testSivInvalidTagLengthBelow128() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/SIV/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[64], "AES");
        final byte[] nonce = new byte[16];

        // Test invalid tag length (96 bits - SIV only supports 128)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(96, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject tag length below 128 bits for SIV");
    }

    @Test
    @DisplayName("Test SIV with invalid tag length above 128")
    public void testSivInvalidTagLengthAbove128() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/SIV/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[64], "AES");
        final byte[] nonce = new byte[16];

        // Test invalid tag length (256 bits - SIV only supports 128)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(256, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject tag length above 128 bits for SIV");
    }

    @Test
    @DisplayName("Test SIV with valid tag length")
    public void testSivValidTagLength() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/SIV/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[64], "AES");
        final byte[] nonce = new byte[16];

        // Test valid tag length (128 bits - only valid length for SIV)
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        // If we get here without exception, the tag length is accepted
    }

    @Test
    @DisplayName("Test getOutputSize with valid tag length")
    public void testGetOutputSizeWithValidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: getOutputSize with valid tag length ===");
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Get output size for 32 bytes of input
        // Expected: 32 (input) + 16 (tag in bytes: 128 bits / 8) = 48
        int outputSize = cipher.getOutputSize(32);
        LOG.info("Input size: 32 bytes, Output size: {} bytes", outputSize);
        assertEquals(48, outputSize, "Output size should be input size + tag size");
        LOG.info("SUCCESS: getOutputSize returns correct value with valid tag length");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 with invalid tag length")
    public void testChaCha20Poly1305InvalidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 with invalid tag length ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];

        // Test invalid tag length (96 bits - ChaCha20-Poly1305 only supports 128)
        LOG.info("Testing invalid tag length: 96 bits");
        final GCMParameterSpec invalidParams = new GCMParameterSpec(96, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length for ChaCha20-Poly1305");
        LOG.info("SUCCESS: Properly rejected invalid ChaCha20-Poly1305 tag length");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 with valid tag length")
    public void testChaCha20Poly1305ValidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 with valid tag length ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];

        // Test valid tag length (128 bits - only valid length for ChaCha20-Poly1305)
        LOG.info("Testing valid tag length: 128 bits");
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        LOG.info("SUCCESS: ChaCha20-Poly1305 accepted valid tag length");
    }

    @Test
    @DisplayName("Test XChaCha20-Poly1305 with invalid tag length")
    public void testXChaCha20Poly1305InvalidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: XChaCha20-Poly1305 with invalid tag length ===");
        final Cipher cipher = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        final byte[] nonce = new byte[24];

        // Test invalid tag length (96 bits - XChaCha20-Poly1305 only supports 128)
        LOG.info("Testing invalid tag length: 96 bits");
        final GCMParameterSpec invalidParams = new GCMParameterSpec(96, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length for XChaCha20-Poly1305");
        LOG.info("SUCCESS: Properly rejected invalid XChaCha20-Poly1305 tag length");
    }

    @Test
    @DisplayName("Test XChaCha20-Poly1305 with valid tag length")
    public void testXChaCha20Poly1305ValidTagLength() throws GeneralSecurityException {
        LOG.info("=== Test: XChaCha20-Poly1305 with valid tag length ===");
        final Cipher cipher = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        final byte[] nonce = new byte[24];

        // Test valid tag length (128 bits - only valid length for XChaCha20-Poly1305)
        LOG.info("Testing valid tag length: 128 bits");
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        LOG.info("SUCCESS: XChaCha20-Poly1305 accepted valid tag length");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 with invalid nonce length")
    public void testChaCha20Poly1305InvalidNonceLength() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 with invalid nonce length ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[24]; // Wrong size - should be 12

        LOG.info("Testing invalid nonce length: 24 bytes (should be 12)");
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }, "Should reject invalid nonce length for ChaCha20-Poly1305");
        LOG.info("SUCCESS: Properly rejected invalid ChaCha20-Poly1305 nonce length");
    }

    @Test
    @DisplayName("Test XChaCha20-Poly1305 with invalid nonce length")
    public void testXChaCha20Poly1305InvalidNonceLength() throws GeneralSecurityException {
        LOG.info("=== Test: XChaCha20-Poly1305 with invalid nonce length ===");
        final Cipher cipher = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        final byte[] nonce = new byte[12]; // Wrong size - should be 24

        LOG.info("Testing invalid nonce length: 12 bytes (should be 24)");
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        }, "Should reject invalid nonce length for XChaCha20-Poly1305");
        LOG.info("SUCCESS: Properly rejected invalid XChaCha20-Poly1305 nonce length");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 initialization with IvParameterSpec")
    public void testChaCha20Poly1305WithIvParameterSpec() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 with IvParameterSpec ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];

        // Initialize with IvParameterSpec instead of GCMParameterSpec
        LOG.info("Initializing with IvParameterSpec");
        final IvParameterSpec params = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt some data to ensure it works
        byte[] plaintext = "Hello World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        LOG.info("Ciphertext length: {} bytes", ciphertext.length);
        assertEquals(plaintext.length + 16, ciphertext.length, "Ciphertext should include 16-byte tag");
        LOG.info("SUCCESS: ChaCha20-Poly1305 works with IvParameterSpec");
    }

    @Test
    @DisplayName("Test XChaCha20-Poly1305 initialization with IvParameterSpec")
    public void testXChaCha20Poly1305WithIvParameterSpec() throws GeneralSecurityException {
        LOG.info("=== Test: XChaCha20-Poly1305 with IvParameterSpec ===");
        final Cipher cipher = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        final byte[] nonce = new byte[24];

        // Initialize with IvParameterSpec instead of GCMParameterSpec
        LOG.info("Initializing with IvParameterSpec");
        final IvParameterSpec params = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Encrypt some data to ensure it works
        byte[] plaintext = "Hello World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        LOG.info("Ciphertext length: {} bytes", ciphertext.length);
        assertEquals(plaintext.length + 16, ciphertext.length, "Ciphertext should include 16-byte tag");
        LOG.info("SUCCESS: XChaCha20-Poly1305 works with IvParameterSpec");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 update with empty input")
    public void testChaCha20Poly1305UpdateWithEmptyInput() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 update with empty input ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];
        final GCMParameterSpec params = new GCMParameterSpec(128, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);

        // Update with empty input - per JCE spec, should return null
        LOG.info("Calling update with empty input");
        byte[] result = cipher.update(new byte[0]);

        // According to JCE specification, update() returns null when input length is 0
        assertEquals(null, result, "Update with empty input should return null per JCE spec");
        LOG.info("SUCCESS: update with empty input returns null (correct JCE behavior)");
    }

    @Test
    @DisplayName("Test ChaCha20-Poly1305 reinitialization after use")
    public void testChaCha20Poly1305Reinitialization() throws GeneralSecurityException {
        LOG.info("=== Test: ChaCha20-Poly1305 reinitialization after use ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce1 = new byte[12];
        final byte[] nonce2 = new byte[12];
        java.util.Arrays.fill(nonce1, (byte) 1);
        java.util.Arrays.fill(nonce2, (byte) 2);

        // First encryption
        LOG.info("First encryption with nonce1");
        final GCMParameterSpec params1 = new GCMParameterSpec(128, nonce1);
        cipher.init(Cipher.ENCRYPT_MODE, key, params1);
        cipher.updateAAD("aad1".getBytes());
        byte[] plaintext = "Hello World!".getBytes();
        byte[] ciphertext1 = cipher.doFinal(plaintext);
        LOG.info("First ciphertext length: {} bytes", ciphertext1.length);

        // Reinitialize with different nonce and AAD
        LOG.info("Reinitializing with nonce2");
        final GCMParameterSpec params2 = new GCMParameterSpec(128, nonce2);
        cipher.init(Cipher.ENCRYPT_MODE, key, params2);
        cipher.updateAAD("aad2".getBytes());
        byte[] ciphertext2 = cipher.doFinal(plaintext);
        LOG.info("Second ciphertext length: {} bytes", ciphertext2.length);

        // Ciphertexts should be different due to different nonce and AAD
        boolean different = false;
        for (int i = 0; i < Math.min(ciphertext1.length, ciphertext2.length); i++) {
            if (ciphertext1[i] != ciphertext2[i]) {
                different = true;
                break;
            }
        }
        assertEquals(true, different, "Ciphertexts should differ with different nonce/AAD");
        LOG.info("SUCCESS: Reinitialization works correctly");
    }

    @Test
    @DisplayName("Test AeadParameterSpec with ChaCha20-Poly1305")
    public void testAeadParameterSpecWithChaCha20Poly1305() throws GeneralSecurityException {
        LOG.info("=== Test: AeadParameterSpec with ChaCha20-Poly1305 ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];
        final byte[] aad = "additional data".getBytes();

        // Use AeadParameterSpec instead of GCMParameterSpec
        LOG.info("Creating AeadParameterSpec with 12-byte nonce and 128-bit tag");
        final AeadParameterSpec params = new AeadParameterSpec(nonce, 128);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] plaintext = "Hello World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        LOG.info("Plaintext length: {} bytes", plaintext.length);
        LOG.info("Ciphertext length: {} bytes (includes 16-byte tag)", ciphertext.length);

        // Verify ciphertext includes tag
        assertEquals(plaintext.length + 16, ciphertext.length, "Ciphertext should include 16-byte tag");

        // Decrypt to verify
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");
        LOG.info("SUCCESS: AeadParameterSpec works with ChaCha20-Poly1305");
    }

    @Test
    @DisplayName("Test AeadParameterSpec with XChaCha20-Poly1305")
    public void testAeadParameterSpecWithXChaCha20Poly1305() throws GeneralSecurityException {
        LOG.info("=== Test: AeadParameterSpec with XChaCha20-Poly1305 ===");
        final Cipher cipher = Cipher.getInstance("XChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "XChaCha20");
        final byte[] nonce = new byte[24]; // XChaCha20 uses 24-byte nonce
        final byte[] aad = "metadata".getBytes();

        // Use AeadParameterSpec with extended nonce
        LOG.info("Creating AeadParameterSpec with 24-byte nonce and 128-bit tag");
        final AeadParameterSpec params = new AeadParameterSpec(nonce, 128);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] plaintext = "XChaCha20-Poly1305 test".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        LOG.info("Plaintext length: {} bytes", plaintext.length);
        LOG.info("Ciphertext length: {} bytes", ciphertext.length);

        // Decrypt to verify
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");
        LOG.info("SUCCESS: AeadParameterSpec works with XChaCha20-Poly1305");
    }

    @Test
    @DisplayName("Test AeadParameterSpec with AES-GCM")
    public void testAeadParameterSpecWithAesGcm() throws GeneralSecurityException {
        LOG.info("=== Test: AeadParameterSpec with AES-GCM ===");
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];
        final byte[] aad = "header data".getBytes();

        // Use AeadParameterSpec with AES-GCM
        LOG.info("Creating AeadParameterSpec for AES-GCM");
        final AeadParameterSpec params = new AeadParameterSpec(nonce, 128);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] plaintext = "AES-GCM with AeadParameterSpec".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        LOG.info("Encryption successful, ciphertext length: {} bytes", ciphertext.length);

        // Decrypt to verify
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");
        LOG.info("SUCCESS: AeadParameterSpec works with AES-GCM");
    }

    @Test
    @DisplayName("Test AeadParameterSpec without AAD")
    public void testAeadParameterSpecWithoutAAD() throws GeneralSecurityException {
        LOG.info("=== Test: AeadParameterSpec without AAD ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];

        // Use AeadParameterSpec without AAD
        LOG.info("Creating AeadParameterSpec without AAD");
        final AeadParameterSpec params = new AeadParameterSpec(nonce, 128);

        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] plaintext = "No AAD".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        LOG.info("Encryption without AAD successful");

        // Decrypt to verify
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        byte[] decrypted = cipher.doFinal(ciphertext);

        assertArrayEquals(plaintext, decrypted, "Decrypted text should match original");
        LOG.info("SUCCESS: AeadParameterSpec works without AAD");
    }

    @Test
    @DisplayName("Test AeadParameterSpec AAD mismatch detection")
    public void testAeadParameterSpecAADMismatch() throws GeneralSecurityException {
        LOG.info("=== Test: AeadParameterSpec AAD mismatch detection ===");
        final Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[32], "ChaCha20");
        final byte[] nonce = new byte[12];
        final byte[] aad1 = "correct data".getBytes();
        final byte[] aad2 = "wrong data".getBytes();

        // Encrypt with AAD1
        LOG.info("Encrypting with AAD: 'correct data'");
        AeadParameterSpec encryptParams = new AeadParameterSpec(nonce, 128);
        cipher.init(Cipher.ENCRYPT_MODE, key, encryptParams);
        cipher.updateAAD(aad1);
        byte[] plaintext = "Secret message".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Try to decrypt with AAD2 (wrong AAD)
        LOG.info("Attempting to decrypt with AAD: 'wrong data'");
        AeadParameterSpec decryptParams = new AeadParameterSpec(nonce, 128);
        cipher.init(Cipher.DECRYPT_MODE, key, decryptParams);
        cipher.updateAAD(aad2);

        // Should throw exception due to authentication failure
        assertThrows(Exception.class, () -> {
            cipher.doFinal(ciphertext);
        }, "Decryption should fail with wrong AAD");
        LOG.info("SUCCESS: AAD mismatch properly detected");
    }

}
