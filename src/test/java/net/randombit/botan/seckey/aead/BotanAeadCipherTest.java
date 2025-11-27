/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.aead;

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
import net.randombit.botan.util.PaddingAlgorithm;

@DisplayName("Botan AEAD ciphers modes tests")
public class BotanAeadCipherTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/aead/ccm_no_padding.csv", "/seckey/aead/eax_no_padding.csv",
            "/seckey/aead/gcm_no_padding.csv", "/seckey/aead/ocb_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test cipher block size")
    public void testCipherBlockSize(String algorithm, String key) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyInBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, keyInBytes);

        assertEquals(16, cipher.getBlockSize(),
                "Cipher block size mismatch for algorithm: " + algorithm);
    }

    @Test
    @DisplayName("Test unsupported padding algorithm")
    public void testUnsupportedPaddingAlgorithm() {
        final String padding = PaddingAlgorithm.PKCS5_PADDING.getName();

        final Exception exception = assertThrows(NoSuchPaddingException.class, () ->
                Cipher.getInstance("AES/GCM/" + padding, BotanProvider.NAME)
        );

        assertEquals("Padding algorithm PKCS5 not allowed for mode GCM", exception.getMessage());
    }

    @Test
    @DisplayName("Test calling cipher update before initialization")
    public void testCipherUpdateWithoutInitialization() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.update(new byte[128]));

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @Test
    @DisplayName("Test calling cipher doFinal before initialization")
    public void testCipherDoFinalWithoutInitialization() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/aead/ccm_no_padding.csv", "/seckey/aead/eax_no_padding.csv",
            "/seckey/aead/gcm_no_padding.csv", "/seckey/aead/ocb_no_padding.csv"}, numLinesToSkip = 1)
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
    @CsvFileSource(resources = {"/seckey/aead/ccm_no_padding.csv", "/seckey/aead/eax_no_padding.csv",
            "/seckey/aead/gcm_no_padding.csv", "/seckey/aead/ocb_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test encrypt then decrypt")
    public void testEncryptThenDecrypt(String algorithm, String key, String nonce, String ad) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final GCMParameterSpec nonceBytes = new GCMParameterSpec(128, HexUtils.decode(nonce));

        final byte[] expected = "some plain text to be encrypted.".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, nonceBytes);
        cipher.updateAAD(HexUtils.decode(ad));
        final byte[] cipherText = cipher.doFinal(expected);

        cipher.init(Cipher.DECRYPT_MODE, keyBytes, nonceBytes);
        cipher.updateAAD(HexUtils.decode(ad));
        final byte[] plainText = cipher.doFinal(cipherText);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/aead/ccm_no_padding.csv", "/seckey/aead/eax_no_padding.csv",
            "/seckey/aead/gcm_no_padding.csv", "/seckey/aead/ocb_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test AEAD cipher encryption with test vectors")
    public void testCipherWithTestVectors(String algorithm, String key, String nonce, String ad, String in, String out)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final GCMParameterSpec ivBytes = new GCMParameterSpec(128, HexUtils.decode(nonce));

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, ivBytes);
        cipher.updateAAD(HexUtils.decode(ad));

        byte[] cipherText = cipher.doFinal(HexUtils.decode(in));

        assertArrayEquals(HexUtils.decode(out), cipherText, "Encryption mismatch with test vector");
    }

    @Test
    @DisplayName("Test GCM with invalid tag length")
    public void testGcmInvalidTagLength() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test invalid tag length (64 bits - not supported by GCM)
        final GCMParameterSpec invalidParams = new GCMParameterSpec(64, nonce);

        assertThrows(IllegalArgumentException.class, () -> {
            cipher.init(Cipher.ENCRYPT_MODE, key, invalidParams);
        }, "Should reject invalid tag length");
    }

    @Test
    @DisplayName("Test GCM with valid tag lengths")
    public void testGcmValidTagLengths() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        final byte[] nonce = new byte[12];

        // Test all valid GCM tag lengths: 96, 104, 112, 120, 128
        int[] validTagLengths = {96, 104, 112, 120, 128};

        for (int tagLen : validTagLengths) {
            final GCMParameterSpec params = new GCMParameterSpec(tagLen, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            // If we get here without exception, the tag length is accepted
        }
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
    @Disabled
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
    @Disabled
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
    @Disabled
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

}
