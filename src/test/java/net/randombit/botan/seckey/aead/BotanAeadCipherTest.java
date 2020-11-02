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

}
