/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.aead;

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
import net.randombit.botan.util.PaddingAlgorithm;

@DisplayName("Botan AEAD ciphers modes tests")
public class BotanAeadCipherTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/aead/gcm_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test cipher block size")
    public void testCipherBlockSize(String algorithm, int blockSize, int keySize) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, key);

        assertEquals(blockSize, cipher.getBlockSize(),
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
    @CsvFileSource(resources = {"/seckey/aead/gcm_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal without input (No Padding)")
    public void testCipherDoFinalWithoutInputNoPadding(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        cipher.updateAAD("adfn".getBytes());
        final byte[] output = cipher.doFinal();

        assertEquals(0, output.length, "doFinal without input should produce no output");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/aead/gcm_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal with output offset")
    public void testCipherDoFinal(String algorithm, int blockSize, int keySize) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final GCMParameterSpec iv = new GCMParameterSpec(128, new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        int outputLength = cipher.doFinal(new byte[32]).length;

        assertEquals(outputLength, 32 + 128 / 8, "Cipher doFinal output length mismatch");
    }

}
