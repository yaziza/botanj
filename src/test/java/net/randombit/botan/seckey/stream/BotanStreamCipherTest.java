/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.ValueSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;

@DisplayName("Botan stream ciphers tests")
public class BotanStreamCipherTest {

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv",
            "/seckey/stream/ctr.csv", "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling cipher update before initialization")
    public void testCipherUpdateWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.update(new byte[122]));

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv",
            "/seckey/stream/ctr.csv", "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal before initialization")
    public void testCipherDoFinalWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ChaCha20/None/NoPadding", "Salsa20/None/NoPadding", "XChaCha20/None/NoPadding",
            "XSalsa20/None/NoPadding"})
    @DisplayName("Test calling (X)SALSA/(X)CHACHA cipher with empty nonce")
    public void testCipherWithEmptyNonce(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "ChaCha20");

        // empty nonce not allowed for (X)SALSA/(X)CHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[0])));
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv", "/seckey/stream/ctr.csv",
            "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling doFinal with empty input")
    public void testDoFinalEmptyInput(String algorithm, String key, String nonce) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec iv = new IvParameterSpec(HexUtils.decode(nonce));

        final byte[] expected = new byte[0];

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final byte[] cipherText = cipher.doFinal(expected);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        final byte[] plainText = cipher.doFinal(cipherText);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv", "/seckey/stream/ctr.csv",
            "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test encrypting then decrypting cipher")
    public void testEncryptThenDecrypt(String algorithm, String key, String nonce) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec iv = new IvParameterSpec(HexUtils.decode(nonce));

        final byte[] expected = "some plain text to be encrypted.".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final byte[] cipherText = cipher.doFinal(expected);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        final byte[] plainText = cipher.doFinal(cipherText);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv", "/seckey/stream/ctr.csv",
            "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test stream cipher encryption with test vectors")
    public void testCipherWithTestVectors(String algorithm, String key, String iv, String in, String out)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec ivBytes = new IvParameterSpec(HexUtils.decode(iv));

        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, ivBytes);

        byte[] cipherText = cipher.doFinal(HexUtils.decode(in));

        assertArrayEquals(HexUtils.decode(out), cipherText, "Encryption mismatch with test vector");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv", "/seckey/stream/ctr.csv",
            "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test update working with cipher offset")
    public void testUpdateWithOffset(String algorithm, String key, String nonce)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec iv = new IvParameterSpec(HexUtils.decode(nonce));

        final byte[] input = "----some plain text to be encrypted.----".getBytes();
        final byte[] expected = "some plain text to be encrypted.".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final byte[] cipherText = cipher.update(input, 4, input.length - 8);
        cipher.doFinal();

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        final byte[] plainText = cipher.update(cipherText, 0, cipherText.length);
        cipher.doFinal();

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/stream/salsa20.csv", "/seckey/stream/chacha20.csv", "/seckey/stream/ctr.csv",
            "/seckey/stream/ofb.csv"}, numLinesToSkip = 1)
    @DisplayName("Test doFinal working with cipher offset")
    public void testDoFinalWithOffset(String algorithm, String key, String nonce)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final IvParameterSpec iv = new IvParameterSpec(HexUtils.decode(nonce));

        final byte[] input = "----some plain text to be encrypted.----".getBytes();
        final byte[] expected = "some plain text to be encrypted.".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        final byte[] cipherText = cipher.doFinal(input, 4, input.length - 8);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        final byte[] plainText = cipher.doFinal(cipherText, 0, cipherText.length);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @Test
    @DisplayName("Test calling SALSA20 cipher with valid nonce")
    public void testSalsa20WithValidNonce() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("Salsa20/None/NoPadding", BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "Salsa20");

        // 8 byte nonce allowed for SALSA20
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[8]));

        // only 24 byte nonce is allowed for SALSA20
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[24]));
    }

    @Test
    @DisplayName("Test calling SALSA20 cipher with invalid nonce")
    public void testSalsa20WithInvalidNonce() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("Salsa20/None/NoPadding", BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "Salsa20");

        // 12 byte nonce allowed for SALSA20
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[12])));
    }

    @Test
    @DisplayName("Test calling CHACHA20 cipher with valid nonce")
    public void testChacha20WithValidNonce() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("Chacha20/None/NoPadding", BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "ChaCha20");

        // 8 byte nonce allowed for SALSA/CHACHA
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[8]));

        // 12 byte nonce allowed for SALSA/CHACHA
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[12]));

        // only 24 byte nonce is allowed for SALSA/CHACHA
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[24]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"ChaCha20/None/NoPadding", "Salsa20/None/NoPadding"})
    @DisplayName("Test calling SALSA/CHACHA cipher with invalid nonce")
    public void testCipherWithInvalidNonce(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "ChaCha20");

        // 6 byte nonce not allowed for SALSA/CHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[6])));

        // 32 byte nonce allowed for SALSA/CHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[32])));
    }

    @ParameterizedTest
    @ValueSource(strings = {"XChaCha20/None/NoPadding", "XSalsa20/None/NoPadding"})
    @DisplayName("Test calling XSALSA/XCHACHA cipher with invalid eXtended nonce")
    public void testCipherWithInvalidExtendedNonce(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec keyBytes = new SecretKeySpec(new byte[16], "XChaCha20");

        // 8 byte nonce not allowed for XSALSA/XCHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[8])));

        // 12 byte nonce not allowed for XSALSA/XCHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[12])));

        // 16 byte nonce not allowed for XSALSA/XCHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[16])));

        // 32 byte nonce not allowed for XSALSA/XCHACHA
        assertThrows(InvalidAlgorithmParameterException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, keyBytes,
                new IvParameterSpec(new byte[32])));

        // only 24 byte nonce is allowed for XSALSA/XCHACHA
        cipher.init(Cipher.ENCRYPT_MODE, keyBytes, new IvParameterSpec(new byte[24]));
    }

}
