/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@DisplayName("Botan stream ciphers tests")
public class BotanStreamCipherTest {

    private static final Logger LOG = LogManager.getLogger(BotanStreamCipherTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/stream/salsa20.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling cipher update before initialization")
    public void testCipherUpdateWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.update(new byte[122]));

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/stream/salsa20.csv", numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal before initialization")
    public void testCipherDoFinalWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/stream/salsa20.csv", numLinesToSkip = 1)
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
    @CsvFileSource(resources = "/stream/salsa20.csv", numLinesToSkip = 1)
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
}
