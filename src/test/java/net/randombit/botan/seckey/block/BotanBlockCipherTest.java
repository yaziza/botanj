/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.block;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@DisplayName("Botan block ciphers tests")
public class BotanBlockCipherTest {

    private static final Logger LOG = LogManager.getLogger(BotanBlockCipherTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_padding.csv", "/seckey/block/cbc_no_padding.csv",
            "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test cipher block size")
    public void testCipherBlockSize(String algorithm, int blockSize, int keySize) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        cipher.init(Cipher.ENCRYPT_MODE, key);

        assertEquals(blockSize, cipher.getBlockSize(),
                "Cipher block size mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test cipher parameters IV set")
    public void testCipherParametersWithIv(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        AlgorithmParameters parameters = cipher.getParameters();

        String baseCipher = algorithm.substring(0, algorithm.indexOf('/'));
        assertEquals(baseCipher, parameters.getAlgorithm(), "Cipher name mismatch: " + baseCipher);
    }

    @Test
    @DisplayName("Test unsupported padding algorithm")
    public void testUnsupportedPaddingAlgorithm() {
        final String padding = "some padding";

        final Exception exception = assertThrows(NoSuchPaddingException.class, () ->
                Cipher.getInstance("AES/CBC/" + padding, BotanProvider.NAME)
        );

        assertEquals("Padding algorithm not supported: " + padding, exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test calling cipher update before initialization")
    public void testCipherUpdateWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.update(new byte[128]));

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/seckey/block/cfb_no_padding.csv", numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal before initialization")
    public void testCipherDoFinalWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

        assertEquals("Cipher not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal without input (No Padding)")
    public void testCipherDoFinalWithoutInputNoPadding(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        final byte[] output = cipher.doFinal();

        assertEquals(0, output.length, "doFinal without input should produce no output");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal with output offset")
    public void testCipherDoFinalWithOutputOffset(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        final byte[] output = new byte[64];
        final int outputOffset = 22;

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        int outputLength = cipher.doFinal(new byte[blockSize], 0, blockSize, output, outputOffset);

        assertNotEquals(outputLength, output.length, "Cipher doFinal should only encrypt from offset");
        assertEquals(outputLength, blockSize, "Cipher doFinal output length mismatch");

        // 0 to outputOffset must stay the same
        assertArrayEquals(new byte[outputOffset], Arrays.copyOfRange(output, 0, outputOffset));

        // outputOffset + block size to array end must stay the same
        assertArrayEquals(new byte[output.length - outputOffset - blockSize],
                Arrays.copyOfRange(output, outputOffset + blockSize, output.length));

        // data from outputOffset must be encrypted
        assertArrayEquals(cipher.doFinal(new byte[blockSize]),
                Arrays.copyOfRange(output, outputOffset, outputOffset + blockSize));
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/seckey/block/cbc_padding.csv", numLinesToSkip = 1)
    @DisplayName("Test calling cipher doFinal without input (With Padding)")
    public void testCipherDoFinalWithoutInputWithPadding(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        final byte[] output = cipher.doFinal();

        assertEquals(blockSize, output.length, "doFinal without input should produce no output");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_padding.csv", "/seckey/block/cfb_no_padding.csv",
            "/seckey/block/cfb_no_padding.csv"}, numLinesToSkip = 1)
    @DisplayName("Test encrypting then decrypting cipher")
    public void testEncryptThenDecrypt(String algorithm, int blockSize, int keySize) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        final byte[] expected = "some plain text to be encrypted.".getBytes();

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        final byte[] cipherText = cipher.doFinal(expected);

        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        final byte[] plainText = cipher.doFinal(cipherText);

        assertArrayEquals(expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test cipher encrypt(no padding) against bouncy castle")
    public void testEncryptNoPaddingAgainstBouncyCastle(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        bc.init(Cipher.ENCRYPT_MODE, key, iv);
        botan.init(Cipher.ENCRYPT_MODE, key, iv);

        final byte[] input = new byte[blockSize * Byte.SIZE * 10];

        byte[] expected = bc.doFinal(input);
        byte[] actual = botan.doFinal(input);

        assertArrayEquals(expected, actual, "Encryption mismatch with Bouncy Castle provider for algorithm "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/seckey/block/cbc_no_padding.csv", numLinesToSkip = 1)
    @DisplayName("Test cipher data not block size aligned")
    public void testEncryptDataNotBlockSizeAligned(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        cipher.update(new byte[2]);

        Exception exception = assertThrows(IllegalBlockSizeException.class, () -> cipher.doFinal());
        assertEquals("Data not block size aligned", exception.getMessage());

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        exception = assertThrows(IllegalBlockSizeException.class, () -> cipher.doFinal(new byte[1]));
        assertEquals("Data not block size aligned", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/seckey/block/cbc_padding.csv", numLinesToSkip = 1)
    @DisplayName("Test cipher correct padding length")
    public void testCorrectPaddingLength(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] output = cipher.doFinal(new byte[0]);

        assertEquals(blockSize, output.length, "Cipher padding incorrect size");

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        output = cipher.doFinal(new byte[blockSize]);

        assertEquals(blockSize * 2, output.length, "Cipher padding incorrect size");
    }

    @ParameterizedTest
    @CsvFileSource(resources = {"/seckey/block/cbc_test_vectors.csv", "/seckey/block/cfb_test_vectors.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test block cipher encryption with test vectors")
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
    @CsvFileSource(resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
            numLinesToSkip = 1)
    @DisplayName("Test Botan performance against Bouncy Castle")
    public void testBotanPerformanceAgainstBouncyCastle(String algorithm, int blockSize, int keySize)
            throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final AlgorithmParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.NAME);

        bc.init(Cipher.ENCRYPT_MODE, key, iv);
        botan.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] input = new byte[10_240];

        final long startBc = System.nanoTime();
        final byte[] expected = bc.doFinal(input);
        final long endBc = System.nanoTime();

        final long startBotan = System.nanoTime();
        final byte[] actual = botan.doFinal(input);
        final long endBotan = System.nanoTime();

        double difference = (endBc - startBc) - (endBotan - startBotan);
        difference /= (endBc - startBc);
        difference *= 100;

        LOG.info(new StringFormattedMessage(
                "Performance against Bouncy Castle for algorithm with key size: %s(%d): %.2f %%",
                algorithm, keySize, difference));

        assertArrayEquals(expected, actual, "Cipher mismatch with Bouncy Castle provider for algorithm "
                + algorithm);
    }

}
