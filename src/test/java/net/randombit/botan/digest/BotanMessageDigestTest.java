/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@DisplayName("Botan message digest tests")
public class BotanMessageDigestTest {

    private static final Logger LOG = LogManager.getLogger(BotanMessageDigestTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test digest output size")
    public void testDigestOutputSize(String algorithm, int size) throws GeneralSecurityException {
        final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
        final byte[] output = digest.digest("Some input".getBytes());

        assertEquals(size, digest.getDigestLength(), "Output size mismatch for algorithm: " + algorithm);
        assertEquals(size, output.length, "Output size mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test digest output against Bouncy Castle")
    public void testAgainstBouncyCastle(String algorithm) throws GeneralSecurityException {
        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        final byte[] expected = bc.digest("hello world".getBytes());
        final byte[] actual = botan.digest("hello world".getBytes());

        assertArrayEquals(expected, actual, "Digest mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test clone digest")
    public void testCloneDigest(String algorithm) throws GeneralSecurityException, CloneNotSupportedException {
        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
        final MessageDigest clone = (MessageDigest) botan.clone();

        final byte[] expected = bc.digest("Clone supported".getBytes());
        final byte[] actual = clone.digest("Clone supported".getBytes());

        assertArrayEquals(expected, actual, "Digest mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test rest digest")
    public void testRestDigest(String algorithm) throws GeneralSecurityException {
        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        botan.update("to reset".getBytes());
        botan.reset();

        bc.update("Rest support".getBytes());
        botan.update("Rest support".getBytes());

        final byte[] expected = bc.digest();
        final byte[] actual = botan.digest();

        assertArrayEquals(expected, actual, "Digest mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test digest single byte update")
    public void testSingleByteUpdate(String algorithm) throws GeneralSecurityException {
        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        botan.update((byte) 'H');
        botan.update((byte) 'e');
        botan.update((byte) 'l');
        botan.update((byte) 'l');
        botan.update((byte) 'o');

        bc.update("Hello".getBytes());

        final byte[] expected = bc.digest();
        final byte[] actual = botan.digest();

        assertArrayEquals(expected, actual, "Digest mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/test_vectors.csv", numLinesToSkip = 1)
    @DisplayName("Test digests against test vectors")
    public void testAgainstTestVectors(String algorithm, String in, String out) throws NoSuchProviderException,
            NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        final byte[] input = HexUtils.decode(in);
        final byte[] expected = HexUtils.decode(out);

        final byte[] actual = digest.digest(input);

        assertArrayEquals(expected, actual, "Digest mismatch with test vector");
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
    @DisplayName("Test Botan performance against Bouncy Castle")
    public void testBotanPerformance(String algorithm) throws GeneralSecurityException {
        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        final long startBc = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            bc.update("some input".getBytes());
        }
        final byte[] expected = bc.digest();
        final long endBc = System.nanoTime();

        final long startBotan = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            botan.update("some input".getBytes());
        }
        final byte[] actual = botan.digest();
        final long endBotan = System.nanoTime();

        double difference = (endBc - startBc) - (endBotan - startBotan);
        difference /= (endBc - startBc);
        difference *= 100;

        LOG.info(new StringFormattedMessage(
                "Performance against Bouncy Castle for algorithm %s: %.2f %%",
                algorithm, difference));

        assertArrayEquals(expected, actual, "Digest mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

}
