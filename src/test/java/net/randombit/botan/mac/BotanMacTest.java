/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@DisplayName("Botan MAC tests")
public class BotanMacTest {

    private static final Logger LOG = LogManager.getLogger(BotanMacTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC output size")
    public void testMacOutputSize(String algorithm, int size) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        mac.init(key);
        final byte[] output = mac.doFinal("some input".getBytes());

        assertEquals(size, mac.getMacLength(), "Output size mismatch for algorithm: " + algorithm);
        assertEquals(size, output.length, "Output size mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC output against Bouncy Castle")
    public void testAgainstBouncyCastle(String algorithm, int size) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC reset")
    public void testRestDigest(String algorithm, int size) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        botan.update("hello world".getBytes());
        botan.reset();

        //TODO: check bc rest and remove this
        botan.init(key);

        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test single Byte update")
    public void testSingleByteUpdate(String algorithm, int size) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        botan.update((byte) 'H');
        botan.update((byte) 'e');
        botan.update((byte) 'l');
        botan.update((byte) 'l');
        botan.update((byte) 'o');

        final byte[] expected = bc.doFinal("Hello".getBytes());
        final byte[] actual = botan.doFinal();

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test Botan performance against Bouncy Castle")
    public void testBotanPerformance(String algorithm, int size) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        final long startBc = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            bc.update("some input".getBytes());
        }
        final byte[] expected = bc.doFinal();
        final long endBc = System.nanoTime();

        final long startBotan = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            botan.update("some input".getBytes());
        }
        final byte[] actual = botan.doFinal();
        final long endBotan = System.nanoTime();

        double difference = (endBc - startBc) - (endBotan - startBotan);
        difference /= (endBc - startBc);
        difference *= 100;

        LOG.info(new StringFormattedMessage(
                "Performance against Bouncy Castle for algorithm %s: %.2f %%",
                algorithm, difference));

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

}
