/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import net.randombit.botan.mac.BotanMacTest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import net.randombit.botan.BotanProvider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class BotanMessageDigestTest {

    private static final Logger LOG = LogManager.getLogger(BotanMessageDigestTest.class.getSimpleName());

    private static final String NOT_SUPPORTED_BY_BC = "Algorithm not supported by Bouncy Castle {}";

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                // SHA-1
                {"sha1", 20, true},

                // SHA-2
                {"sha-224", 28, true},
                {"sha-256", 32, true},
                {"sha-384", 48, true},
                {"sha-512", 64, true},
                {"sha2", 64, false},

                // SHA-3
                {"sha3-224", 28, true},
                {"sha3-256", 32, true},
                {"sha3-384", 48, true},
                {"sha3-512", 64, true},
                {"sha3", 64, false},

                // KECCAK
                {"keccak-224", 28, true},
                {"keccak-256", 32, true},
                {"keccak-384", 48, true},
                {"keccak-512", 64, true},
                {"keccak", 64, false},

                // Blake2b
                {"blake2b-160", 20, true},
                {"blake2b-256", 32, true},
                {"blake2b-384", 48, true},
                {"blake2b-512", 64, true},
                {"blake2b", 64, false},

                // MD
                {"md4", 16, true},
                {"md5", 16, true},
                {"ripemd160", 20, true},
        });
    }

    private final String algorithm;
    private final int size;
    private final boolean isSupportedByBouncyCastle;

    public BotanMessageDigestTest(String algorithm, int size, boolean isSupportedByBouncyCastle) {
        this.algorithm = algorithm;
        this.size = size;
        this.isSupportedByBouncyCastle = isSupportedByBouncyCastle;
    }

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDigestOutputSize() throws GeneralSecurityException {
        final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
        final byte[] output = digest.digest("Some input".getBytes());

        Assert.assertEquals(algorithm + " output size in bytes", size, digest.getDigestLength());
        Assert.assertEquals(algorithm + " output size in bytes", size, output.length);
    }

    @Test
    public void testAgainstBouncyCastle() throws GeneralSecurityException {
        if (!isSupportedByBouncyCastle) {
            LOG.info(NOT_SUPPORTED_BY_BC, algorithm);
            return;
        }

        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        final byte[] expected = bc.digest("hello world".getBytes());
        final byte[] actual = botan.digest("hello world".getBytes());

        Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                + algorithm, expected, actual);
    }

    @Test
    public void testCloneDigest() throws GeneralSecurityException, CloneNotSupportedException {
        if (!isSupportedByBouncyCastle) {
            LOG.info(NOT_SUPPORTED_BY_BC, algorithm);
            return;
        }

        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
        final MessageDigest clone = (MessageDigest) botan.clone();

        final byte[] expected = bc.digest("Clone support".getBytes());
        final byte[] actual = clone.digest("Clone support".getBytes());

        Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                + algorithm, expected, actual);
    }

    @Test
    public void testRestDigest() throws GeneralSecurityException {
        if (!isSupportedByBouncyCastle) {
            LOG.info(NOT_SUPPORTED_BY_BC, algorithm);
            return;
        }

        final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

        botan.update("to reset".getBytes());
        botan.reset();

        bc.update("Rest support".getBytes());
        botan.update("Rest support".getBytes());

        final byte[] expected = bc.digest();
        final byte[] actual = botan.digest();

        Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                + algorithm, expected, actual);
    }

    @Test
    public void testSingleByteUpdate() throws GeneralSecurityException {
        if (!isSupportedByBouncyCastle) {
            LOG.info(NOT_SUPPORTED_BY_BC, algorithm);
            return;
        }

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

        Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                + algorithm, expected, actual);
    }

    @Test
    public void testBotanPerformance() throws GeneralSecurityException {
        if (!isSupportedByBouncyCastle) {
            LOG.info(NOT_SUPPORTED_BY_BC, algorithm);
            return;
        }

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

        Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                + algorithm, expected, actual);
    }

}
