/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

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

                // SHA-3
                {"sha3-224", 28, true},
                {"sha3-256", 32, true},
                {"sha3-384", 48, true},
                {"sha3-512", 64, true},

                // KECCAK
                {"keccak-224", 28, true},
                {"keccak-256", 32, true},
                {"keccak-384", 48, true},
                {"keccak-512", 64, true},

                // Blake2b
                {"blake2b-160", 20, true},
                {"blake2b-256", 32, true},
                {"blake2b-384", 48, true},
                {"blake2b-512", 64, true},

                // MD
                {"md4", 16, true},
                {"md5", 16, true},
                {"ripemd160", 20, true},
        });
    }

    private final String algorithm;
    private final int size;
    private final boolean isSupportedBySun;

    public BotanMessageDigestTest(String algorithm, int size, boolean isSupportedBySun) {
        this.algorithm = algorithm;
        this.size = size;
        this.isSupportedBySun = isSupportedBySun;
    }

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDigestOutputSize() throws GeneralSecurityException {
        final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);
        final byte[] output = digest.digest("Some input".getBytes());

        Assert.assertEquals(algorithm + " output size in bytes", size, digest.getDigestLength());
        Assert.assertEquals(algorithm + " output size in bytes", size, output.length);
    }

    @Test
    public void testAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedBySun) {
            final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            final byte[] expected = bc.digest("hello world".getBytes());
            final byte[] actual = botan.digest("hello world".getBytes());

            Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testCloneDigest() throws GeneralSecurityException, CloneNotSupportedException {
        if (isSupportedBySun) {
            final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);
            final MessageDigest clone = (MessageDigest) botan.clone();

            final byte[] expected = bc.digest("Clone support".getBytes());
            final byte[] actual = clone.digest("Clone support".getBytes());

            Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testRestDigest() throws GeneralSecurityException {
        if (isSupportedBySun) {
            final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            botan.update("to reset".getBytes());
            botan.reset();

            bc.update("Rest support".getBytes());
            botan.update("Rest support".getBytes());

            final byte[] expected = bc.digest();
            final byte[] actual = botan.digest();

            Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);

        }
    }

    @Test
    public void testSingleByteUpdate() throws GeneralSecurityException {
        if (isSupportedBySun) {
            final MessageDigest bc = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            botan.update(new byte[] {'H'});
            botan.update(new byte[] {'e'});
            botan.update(new byte[] {'l'});
            botan.update(new byte[] {'l'});
            botan.update(new byte[] {'o'});

            bc.update("Hello".getBytes());

            final byte[] expected = bc.digest();
            final byte[] actual = botan.digest();

            Assert.assertArrayEquals("Digest mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

}
