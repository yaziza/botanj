/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.mac;

import java.security.GeneralSecurityException;
import java.security.Security;
import net.randombit.botan.BotanProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class BotanMacTest {

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                // HMAC
                {"HMAC-SHA1", 20, true},
                {"HMAC-SHA224", 28, true},
                {"HMAC-SHA256", 32, true},
                {"HMAC-SHA384", 48, true},
                {"HMAC-SHA512", 64, true},
                {"HMAC-SHA2", 64, false},
                {"HMAC-MD5", 16, true},
                {"HMAC-RIPEMD160", 20, true},
        });
    }

    private final String algorithm;
    private final int size;
    private final boolean isSupportedByBouncyCastle;

    public BotanMacTest(String algorithm, int size, boolean isSupportedByBouncyCastle) {
        this.algorithm = algorithm;
        this.size = size;
        this.isSupportedByBouncyCastle = isSupportedByBouncyCastle;
    }

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMacOutputSize() throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

        mac.init(key);
        final byte[] output = mac.doFinal("some input".getBytes());

        Assert.assertEquals(algorithm + " output size in bytes", size, mac.getMacLength());
        Assert.assertEquals(algorithm + " output size in bytes", size, output.length);
    }

    @Test
    public void testAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

            final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Mac botan = Mac.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(key);
            botan.init(key);

            final byte[] expected = bc.doFinal("some input".getBytes());
            final byte[] actual = botan.doFinal("some input".getBytes());

            Assert.assertArrayEquals("MAC mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testRestDigest() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

            final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Mac botan = Mac.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(key);
            botan.init(key);

            botan.update("hello world".getBytes());
            botan.reset();

            //TODO: check bc rest and remove this
            botan.init(key);

            final byte[] expected = bc.doFinal("some input".getBytes());
            final byte[] actual = botan.doFinal("some input".getBytes());

            Assert.assertArrayEquals("MAC mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testSingleByteUpdate() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

            final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Mac botan = Mac.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(key);
            botan.init(key);

            botan.update((byte) 'H');
            botan.update((byte) 'e');
            botan.update((byte) 'l');
            botan.update((byte) 'l');
            botan.update((byte) 'o');

            final byte[] expected = bc.doFinal("Hello".getBytes());
            final byte[] actual = botan.doFinal();

            Assert.assertArrayEquals("MAC mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testBotanPerformance() throws GeneralSecurityException, InterruptedException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[size], algorithm);

            final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Mac botan = Mac.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

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

            System.out.println("BC    : " + (endBc - startBc) + " ns");
            System.out.println("Botan : " + (endBotan - startBotan + " ns"));
            System.out.println(String.format(algorithm + " Botan faster/slower than Bouncy castle by: %.2f ", difference) + "%");

            Assert.assertArrayEquals("MAC mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

}
